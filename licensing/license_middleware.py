"""
License Middleware for FastAPI (v3.2 -- Docker + Industrial Grade)
==================================================================
Provides three integration points:
  1. startup_license_check() -- validates license + all hardening at startup
  2. PipelineGate()          -- FastAPI Depends() for per-request validation
  3. check_pipeline_access() -- tier-based pipeline gating

v3.2 Breaking Change:
  - Phone-home is now MANDATORY for Docker deployments (fail-closed).
  - PHONE_HOME_URL must be set and reachable at startup.
  - Closes license-sharing loophole (multiple machines, same license.key).

v3.0 Docker Support:
  - Auto-activation via bind-mounted host HWID
  - VM detection skipped in Docker mode
  - NTP strict auto-disabled in Docker mode

v2.0 Industrial Hardening:
  - VM detection: blocks VirtualBox, VMware, Hyper-V
  - NTP strict mode: refuses to start if time can't be verified
  - Heartbeat: background re-validation every 30 min
  - Audit trail: tamper-evident HMAC-chained log
  - Revocation, grace period, offline mode, integrity, concurrency
"""

import os
import json
import logging
from typing import Optional

from fastapi import HTTPException, Request

from licensing.license_validator import (
    LicenseValidator,
    LicenseInfo,
    LicenseError,
    LicenseFileNotFoundError,
    LicenseSignatureError,
    LicenseExpiredError,
    LicenseHWIDMismatchError,
    NTPTimeError,
)
from licensing.revocation import LicenseRevokedError
from licensing.tier_manager import TierManager
from licensing.vm_detector import VMDetector, VirtualMachineDetectedError
from licensing.audit_logger import AuditLogger, EVENT_STARTUP, EVENT_VALIDATION_OK, EVENT_GRACE_ENTERED, EVENT_VM_DETECTED, EVENT_TAMPER_DETECTED
from licensing.heartbeat import LicenseHeartbeat
from licensing.integrity import IntegrityChecker
from licensing.concurrency import ConcurrencyGuard, ConcurrentUseError
from licensing.phone_home import PhoneHomeBeacon, PhoneHomeRequiredError

logger = logging.getLogger(__name__)

# -- Global State ---------------------------------------------------------------

_license_info: Optional[LicenseInfo] = None
_validator: Optional[LicenseValidator] = None
_tier_manager: Optional[TierManager] = None
_heartbeat: Optional[LicenseHeartbeat] = None
_audit: Optional[AuditLogger] = None
_integrity: Optional[IntegrityChecker] = None
_concurrency: Optional[ConcurrencyGuard] = None
_beacon: Optional[PhoneHomeBeacon] = None


def get_current_license() -> Optional[LicenseInfo]:
    """Get the currently validated license info (or None)."""
    return _license_info


def get_heartbeat_status() -> dict:
    """Get heartbeat status."""
    if _heartbeat:
        return _heartbeat.status
    return {"running": False, "detail": "Heartbeat not initialized"}


def get_audit_recent(n: int = 50) -> list:
    """Get recent audit log entries."""
    if _audit:
        return _audit.get_recent(n)
    return []


def get_integrity_status() -> dict:
    """Get integrity check status."""
    if _integrity:
        return _integrity.verify()
    return {"valid": True, "detail": "Integrity checker not initialized"}


# -- Startup Check ---------------------------------------------------------------

def startup_license_check(
    license_dir: str = "./License",
    license_filename: str = "license.key",
    public_key_path: str = "./keys/public_key.pem",
    ntp_server: str = "pool.ntp.org",
    skip_hwid: bool = False,
    ntp_strict: bool = True,
    cache_ttl: float = 3600,
    block_vm: bool = False,
    grace_period_hours: float = 72.0,
    offline_grace_hours: float = 48.0,
    max_hwid_changes: int = 1,
    heartbeat_interval: float = 1800,
    heartbeat_max_failures: int = 3,
    heartbeat_grace_hours: float = 72.0,  # Gap 4 fix: network blip tolerance
    enable_audit: bool = True,
    enable_integrity: bool = True,
    enable_concurrency: bool = True,
    mode: str = "bare_metal",  # "bare_metal" or "docker"
    data_dir: str = "./data",  # Docker volume for activation data
    phone_home_url: str = "",  # REQUIRED for Docker mode
):
    """
    Run full license validation at app startup.
    Call this in your FastAPI lifespan handler.

    Layers:
      0. VM detection (optional)
      1. RSA-4096 signature
      2. JWT decode
      3. HWID match (with migration)
      4. NTP time check (with offline cache + grace period)
      5. Revocation check (JTI-based)
      6. Integrity check (SHA-256 code validation)
      7. Concurrency check (lockfile guard)
      8. Phone-home verification (MANDATORY for Docker)
      + Background heartbeat started after validation
    """
    global _license_info, _validator, _tier_manager, _heartbeat, _audit, _integrity, _concurrency, _beacon

    version_label = "v3.2 Docker" if mode == "docker" else "v2.0 Industrial"
    logger.info("=" * 60)
    logger.info(f"  LICENSE VALIDATION -- STARTUP CHECK ({version_label})")
    logger.info("=" * 60)

    # Pre-flight: Validate PHONE_HOME_URL for Docker mode (v3.2 mandatory)
    if mode == "docker":
        _ph_url = phone_home_url or os.environ.get("PHONE_HOME_URL", "").strip()
        if not _ph_url:
            logger.error("=" * 60)
            logger.error("  PHONE_HOME_URL is REQUIRED for Docker deployments (v3.2)")
            logger.error("  This prevents license sharing across multiple machines.")
            logger.error("  Set PHONE_HOME_URL in your docker-compose.yml:")
            logger.error("    environment:")
            logger.error("      - PHONE_HOME_URL=https://your-server.com/api/license/beacon")
            logger.error("=" * 60)
            raise SystemExit(
                "PHONE_HOME_URL is REQUIRED for Docker deployments. "
                "Set it in your docker-compose.yml environment variables."
            )
        # Initialize beacon early for startup verification
        _beacon = PhoneHomeBeacon(url=_ph_url)
        logger.info(f"  Phone-home: REQUIRED (Docker mode) → {_ph_url[:50]}...")

    # Initialize audit logger
    if enable_audit:
        log_dir = os.path.join(os.path.dirname(license_dir), "logs")
        _audit = AuditLogger(log_dir=log_dir)

    def _audit_log(event: str, detail: str = "", **kwargs):
        if _audit:
            hwid = _license_info.hwid if _license_info else ""
            tier = _license_info.tier if _license_info else ""
            _audit.log(event, hwid=hwid, tier=tier, detail=detail, **kwargs)

    # Layer 0: VM Detection (SKIP in Docker mode)
    if mode == "docker":
        logger.info("  Layer 0: SKIPPED (Docker mode -- VM detection not applicable)")
    else:
        logger.info("  Layer 0: Virtual Machine Detection...")
        try:
            vm = VMDetector()
            result = vm.check_all()
            if result["is_virtual"]:
                if block_vm:
                    _audit_log(EVENT_VM_DETECTED, detail=str(result["detections"][:2]))
                    raise VirtualMachineDetectedError(
                        f"Virtual machine detected (confidence: {result['confidence']*100:.0f}%). "
                        f"License cannot run in virtualized environments."
                    )
                else:
                    logger.warning(f"  Layer 0 WARNING: VM detected but BLOCK_VM=false")
            else:
                logger.info(f"  Layer 0 PASSED: Physical hardware confirmed ({result['total_checks']} checks)")
        except VirtualMachineDetectedError:
            raise
        except Exception as e:
            logger.warning(f"  Layer 0 WARNING: VM detection error: {e}")

    # Docker activation verification (Fix #3: NO re-activation — entrypoint already did it)
    _docker_real_hwid = ""  # Fix #2: track real HWID for phone-home
    if mode == "docker":
        logger.info("  Docker: Loading activation data (entrypoint handles activation)...")
        try:
            from licensing.auto_activator import AutoActivator
            from licensing.docker_hwid import generate_docker_hwid
            _docker_real_hwid = generate_docker_hwid(public_key_path=public_key_path)
            _activator = AutoActivator(
                license_dir=license_dir,
                data_dir=data_dir,
                public_key_path=public_key_path,
            )
            _act_data = _activator.load_activation()
            if not _act_data:
                raise SystemExit(
                    "Docker activation not found. "
                    "Ensure docker_entrypoint.py runs before the FastAPI app."
                )
            logger.info(
                f"  Docker: Activation loaded — HWID={_docker_real_hwid[:16]}..., "
                f"JTI={_act_data['jti'][:8]}..., "
                f"boot_count={_act_data.get('boot_count', 0)}"
            )
        except SystemExit:
            raise
        except Exception as e:
            _audit_log("ACTIVATION_LOAD_FAILED", detail=str(e))
            logger.error(f"  Docker: Activation load FAILED: {e}")
            raise SystemExit(f"DOCKER ACTIVATION LOAD FAILED: {e}")

    # Layers 1-5: License Validation
    _validator = LicenseValidator(
        license_dir=license_dir,
        license_filename=license_filename,
        public_key_path=public_key_path,
        ntp_server=ntp_server,
        ntp_strict=ntp_strict,
        cache_ttl=cache_ttl,
        grace_period_hours=grace_period_hours,
        offline_grace_hours=offline_grace_hours,
        max_hwid_changes=max_hwid_changes,
        mode=mode,
        data_dir=data_dir,
    )

    try:
        _license_info = _validator.validate(skip_hwid=skip_hwid)
    except LicenseRevokedError as e:
        _audit_log("LICENSE_REVOKED", detail=str(e))
        logger.error(f"  LICENSE REVOKED: {e}")
        raise SystemExit(f"LICENSE REVOKED: {e}")
    except NTPTimeError as e:
        _audit_log("NTP_FAILED", detail=str(e))
        logger.error(f"  NTP TIME CHECK FAILED: {e}")
        raise SystemExit(f"NTP TIME CHECK FAILED: {e}")
    except LicenseError as e:
        _audit_log("LICENSE_INVALID", detail=str(e))
        logger.error(f"  LICENSE VALIDATION FAILED: {e}")
        raise SystemExit(f"LICENSE VALIDATION FAILED: {e}")

    # Layer 6: Integrity Check (v3.1: use JWT-embedded hashes when available)
    if enable_integrity:
        logger.info("  Layer 6: Runtime Integrity Check...")
        _integrity = IntegrityChecker()
        # v3.1 Fix 5: Extract file_hashes from license JWT for trusted baseline
        # This defeats the baseline-bypass attack where an attacker modifies
        # code BEFORE the container starts.
        try:
            import base64
            import jwt as _jwt
            license_path = os.path.join(license_dir, license_filename)
            if os.path.exists(license_path):
                with open(license_path, "r") as f:
                    ldata = json.load(f)
                payload_bytes = base64.b64decode(ldata["payload"])
                jwt_claims = _jwt.decode(payload_bytes.decode("utf-8"), options={"verify_signature": False})
                jwt_file_hashes = jwt_claims.get("file_hashes")
                if jwt_file_hashes:
                    _integrity.set_jwt_baseline(jwt_file_hashes)
                    logger.info(f"  Layer 6: Using JWT-embedded integrity baseline ({len(jwt_file_hashes)} hashes)")
                else:
                    logger.info("  Layer 6: No file_hashes in JWT -- using self-computed baseline")
        except Exception as e:
            logger.warning(f"  Layer 6: Could not extract JWT file_hashes: {e} -- using self-computed baseline")
        try:
            _integrity.enforce()
            logger.info(f"  Layer 6 PASSED: {len(_integrity.get_hashes())} files verified")
        except Exception as e:
            _audit_log(EVENT_TAMPER_DETECTED, detail=str(e))
            logger.error(f"  Layer 6 FAILED: {e}")
            raise SystemExit(f"INTEGRITY CHECK FAILED: {e}")

    # Layer 7: Concurrency Check
    if enable_concurrency:
        logger.info("  Layer 7: Concurrency Check...")
        from licensing.hwid_generator import generate_hwid
        _concurrency = ConcurrencyGuard(
            lock_dir=license_dir,
            hwid=generate_hwid(),
            stale_seconds=heartbeat_interval * 2,
        )
        try:
            _concurrency.acquire()
            logger.info("  Layer 7 PASSED: No concurrent instances detected")
        except ConcurrentUseError as e:
            _audit_log("CONCURRENT_BLOCKED", detail=str(e))
            logger.error(f"  Layer 7 FAILED: {e}")
            raise SystemExit(f"CONCURRENT USE DETECTED: {e}")

    # Tier manager
    _tier_manager = TierManager()

    # Log audit event
    _audit_log(EVENT_STARTUP, detail="All layers passed")
    if _license_info.in_grace_period:
        _audit_log(EVENT_GRACE_ENTERED,
                    detail=f"{_license_info.grace_hours_remaining:.1f}h remaining")

    # Print summary
    logger.info(f"  Tier     : {_license_info.tier}")
    logger.info(f"  Customer : {_license_info.customer_id}")
    logger.info(f"  JTI      : {_license_info.jti[:8]}..." if _license_info.jti else "  JTI      : (none)")
    logger.info(f"  Expires  : {_license_info.expires_at}")
    logger.info(f"  Pipelines: {_license_info.allowed_pipelines}")
    logger.info(f"  NTP Mode : {'STRICT' if ntp_strict else 'relaxed'}")
    logger.info(f"  Cache TTL: {cache_ttl}s ({cache_ttl/60:.0f} min)")
    logger.info(f"  VM Block : {'skipped (docker)' if mode == 'docker' else ('enabled' if block_vm else 'disabled')}")
    logger.info(f"  Mode     : {mode}")
    logger.info(f"  Grace    : {grace_period_hours}h")
    logger.info(f"  Offline  : {offline_grace_hours}h cached NTP")
    logger.info(f"  Phone-Home: {'REQUIRED (Docker)' if mode == 'docker' else 'optional'}")
    if _license_info.in_grace_period:
        logger.warning(
            f"  STATUS   : GRACE PERIOD -- {_license_info.grace_hours_remaining:.1f}h remaining"
        )
    else:
        logger.info("  STATUS   : VALID -- Application authorized to run")
    logger.info("=" * 60)

    # Layer 8: Phone-Home Verification (v3.2 — MANDATORY for Docker)
    if mode == "docker" and _beacon:
        logger.info("  Layer 8: Phone-Home Startup Verification...")
        try:
            # Get boot_count from activation data
            _boot_count_ph = 0
            try:
                from licensing.auto_activator import AutoActivator
                _act = AutoActivator(license_dir=license_dir, data_dir=data_dir, public_key_path=public_key_path)
                _act_data = _act.load_activation()
                if _act_data:
                    _boot_count_ph = _act_data.get("boot_count", 0)
            except Exception:
                pass

            # Fix #2: Send real Docker HWID, not empty _license_info.hwid
            _ph_hwid = _docker_real_hwid if mode == "docker" else (_license_info.hwid if _license_info else "")
            _beacon.verify_or_fail(
                jti=_license_info.jti if _license_info else "",
                hwid=_ph_hwid,
                tier=_license_info.tier if _license_info else "",
                boot_count=_boot_count_ph,
            )
            logger.info("  Layer 8 PASSED: Phone-home server acknowledged license")
            _audit_log("PHONE_HOME_OK", detail="Startup verification succeeded")
        except PhoneHomeRequiredError as e:
            _audit_log("PHONE_HOME_FAILED", detail=str(e))
            logger.error(f"  Layer 8 FAILED: {e}")
            raise SystemExit(f"PHONE-HOME VERIFICATION FAILED: {e}")
    elif mode != "docker":
        # Bare-metal: initialize beacon as optional
        if phone_home_url:
            _beacon = PhoneHomeBeacon(url=phone_home_url)
            logger.info(f"  Phone-home beacon enabled (optional): {phone_home_url[:50]}")
        else:
            logger.info("  Phone-home beacon: disabled (bare_metal mode, optional)")

    # Start heartbeat
    _heartbeat_first_fail_time = [None]  # mutable container for closure

    def _on_heartbeat_fail():
        global _license_info
        import time as _time
        now = _time.monotonic()  # Fix #8: monotonic clock can't be rolled back

        # Track when failures started
        if _heartbeat_first_fail_time[0] is None:
            _heartbeat_first_fail_time[0] = now
            logger.warning(
                f"HEARTBEAT FAILED -- grace period active ({heartbeat_grace_hours}h tolerance)"
            )
            return  # Don't kill yet

        # How long have we been failing?
        hours_failing = (now - _heartbeat_first_fail_time[0]) / 3600

        if hours_failing < heartbeat_grace_hours:
            remaining = heartbeat_grace_hours - hours_failing
            logger.warning(
                f"HEARTBEAT FAILED -- {remaining:.1f}h remaining in grace period "
                f"(industrial network tolerance)"
            )
        else:
            # Grace exhausted -- kill license
            if _license_info:
                _license_info.valid = False
                logger.error(
                    f"HEARTBEAT KILLED LICENSE after {hours_failing:.1f}h of failures "
                    f"(grace was {heartbeat_grace_hours}h) -- all gated endpoints blocked"
                )
                if _audit:
                    _audit.log("HEARTBEAT_KILL", detail=f"Grace exhausted after {hours_failing:.1f}h")

    def _on_heartbeat_success(info):
        global _license_info
        _license_info = info
        _heartbeat_first_fail_time[0] = None  # Reset grace timer on success
        # Refresh concurrency lock
        if _concurrency:
            _concurrency.refresh()
        # Phone-home beacon (Fix #2: send real Docker HWID, not empty _license_info.hwid)
        if _beacon:
            # Get boot_count from activation data if available
            _boot_count = 0
            _hb_hwid = info.hwid if info else ""  # bare_metal default
            if mode == "docker":
                try:
                    from licensing.auto_activator import AutoActivator
                    act = AutoActivator(license_dir=license_dir, data_dir=data_dir, public_key_path=public_key_path)
                    act_data = act.load_activation()
                    if act_data:
                        _boot_count = act_data.get("boot_count", 0)
                        _hb_hwid = act_data.get("hwid", "") or _docker_real_hwid
                except Exception:
                    _hb_hwid = _docker_real_hwid  # fallback to detected HWID
            _beacon.send(
                jti=info.jti if info else "",
                hwid=_hb_hwid,
                tier=info.tier if info else "",
                boot_count=_boot_count,
            )

    def _heartbeat_validate():
        return _validator.validate(skip_hwid=skip_hwid, bypass_cache=True)

    def _heartbeat_audit(event, detail=""):
        if _audit:
            _audit.log(event, detail=detail)

    _heartbeat = LicenseHeartbeat(
        validate_fn=_heartbeat_validate,
        on_failure=_on_heartbeat_fail,
        on_success=_on_heartbeat_success,
        interval=heartbeat_interval,
        max_failures=heartbeat_max_failures,
        audit_fn=_heartbeat_audit,
    )
    _heartbeat.start()
    logger.info(
        f"  Heartbeat started: every {heartbeat_interval}s, "
        f"kill after {heartbeat_max_failures} failures"
    )


# -- Per-Request Gate (FastAPI Depends) -----------------------------------------

class PipelineGate:
    """
    FastAPI Depends() that validates license on every request.
    Uses cached validation (cache_ttl) so it's fast for most requests.

    In grace period: restricts to standard tier only.
    """

    async def __call__(self, request: Request = None):
        if _license_info is None or not _license_info.valid:
            raise HTTPException(
                status_code=403,
                detail="License invalid or not validated. Application not authorized.",
            )

        # Check heartbeat health
        if _heartbeat and not _heartbeat.is_healthy:
            raise HTTPException(
                status_code=403,
                detail="License heartbeat failed. Re-validation required.",
            )

        # Grace period: add warning header
        if _license_info.in_grace_period:
            logger.warning(
                f"Request in grace period ({_license_info.grace_hours_remaining:.1f}h remaining)"
            )

        return _license_info


# -- Pipeline Access Check (Tier Gating) ----------------------------------------

def check_pipeline_access(pipeline_name: str):
    """
    Check if the current license tier allows access to a specific pipeline.
    In grace period: only standard tier pipelines allowed.
    """
    if _license_info is None:
        raise HTTPException(status_code=403, detail="No valid license")

    # Grace period: restrict to standard tier
    effective_tier = _license_info.tier
    if _license_info.in_grace_period:
        effective_tier = "standard"
        logger.warning(f"Grace period active: restricting to standard tier")

    if _tier_manager:
        allowed = _tier_manager.get_allowed_pipelines(effective_tier)
        if pipeline_name not in allowed:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Pipeline '{pipeline_name}' not available for "
                    f"{'grace period (standard)' if _license_info.in_grace_period else effective_tier} tier. "
                    f"Allowed: {allowed}"
                ),
            )
