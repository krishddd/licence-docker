"""
License Validator v2.0 — Industrial-Grade Validation
======================================================
Performs a 6-layer validation:
  1. RSA-4096 digital signature verification (public key only)
  2. JWT decode — extract claims (tier, pipelines, hwid, expiry)
  3. HWID comparison — with migration support (1 change allowed)
  4. NTP time check — with offline cache (48h grace)
  5. Revocation check — JTI-based kill list
  6. Grace period — 72h degraded mode on expiry

All open-source: cryptography, PyJWT, ntplib.
"""

import os
import json
import time
import hmac as hmac_mod
import hashlib
import base64
import datetime
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from functools import wraps

import jwt  # PyJWT
import ntplib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from licensing.hwid_generator import generate_hwid
from licensing.revocation import RevocationChecker, LicenseRevokedError

logger = logging.getLogger(__name__)

# ── Custom Exceptions ─────────────────────────────────────────────────────────

class LicenseError(Exception):
    """Base exception for all license errors."""
    pass

class LicenseFileNotFoundError(LicenseError):
    """License or key file not found."""
    pass

class LicenseSignatureError(LicenseError):
    """RSA signature verification failed — license tampered or forged."""
    pass

class LicenseExpiredError(LicenseError):
    """License has expired (NTP-verified)."""
    pass

class LicenseHWIDMismatchError(LicenseError):
    """HWID in license does not match this machine."""
    pass

class NTPTimeError(LicenseError):
    """Could not verify time via NTP."""
    pass


# ── License Info Dataclass ────────────────────────────────────────────────────

@dataclass
class LicenseInfo:
    """Validated license information."""
    valid: bool = False
    tier: str = "unknown"
    customer_id: str = ""
    hwid: str = ""
    jti: str = ""  # License serial number (for revocation)
    allowed_pipelines: List[str] = field(default_factory=list)
    issued_at: Optional[datetime.datetime] = None
    expires_at: Optional[datetime.datetime] = None
    max_models: int = 1
    vector_db_access: bool = False
    in_grace_period: bool = False  # True = expired but within grace window
    grace_hours_remaining: float = 0.0
    hwid_migrated: bool = False  # True = HWID changed, migration used
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "tier": self.tier,
            "customer_id": self.customer_id,
            "hwid_prefix": self.hwid[:16] + "..." if self.hwid else "",
            "jti": self.jti[:8] + "..." if self.jti else "",
            "allowed_pipelines": self.allowed_pipelines,
            "issued_at": self.issued_at.isoformat() if self.issued_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "max_models": self.max_models,
            "vector_db_access": self.vector_db_access,
            "in_grace_period": self.in_grace_period,
            "grace_hours_remaining": round(self.grace_hours_remaining, 1),
            "error": self.error,
        }


# ── Retry Decorator ──────────────────────────────────────────────────────────

def _retry(times: int = 3, delay: float = 2.0):
    """Retry decorator for flaky network calls (NTP)."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(1, times + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exc = e
                    logger.warning(f"Attempt {attempt}/{times} of '{func.__name__}' failed: {e}")
                    if attempt < times:
                        time.sleep(delay)
            raise last_exc
        return wrapper
    return decorator


# ── NTP Time Checker ──────────────────────────────────────────────────────────

def _utcnow():
    """UTC now — compatible with Python 3.12+ (no deprecation warning)."""
    try:
        return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    except Exception:
        return datetime.datetime.utcnow()


@_retry(times=3, delay=3.0)
def get_ntp_time(server: str = "pool.ntp.org", timeout: float = 5.0) -> datetime.datetime:
    """Fetch current UTC time from NTP server (anti-clock-tamper)."""
    try:
        client = ntplib.NTPClient()
        response = client.request(server, version=3, timeout=timeout)
        ntp_time = datetime.datetime.fromtimestamp(response.tx_time, tz=datetime.timezone.utc).replace(tzinfo=None)
        logger.debug(f"NTP time from {server}: {ntp_time}")
        return ntp_time
    except ntplib.NTPException as e:
        raise NTPTimeError(f"NTP communication error: {e}")
    except OSError as e:
        raise NTPTimeError(f"Network error during NTP request: {e}")


# NTP cache file -- default location (overridden per-instance for Docker)
_NTP_CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".ntp_cache")


def _save_ntp_cache(ntp_time: datetime.datetime, cache_file: str = ""):
    """Save last known NTP time for offline mode."""
    target = cache_file or _NTP_CACHE_FILE
    try:
        data = {
            "ntp_utc": ntp_time.isoformat(),
            "local_utc": _utcnow().isoformat(),
            "saved_at": time.time(),
        }
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        with open(target, "w") as f:
            json.dump(data, f)
    except Exception as e:
        logger.debug(f"Could not save NTP cache: {e}")


def _load_ntp_cache(max_age_hours: float = 48.0, cache_file: str = "") -> Optional[datetime.datetime]:
    """Load cached NTP time if fresh enough (offline mode)."""
    target = cache_file or _NTP_CACHE_FILE
    if not os.path.exists(target):
        return None
    try:
        with open(target, "r") as f:
            data = json.load(f)
        age_seconds = time.time() - data["saved_at"]
        age_hours = age_seconds / 3600
        if age_hours > max_age_hours:
            logger.warning(f"NTP cache too old ({age_hours:.1f}h > {max_age_hours}h)")
            return None
        # Estimate current time: cached NTP time + elapsed since cache
        cached_ntp = datetime.datetime.fromisoformat(data["ntp_utc"])
        estimated = cached_ntp + datetime.timedelta(seconds=age_seconds)
        logger.info(
            f"Using cached NTP time (age: {age_hours:.1f}h, "
            f"{max_age_hours - age_hours:.1f}h offline grace remaining)"
        )
        return estimated
    except Exception as e:
        logger.warning(f"Could not load NTP cache: {e}")
        return None


def _get_current_time(
    ntp_server: str = "pool.ntp.org",
    strict: bool = False,
    offline_grace_hours: float = 48.0,
    ntp_cache_file: str = "",  # Fix #7: instance-specific cache path
) -> datetime.datetime:
    """
    Get current time with NTP. Supports offline mode via cached NTP time.

    Priority:
      1. Live NTP (best) -> cache the result
      2. Cached NTP + local delta (offline mode, up to offline_grace_hours)
      3. Local clock fallback (only if strict=False)
    """
    try:
        ntp_time = get_ntp_time(ntp_server)
        _save_ntp_cache(ntp_time, cache_file=ntp_cache_file)  # Cache for offline use
        return ntp_time
    except Exception as e:
        # Try offline cache
        cached = _load_ntp_cache(max_age_hours=offline_grace_hours, cache_file=ntp_cache_file)
        if cached is not None:
            return cached

        if strict:
            raise NTPTimeError(
                f"NTP verification FAILED, no cached time available. "
                f"Cannot verify time: {e}. "
                f"Ensure internet connectivity for license validation."
            )
        logger.warning(f"NTP failed, no cache, falling back to local clock: {e}")
        return _utcnow()


# ── License Validator ─────────────────────────────────────────────────────────

class LicenseValidator:
    """
    Validates a license file through 6 layers:
      1. RSA-4096 signature verification
      2. JWT decode + claims extraction
      3. HWID comparison (with migration support)
      4. NTP-based time check (with offline cache)
      5. Revocation check (JTI-based)
      6. Grace period (72h degraded mode on expiry)

    Industrial hardening options:
      - ntp_strict:          Refuse if NTP + cache both fail
      - cache_ttl:           Re-validate interval (default 1h)
      - grace_period_hours:  Hours to run after expiry in degraded mode (default 72)
      - offline_grace_hours: Hours to trust cached NTP time (default 48)
      - max_hwid_changes:    Allowed HWID migrations per license (default 1)
    """

    def __init__(
        self,
        license_dir: str = "./License",
        license_filename: str = "license.key",
        public_key_path: str = "./keys/public_key.pem",
        ntp_server: str = "pool.ntp.org",
        ntp_strict: bool = True,
        cache_ttl: float = 3600,
        grace_period_hours: float = 72.0,
        offline_grace_hours: float = 48.0,
        max_hwid_changes: int = 1,
        mode: str = "bare_metal",  # "bare_metal" or "docker"
        data_dir: str = "",  # Fix #7: persistent volume for NTP cache
    ):
        self.license_dir = license_dir
        self.license_filename = license_filename
        self.public_key_path = public_key_path
        self.ntp_server = ntp_server
        # Concern A: Docker mode MUST enforce strict NTP — prevents clock-rollback.
        # Even if caller passes ntp_strict=False, Docker overrides to True.
        if mode == "docker" and not ntp_strict:
            logger.warning("Docker mode: overriding ntp_strict=False → True (security enforcement)")
        self.ntp_strict = True if mode == "docker" else ntp_strict
        self.cache_ttl = cache_ttl
        self.grace_period_hours = grace_period_hours
        self.offline_grace_hours = offline_grace_hours
        self.max_hwid_changes = max_hwid_changes
        self.mode = mode
        self._public_key = None
        self._cached_info: Optional[LicenseInfo] = None
        self._cache_time: float = 0
        # Revocation checker
        revocation_file = os.path.join(license_dir, "revoked.json")
        self._revocation = RevocationChecker(revocation_file, public_key_path=public_key_path)

        # Fix #4: HWID history in data_dir (not bind-mounted license_dir)
        # with HMAC protection to prevent unlimited migration resets
        _hist_dir = data_dir if data_dir else license_dir
        self._hwid_history_file = os.path.join(_hist_dir, ".hwid_history")
        # HMAC key derived from public key for hwid_history protection
        try:
            with open(public_key_path, "rb") as f:
                self._hmac_key = hashlib.sha256(f.read()).digest()
        except Exception:
            self._hmac_key = b"hwid-history-fallback-key"

        # Fix #7: NTP cache in data_dir (persistent Docker volume)
        if data_dir:
            self._ntp_cache_file = os.path.join(data_dir, ".ntp_cache")
        else:
            self._ntp_cache_file = ""  # use module-level default

    def _load_public_key(self):
        """Load the RSA public key from PEM file."""
        if not os.path.exists(self.public_key_path):
            raise LicenseFileNotFoundError(
                f"Public key not found: {self.public_key_path}"
            )
        with open(self.public_key_path, "rb") as f:
            self._public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )
        logger.info(f"Loaded RSA public key from {self.public_key_path}")

    def _read_license_file(self) -> dict:
        """Read and parse the license file (JSON with signature + payload)."""
        license_path = os.path.join(self.license_dir, self.license_filename)
        if not os.path.exists(license_path):
            raise LicenseFileNotFoundError(
                f"License file not found: {license_path}. "
                f"Ensure '{self.license_dir}' contains '{self.license_filename}'."
            )
        with open(license_path, "r") as f:
            data = json.load(f)
        logger.info(f"Loaded license file from {license_path}")
        return data

    def _verify_signature(self, payload_bytes: bytes, signature_bytes: bytes):
        """Layer 1: Verify RSA-4096 digital signature."""
        if self._public_key is None:
            self._load_public_key()
        try:
            self._public_key.verify(
                signature_bytes,
                payload_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            logger.info("Layer 1 PASSED: RSA signature verified")
        except Exception as e:
            raise LicenseSignatureError(
                f"RSA signature verification FAILED: {e}. "
                "License file may be tampered or forged."
            )

    def _decode_jwt(self, token: str) -> dict:
        """Layer 2: Decode JWT and extract claims (no signature check — already done via RSA)."""
        try:
            # We verify signature ourselves via RSA, so decode without verification.
            # Concern B: verify_exp=False — our NTP-based _verify_expiry() owns the
            # expiry decision. Without this, PyJWT may reject a license that is still
            # within our grace period (72h) before _verify_expiry even runs.
            claims = jwt.decode(token, options={
                "verify_signature": False,
                "verify_exp": False,
            })
            logger.info(
                f"Layer 2 PASSED: JWT decoded — tier={claims.get('tier')}, "
                f"sub={claims.get('sub')}"
            )
            return claims
        except jwt.DecodeError as e:
            raise LicenseError(f"JWT decode failed: {e}")

    def _verify_hwid(self, license_hwid: str) -> bool:
        """Layer 3: Compare license HWID with local machine HWID (migration support)."""
        local_hwid = generate_hwid()
        if license_hwid == local_hwid:
            logger.info("Layer 3 PASSED: HWID matches this machine")
            return False  # No migration needed

        # HWID mismatch -- check if migration is allowed
        migration_count = self._get_hwid_migration_count()
        if migration_count < self.max_hwid_changes:
            # Allow migration
            self._record_hwid_migration(license_hwid, local_hwid)
            logger.warning(
                f"Layer 3 PASSED (MIGRATION): HWID changed. "
                f"Migration {migration_count + 1}/{self.max_hwid_changes} used. "
                f"Old: {license_hwid[:16]}..., New: {local_hwid[:16]}..."
            )
            return True  # Migration occurred
        else:
            raise LicenseHWIDMismatchError(
                f"HWID mismatch! License is bound to a different machine. "
                f"License HWID: {license_hwid[:16]}..., "
                f"Local HWID: {local_hwid[:16]}... "
                f"No migrations remaining ({self.max_hwid_changes} used)."
            )

    def _get_hwid_migration_count(self) -> int:
        """Get the number of HWID migrations used (Fix #4: HMAC-verified)."""
        if not os.path.exists(self._hwid_history_file):
            return 0
        try:
            with open(self._hwid_history_file, "r") as f:
                data = json.load(f)
            # Verify HMAC if present
            stored_sig = data.pop("_sig", "")
            if stored_sig:
                content = json.dumps(data.get("migrations", []), sort_keys=True)
                expected_sig = hmac_mod.new(
                    self._hmac_key, content.encode(), hashlib.sha256
                ).hexdigest()
                if not hmac_mod.compare_digest(stored_sig, expected_sig):
                    raise LicenseError(
                        "HWID migration history tampered — cannot process migration. "
                        "File integrity check failed."
                    )
            return len(data.get("migrations", []))
        except LicenseError:
            raise
        except Exception:
            return 0

    def _record_hwid_migration(self, old_hwid: str, new_hwid: str):
        """Record a HWID migration with HMAC protection (Fix #4)."""
        data = {"migrations": []}
        if os.path.exists(self._hwid_history_file):
            try:
                with open(self._hwid_history_file, "r") as f:
                    data = json.load(f)
                # Remove sig for content re-computation
                data.pop("_sig", None)
            except Exception:
                pass
        data["migrations"].append({
            "ts": _utcnow().isoformat(),
            "old_hwid": old_hwid[:16],
            "new_hwid": new_hwid[:16],
        })
        # Compute HMAC over migrations content
        content = json.dumps(data["migrations"], sort_keys=True)
        sig = hmac_mod.new(self._hmac_key, content.encode(), hashlib.sha256).hexdigest()
        data["_sig"] = sig
        os.makedirs(os.path.dirname(self._hwid_history_file) or ".", exist_ok=True)
        with open(self._hwid_history_file, "w") as f:
            json.dump(data, f, indent=2)

    def _verify_expiry(self, exp_timestamp: float) -> dict:
        """
        Layer 4: Check expiry using NTP time (with offline cache + grace period).
        Returns dict with grace_period info.
        """
        current_time = _get_current_time(
            self.ntp_server,
            strict=self.ntp_strict,
            offline_grace_hours=self.offline_grace_hours,
            ntp_cache_file=self._ntp_cache_file,
        )
        expiry_time = datetime.datetime.fromtimestamp(
            exp_timestamp, tz=datetime.timezone.utc
        ).replace(tzinfo=None)

        if current_time >= expiry_time:
            # Check grace period
            overtime = current_time - expiry_time
            overtime_hours = overtime.total_seconds() / 3600
            grace_remaining = self.grace_period_hours - overtime_hours

            if grace_remaining > 0:
                logger.warning(
                    f"Layer 4 WARNING: License EXPIRED but within grace period. "
                    f"{grace_remaining:.1f}h remaining in grace mode."
                )
                return {
                    "in_grace": True,
                    "grace_hours_remaining": grace_remaining,
                }
            else:
                raise LicenseExpiredError(
                    f"License expired at {expiry_time.isoformat()} "
                    f"and grace period ({self.grace_period_hours}h) exhausted. "
                    f"Current UTC time: {current_time.isoformat()}"
                )

        remaining = expiry_time - current_time
        logger.info(
            f"Layer 4 PASSED: License valid until {expiry_time.isoformat()} "
            f"({remaining.days} days remaining)"
        )
        return {"in_grace": False, "grace_hours_remaining": 0.0}

    def validate(self, skip_hwid: bool = False, bypass_cache: bool = False) -> LicenseInfo:
        """
        Run the full 6-layer validation.

        Args:
            skip_hwid:    If True, skip HWID check (dev mode).
            bypass_cache: If True, ignore cached result (used by heartbeat).

        Returns:
            LicenseInfo with all validated claims.

        Raises:
            LicenseError subclasses on validation failure.
        """
        # Check cache
        if not bypass_cache and self._cached_info and (time.time() - self._cache_time) < self.cache_ttl:
            logger.debug(f"Returning cached license info (TTL: {self.cache_ttl}s)")
            return self._cached_info

        info = LicenseInfo()
        try:
            # Read license file
            license_data = self._read_license_file()
            payload_b64 = license_data["payload"]
            signature_hex = license_data["signature"]

            # Layer 1: RSA signature
            payload_bytes = base64.b64decode(payload_b64)
            signature_bytes = bytes.fromhex(signature_hex)
            self._verify_signature(payload_bytes, signature_bytes)

            # Layer 2: JWT decode
            jwt_token = payload_bytes.decode("utf-8")
            claims = self._decode_jwt(jwt_token)

            # Layer 3: HWID check (with migration)
            hwid_migrated = False
            if not skip_hwid:
                if self.mode == "docker":
                    # Docker mode: HWID already verified by auto_activator
                    # Just log that we're using activation-based HWID
                    logger.info("Layer 3 PASSED: Docker mode -- HWID verified via activation")
                else:
                    hwid_migrated = self._verify_hwid(claims.get("hwid", ""))

            # Layer 4: Expiry check (NTP + offline cache + grace period)
            expiry_result = self._verify_expiry(claims["exp"])

            # Layer 5: Revocation check
            self._revocation.reload()  # Reload list on each validation
            jti = claims.get("jti", "")
            self._revocation.check(jti)
            if jti:
                logger.info(f"Layer 5 PASSED: License JTI {jti[:8]}... not revoked")

            # Populate LicenseInfo
            info.valid = True
            info.tier = claims.get("tier", "standard")
            info.customer_id = claims.get("sub", "unknown")
            info.hwid = claims.get("hwid", "")
            info.jti = jti
            info.allowed_pipelines = claims.get("pipelines", [])
            info.max_models = claims.get("max_models", 1)
            info.vector_db_access = claims.get("vector_db", False)
            info.in_grace_period = expiry_result["in_grace"]
            info.grace_hours_remaining = expiry_result["grace_hours_remaining"]
            info.hwid_migrated = hwid_migrated
            if claims.get("iat"):
                info.issued_at = datetime.datetime.fromtimestamp(
                    claims["iat"], tz=datetime.timezone.utc
                ).replace(tzinfo=None)
            if claims.get("exp"):
                info.expires_at = datetime.datetime.fromtimestamp(
                    claims["exp"], tz=datetime.timezone.utc
                ).replace(tzinfo=None)

            status = "GRACE PERIOD" if info.in_grace_period else "VALID"
            logger.info(
                f"LICENSE {status} -- Tier: {info.tier}, "
                f"Customer: {info.customer_id}, "
                f"Pipelines: {info.allowed_pipelines}"
            )

            # Cache result
            self._cached_info = info
            self._cache_time = time.time()

        except (LicenseError, LicenseRevokedError):
            raise
        except Exception as e:
            raise LicenseError(f"Unexpected license validation error: {e}")

        return info

    def invalidate_cache(self):
        """Force re-validation on next call."""
        self._cached_info = None
        self._cache_time = 0
