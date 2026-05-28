"""
Auto-Activator -- First-Run License Activation for Docker (v3.1)
=================================================================
On first container start:
  1. Read pre-signed license.key (already in image, no HWID)
  2. Detect host HWID from bind mounts
  3. Create activation.json with HMAC tamper protection
  4. Save to persistent Docker volume

On subsequent starts:
  1. Load activation.json -> verify HMAC -> compare HWID

Security:
  - HMAC key = SHA256(public_key_bytes + license_payload + random_salt)
  - Salt is random 32 bytes, generated at activation, stored alongside
  - Same-HWID re-activation does NOT consume migration slot
  - activation_limit enforced (default: 1 machine)

v3.1 Security Hardening:
  - last_seen_utc: timestamp monotonicity check detects clock-rollback
  - If current_time < last_seen_utc by >5min, requires phone-home validation
  - Defense-in-depth: full-volume snapshot + clock rollback bypasses this;
    real defense is server-side boot_count rejection via phone-home
"""

import os
import json
import time
import hmac
import hashlib
import secrets
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ActivationError(Exception):
    """Raised when license activation fails."""
    pass


class ActivationLimitError(ActivationError):
    """Raised when activation_limit is reached for a different HWID."""
    pass


class ActivationTamperedError(ActivationError):
    """Raised when activation.json has been tampered with."""
    pass


class AutoActivator:
    """
    Manages first-run license activation in Docker containers.

    Files:
      - license.key:      Pre-signed license (in image, no HWID)
      - activation.json:  Created on first run (in volume, has HWID + HMAC)
      - public_key.pem:   RSA public key (in image)
    """

    def __init__(
        self,
        license_dir: str = "./License",
        data_dir: str = "./data",
        public_key_path: str = "./keys/public_key.pem",
        license_filename: str = "license.key",
    ):
        self.license_dir = license_dir
        self.data_dir = data_dir
        self.public_key_path = public_key_path
        self.license_filename = license_filename
        self._activation_file = os.path.join(data_dir, "activation.json")

    def _read_license_payload(self) -> bytes:
        """Read the raw license payload bytes."""
        license_path = os.path.join(self.license_dir, self.license_filename)
        if not os.path.exists(license_path):
            raise ActivationError(f"License file not found: {license_path}")
        with open(license_path, "r") as f:
            data = json.load(f)
        return data["payload"].encode("utf-8")

    def _read_public_key_bytes(self) -> bytes:
        """Read the raw public key PEM bytes."""
        if not os.path.exists(self.public_key_path):
            raise ActivationError(f"Public key not found: {self.public_key_path}")
        with open(self.public_key_path, "rb") as f:
            return f.read()

    def _compute_hmac(self, hwid: str, jti: str, timestamp: str, salt: str, boot_count: int = 0, last_seen_utc: str = "") -> str:
        """
        Compute HMAC for activation tamper protection.
        Key = SHA256(public_key_bytes + license_payload_bytes + salt_bytes)
        Message = hwid + jti + timestamp + boot_count + last_seen_utc

        v3.2 fix: last_seen_utc is now included in the HMAC. Without this,
        an attacker could modify last_seen_utc in activation.json to bypass
        the timestamp monotonicity check without breaking the HMAC.
        """
        pubkey = self._read_public_key_bytes()
        payload = self._read_license_payload()
        salt_bytes = bytes.fromhex(salt)

        key = hashlib.sha256(pubkey + payload + salt_bytes).digest()
        message = f"{hwid}|{jti}|{timestamp}|{boot_count}|{last_seen_utc}".encode("utf-8")
        return hmac.new(key, message, hashlib.sha256).hexdigest()

    def _get_license_claims(self) -> dict:
        """Decode JWT claims from license (without verification -- RSA check happens later)."""
        import jwt
        import base64
        license_path = os.path.join(self.license_dir, self.license_filename)
        with open(license_path, "r") as f:
            data = json.load(f)
        payload_bytes = base64.b64decode(data["payload"])
        # verify_exp=False: same as Concern B — let license_validator's NTP check
        # handle expiry. If the license is expired but within grace period, this
        # decode would otherwise raise DecodeError prematurely.
        return jwt.decode(payload_bytes.decode("utf-8"), options={
            "verify_signature": False,
            "verify_exp": False,
        })

    def is_activated(self) -> bool:
        """Check if activation.json exists."""
        return os.path.exists(self._activation_file)

    def load_activation(self) -> Optional[dict]:
        """Load and return activation data (unverified)."""
        if not self.is_activated():
            return None
        try:
            with open(self._activation_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load activation: {e}")
            return None

    def verify_activation(self, current_hwid: str) -> dict:
        """
        Verify existing activation.

        Checks:
          1. activation.json exists and is valid JSON
          2. HMAC matches (tamper detection)
          3. Timestamp monotonicity (clock-rollback / snapshot detection)
          4. HWID matches current host
          5. JTI matches license file

        Returns activation data if valid.
        Raises ActivationError subclasses on failure.
        """
        activation = self.load_activation()
        if activation is None:
            raise ActivationError("No activation found")

        # Verify HMAC (includes boot_count + last_seen_utc for monotonic integrity)
        expected_hmac = self._compute_hmac(
            hwid=activation["hwid"],
            jti=activation["jti"],
            timestamp=activation["activated_at"],
            salt=activation["salt"],
            boot_count=activation.get("boot_count", 0),
            last_seen_utc=activation.get("last_seen_utc", ""),
        )
        if not hmac.compare_digest(expected_hmac, activation.get("hmac", "")):
            raise ActivationTamperedError(
                "Activation file HMAC verification FAILED. "
                "The activation data has been tampered with."
            )

        # ── Timestamp monotonicity check (Fix 4: anti-snapshot/rollback) ──
        last_seen = activation.get("last_seen_utc")
        current_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if last_seen:
            try:
                import datetime
                last_seen_dt = datetime.datetime.strptime(last_seen, "%Y-%m-%dT%H:%M:%SZ")
                current_dt = datetime.datetime.strptime(current_utc, "%Y-%m-%dT%H:%M:%SZ")
                drift = (last_seen_dt - current_dt).total_seconds()

                if drift > 300:  # Current time is >5 min before last_seen
                    logger.error(
                        f"CLOCK ROLLBACK DETECTED: last_seen={last_seen}, "
                        f"current={current_utc}, drift={drift:.0f}s. "
                        f"Possible snapshot restore or clock manipulation."
                    )
                    # Defense-in-depth: this catches lazy attackers who roll
                    # back the clock but DON'T snapshot the volume.
                    # NOTE: A sophisticated attacker who snapshots the entire
                    # volume (restoring last_seen_utc) AND rolls back the clock
                    # will bypass this. The real defense is server-side
                    # boot_count verification via phone-home.
                    raise ActivationError(
                        f"Clock rollback detected (drift: {drift:.0f}s). "
                        f"System time ({current_utc}) is before last verified time ({last_seen}). "
                        f"This may indicate volume snapshot replay or clock manipulation. "
                        f"Ensure system time is correct and contact vendor if this persists."
                    )
            except (ValueError, TypeError) as e:
                logger.warning(f"Could not parse last_seen_utc for monotonicity check: {e}")

        # Increment boot_count (monotonic counter -- defeats clock rollback)
        new_boot_count = activation.get("boot_count", 0) + 1
        activation["boot_count"] = new_boot_count
        activation["last_seen_utc"] = current_utc  # Update timestamp for next check
        # Recompute HMAC with new boot_count + last_seen_utc
        activation["hmac"] = self._compute_hmac(
            hwid=activation["hwid"],
            jti=activation["jti"],
            timestamp=activation["activated_at"],
            salt=activation["salt"],
            boot_count=new_boot_count,
            last_seen_utc=current_utc,
        )
        self._write_with_lock(activation)
        logger.info(f"Boot count incremented: {new_boot_count} (monotonic anti-rollback)")

        # Verify HWID matches
        if activation["hwid"] != current_hwid:
            raise ActivationError(
                f"HWID mismatch: activation bound to {activation['hwid'][:16]}..., "
                f"current host is {current_hwid[:16]}..."
            )

        # Verify JTI matches license
        claims = self._get_license_claims()
        if activation["jti"] != claims.get("jti", ""):
            raise ActivationError(
                "Activation JTI does not match license. "
                "License may have been replaced without re-activation."
            )

        logger.info(f"Activation verified: HWID={current_hwid[:16]}..., JTI={activation['jti'][:8]}...")
        return activation

    def activate(self, hwid: str) -> dict:
        """
        Create a new activation for this HWID.

        Enforces activation_limit from license claims.
        Same-HWID re-activation does NOT count against the limit.
        """
        claims = self._get_license_claims()
        jti = claims.get("jti", "")
        activation_limit = claims.get("activation_limit", 1)

        # Check existing activation
        existing = self.load_activation()
        if existing:
            if existing.get("hwid") == hwid:
                # Same machine re-activation -- always allowed
                logger.info("Same-HWID re-activation (volume was cleared). No migration consumed.")
            else:
                # Different machine -- check activation limit
                activation_count = existing.get("activation_count", 1)
                if activation_count >= activation_limit:
                    raise ActivationLimitError(
                        f"Activation limit reached ({activation_count}/{activation_limit}). "
                        f"This license cannot activate on new hardware. "
                        f"Contact your vendor for a new license."
                    )
                logger.warning(
                    f"Activating on new HWID: {existing.get('hwid', '?')[:16]}... -> {hwid[:16]}... "
                    f"(activation {activation_count + 1}/{activation_limit})"
                )

        # Generate salt and activation
        salt = secrets.token_hex(32)  # 32 bytes = 64 hex chars
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        activation_count = 1
        if existing and existing.get("hwid") != hwid:
            activation_count = existing.get("activation_count", 1) + 1

        activation_data = {
            "hwid": hwid,
            "jti": jti,
            "tier": claims.get("tier", "unknown"),
            "activated_at": timestamp,
            "activation_count": activation_count,
            "boot_count": 1,  # Monotonic counter: defeats clock-rollback on air-gapped machines
            "last_seen_utc": timestamp,  # v3.1: timestamp monotonicity for snapshot detection
            "salt": salt,
            "hmac": "",  # Computed below
            "version": "3.1",
        }

        # Compute HMAC (includes last_seen_utc for tamper protection)
        activation_data["hmac"] = self._compute_hmac(
            hwid=hwid,
            jti=jti,
            timestamp=timestamp,
            salt=salt,
            boot_count=1,
            last_seen_utc=timestamp,
        )

        # Save with file locking
        os.makedirs(self.data_dir, exist_ok=True)
        self._write_with_lock(activation_data)

        logger.info(
            f"License ACTIVATED: HWID={hwid[:16]}..., "
            f"JTI={jti[:8]}..., tier={claims.get('tier')}"
        )
        return activation_data

    def _write_with_lock(self, data: dict):
        """Write activation.json with file locking for multi-replica safety."""
        try:
            import fcntl
            with open(self._activation_file, "w") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                json.dump(data, f, indent=2)
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except ImportError:
            # Windows -- no fcntl, just write normally
            with open(self._activation_file, "w") as f:
                json.dump(data, f, indent=2)

    def activate_if_needed(self, hwid: str) -> dict:
        """
        Main entry point. Activates on first run, verifies on subsequent runs.

        Returns activation data dict.
        """
        if self.is_activated():
            try:
                return self.verify_activation(hwid)
            except ActivationTamperedError:
                raise  # Never allow tampered activation
            except ActivationError as e:
                # Activation exists but invalid -- try re-activation
                logger.warning(f"Existing activation invalid: {e}. Attempting re-activation...")
                return self.activate(hwid)
        else:
            return self.activate(hwid)
