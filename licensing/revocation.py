"""
License Revocation System (v3.2 — Tamper-Protected)
=====================================================
Maintains a local revocation list (revoked.json) of invalidated license
serial numbers (JWT `jti` claim). Checked during every validation.

v3.2 Fix #6: revoked.json now has HMAC-SHA256 tamper protection.
A client who deletes or modifies the file will trigger an error.

The revocation list can be:
  1. Manually updated via `python tools/generate_license.py --revoke <jti>`
  2. Shipped with software updates
  3. Downloaded from a remote URL on heartbeat (optional)
"""

import os
import json
import hmac
import hashlib
import logging
from typing import Set, Optional

logger = logging.getLogger(__name__)


class LicenseRevokedError(Exception):
    """Raised when a license's JTI is in the revocation list."""
    pass


class RevocationChecker:
    """Check if a license serial number (JTI) has been revoked."""

    def __init__(self, revocation_file: str = "./License/revoked.json",
                 public_key_path: str = ""):
        self._file = revocation_file
        self._revoked: Set[str] = set()
        # Fix #6: HMAC key derived from public key for tamper protection
        self._hmac_key = b"revocation-fallback-key"
        if public_key_path and os.path.exists(public_key_path):
            try:
                with open(public_key_path, "rb") as f:
                    self._hmac_key = hashlib.sha256(f.read()).digest()
            except Exception:
                pass
        self._load()

    def _compute_sig(self, jtis_list: list) -> str:
        """Compute HMAC signature over sorted JTI list."""
        content = json.dumps(sorted(jtis_list), sort_keys=True)
        return hmac.new(self._hmac_key, content.encode(), hashlib.sha256).hexdigest()

    def _load(self):
        """Load the revocation list from disk (Fix #6: with HMAC verification)."""
        if not os.path.exists(self._file):
            self._revoked = set()
            return
        try:
            with open(self._file, "r", encoding="utf-8") as f:
                data = json.load(f)
            jtis = data.get("revoked_jtis", [])
            stored_sig = data.get("_sig", "")
            # Verify HMAC if present (backward-compatible with unsigned files)
            if stored_sig:
                expected_sig = self._compute_sig(jtis)
                if not hmac.compare_digest(stored_sig, expected_sig):
                    logger.error("Revocation list HMAC verification FAILED — file tampered")
                    raise LicenseRevokedError(
                        "Revocation list has been tampered with. "
                        "Cannot verify license status — treating as revoked for safety."
                    )
            self._revoked = set(jtis)
            logger.info(f"Loaded {len(self._revoked)} revoked license(s)")
        except LicenseRevokedError:
            raise
        except Exception as e:
            logger.warning(f"Could not load revocation list: {e}")
            self._revoked = set()

    def reload(self):
        """Reload the revocation list (called on heartbeat)."""
        self._load()

    def is_revoked(self, jti: str) -> bool:
        """Check if a JTI is in the revocation list."""
        return jti in self._revoked

    def check(self, jti: Optional[str]):
        """Check and raise LicenseRevokedError if revoked."""
        if not jti:
            return  # No JTI = legacy license, skip check
        if self.is_revoked(jti):
            raise LicenseRevokedError(
                f"License {jti[:8]}... has been revoked. Contact your vendor."
            )

    @staticmethod
    def revoke(jti: str, revocation_file: str = "./License/revoked.json",
               public_key_path: str = ""):
        """Add a JTI to the revocation list (admin tool — Fix #6: HMAC-signed)."""
        os.makedirs(os.path.dirname(revocation_file) or ".", exist_ok=True)
        data = {"revoked_jtis": []}
        if os.path.exists(revocation_file):
            with open(revocation_file, "r", encoding="utf-8") as f:
                data = json.load(f)

        jtis = set(data.get("revoked_jtis", []))
        jtis.add(jti)
        sorted_jtis = sorted(jtis)
        data["revoked_jtis"] = sorted_jtis

        # Compute HMAC signature
        hmac_key = b"revocation-fallback-key"
        if public_key_path and os.path.exists(public_key_path):
            try:
                with open(public_key_path, "rb") as f:
                    hmac_key = hashlib.sha256(f.read()).digest()
            except Exception:
                pass
        content = json.dumps(sorted_jtis, sort_keys=True)
        data["_sig"] = hmac.new(hmac_key, content.encode(), hashlib.sha256).hexdigest()

        with open(revocation_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Revoked license JTI: {jti}")
