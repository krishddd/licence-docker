"""
Phone-Home Beacon -- License Monitoring & Anti-Fraud (v3.2)
============================================================
Fire-and-forget HTTP POST on each heartbeat success.
Reports {jti, hwid, tier, boot_count, timestamp} to PHONE_HOME_URL.

v3.2 Breaking Change:
  - Phone-home is now MANDATORY for Docker deployments (fail-closed).
  - At startup, send_sync() must succeed at least once before the app starts.
  - Ongoing heartbeat beacons remain fire-and-forget (non-blocking).

For bare_metal mode:
  - Phone-home remains optional (silently disabled if URL not set).

The vendor's server can use this data to:
  - Detect same JTI from 2 different HWIDs (license sharing)
  - Track active license count
  - Monitor license health and renewal needs
  - Detect boot_count going backwards (snapshot replay attack)
  - Provide server-verified time as NTP alternative

v3.1 Security Enhancements:
  - Full HWID hash sent (not just prefix) for server-side concurrent-use detection
  - boot_count included for server-side monotonicity verification
  - Server response parsed for server_time (NTP alternative)

Privacy: sends JTI, HWID hash, tier, boot_count, and timestamp.
No source code, data, or pipeline output is ever transmitted.
"""

import os
import json
import time
import hmac as hmac_mod
import hashlib
import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)

PHONE_HOME_URL = os.environ.get("PHONE_HOME_URL", "").strip()


class PhoneHomeRequiredError(Exception):
    """Raised when phone-home is required but fails or is not configured."""
    pass


class PhoneHomeBeacon:
    """
    License beacon for anti-fraud monitoring.

    v3.2: MANDATORY for Docker mode.
      - send_sync() blocks at startup and returns True/False
      - verify_or_fail() raises PhoneHomeRequiredError on failure
      - send() remains async fire-and-forget for heartbeat beacons
    """

    def __init__(self, url: str = "", timeout: float = 10.0):
        self.url = url or PHONE_HOME_URL
        self.timeout = timeout
        self.enabled = bool(self.url)
        self._last_status: Optional[str] = None
        self._last_sent: float = 0
        self._last_server_time: Optional[str] = None

    @property
    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "url": self.url[:40] + "..." if len(self.url) > 40 else self.url,
            "last_status": self._last_status,
            "last_sent": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._last_sent)
            ) if self._last_sent else None,
            "last_server_time": self._last_server_time,
        }

    def get_server_time(self) -> Optional[str]:
        """
        Get the last server-verified time (ISO format).
        Can be used as NTP alternative when NTP is blocked.
        Returns None if no server time is available.
        """
        return self._last_server_time

    def send(
        self,
        jti: str = "",
        hwid: str = "",
        tier: str = "",
        version: str = "3.2",
        boot_count: int = 0,
    ):
        """
        Send beacon in a background thread. Never blocks the caller.
        Used for ongoing heartbeat beacons (fire-and-forget).
        """
        if not self.enabled:
            return

        payload = self._build_payload(jti, hwid, tier, version, boot_count)

        # Fire-and-forget in background thread
        t = threading.Thread(target=self._do_send, args=(payload,), daemon=True)
        t.start()

    def send_sync(
        self,
        jti: str = "",
        hwid: str = "",
        tier: str = "",
        version: str = "3.2",
        boot_count: int = 0,
        retries: int = 3,
    ) -> bool:
        """
        BLOCKING phone-home. Returns True on success, False on failure.
        Used at startup to verify server connectivity before app starts.

        Retries up to `retries` times with exponential backoff.
        """
        if not self.enabled:
            return False

        payload = self._build_payload(jti, hwid, tier, version, boot_count)
        payload["event"] = "startup_verification"

        for attempt in range(1, retries + 1):
            logger.info(f"  Phone-home verification attempt {attempt}/{retries}...")
            if self._do_send_sync(payload):
                return True
            if attempt < retries:
                wait = min(2 ** attempt, 10)
                logger.warning(f"  Phone-home failed, retrying in {wait}s...")
                time.sleep(wait)

        return False

    def verify_or_fail(
        self,
        jti: str = "",
        hwid: str = "",
        tier: str = "",
        boot_count: int = 0,
        retries: int = 3,
    ):
        """
        Mandatory startup verification. Raises PhoneHomeRequiredError on failure.

        This is the enforcement point: Docker containers MUST phone home
        at least once at startup to register their JTI + HWID with the server.
        The server can then detect duplicate activations (same JTI, different HWID).
        """
        if not self.enabled:
            raise PhoneHomeRequiredError(
                "PHONE_HOME_URL is not configured. "
                "Phone-home is REQUIRED for Docker deployments to prevent license sharing. "
                "Set PHONE_HOME_URL in your docker-compose.yml environment variables."
            )

        success = self.send_sync(
            jti=jti, hwid=hwid, tier=tier, boot_count=boot_count, retries=retries,
        )

        if not success:
            raise PhoneHomeRequiredError(
                f"Phone-home verification FAILED after {retries} attempts. "
                f"Could not reach {self.url}. "
                f"The license server must be reachable at startup for Docker deployments. "
                f"Check PHONE_HOME_URL and network connectivity."
            )

        logger.info(f"  Phone-home verified: server acknowledged JTI={jti[:8]}..., HWID={hwid[:16]}...")

    def _build_payload(
        self, jti: str, hwid: str, tier: str, version: str, boot_count: int,
    ) -> dict:
        """Build the beacon payload dict (Fix #13: HMAC-signed)."""
        payload = {
            "jti": jti,
            "hwid": hwid,
            "tier": tier,
            "version": version,
            "boot_count": boot_count,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        # Fix #13: Sign payload with HMAC using JTI as shared secret.
        #
        # IMPORTANT TRADE-OFF (Concern D):
        # JTI is a UUID present in plaintext within the beacon payload, so this
        # is an INTEGRITY CHECK, not secret-based authentication. An attacker who
        # intercepts a beacon can extract the JTI and forge new payloads.
        #
        # Why this is still useful:
        #   1. Prevents casual replay/modification by clients
        #   2. Server can verify the beacon wasn't corrupted in transit
        #   3. True authentication would require a pre-shared secret per license
        #      (e.g., an HMAC key embedded in the JWT), which is a future enhancement.
        #
        # Server-side correlation (JTI+HWID+boot_count) remains the primary
        # anti-fraud defense — the signature is a supplementary check.
        if jti:
            content = json.dumps(payload, sort_keys=True)
            sig = hmac_mod.new(
                jti.encode(), content.encode(), hashlib.sha256
            ).hexdigest()[:32]
            payload["_sig"] = sig
        return payload

    def _do_send_sync(self, payload: dict) -> bool:
        """Blocking HTTP POST. Returns True on success."""
        try:
            import urllib.request
            import urllib.error

            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                self._last_status = f"{resp.status} OK"
                self._last_sent = time.time()
                logger.info(f"  Phone-home beacon sent: {self._last_status}")

                try:
                    resp_body = resp.read().decode("utf-8")
                    if resp_body:
                        resp_data = json.loads(resp_body)
                        server_time = resp_data.get("server_time")
                        if server_time:
                            self._last_server_time = server_time
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

                return True

        except Exception as e:
            self._last_status = f"failed: {str(e)[:80]}"
            logger.warning(f"  Phone-home failed: {e}")
            return False

    def _do_send(self, payload: dict):
        """Async HTTP POST -- runs in background thread (fire-and-forget)."""
        try:
            import urllib.request
            import urllib.error

            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                self._last_status = f"{resp.status} OK"
                self._last_sent = time.time()
                logger.debug(f"Phone-home beacon sent: {self._last_status}")

                try:
                    resp_body = resp.read().decode("utf-8")
                    if resp_body:
                        resp_data = json.loads(resp_body)
                        server_time = resp_data.get("server_time")
                        if server_time:
                            self._last_server_time = server_time
                            logger.debug(f"Server time received: {server_time}")
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

        except Exception as e:
            self._last_status = f"failed: {str(e)[:50]}"
            logger.debug(f"Phone-home beacon failed (non-blocking): {e}")
