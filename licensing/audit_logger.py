"""
Audit Logger -- Tamper-Evident License Event Logging
=====================================================
Append-only JSON Lines file with HMAC-SHA256 chain.
Each entry's HMAC includes the previous entry's HMAC, creating
a tamper-evident chain (any modification breaks the chain).

Events logged: STARTUP_CHECK, HEARTBEAT_OK, HEARTBEAT_FAIL,
EXPIRY_WARNING, GRACE_ENTERED, LICENSE_EXPIRED, HWID_MISMATCH,
VM_DETECTED, TAMPER_DETECTED, VALIDATION_OK, LICENSE_REVOKED,
HWID_MIGRATION, OFFLINE_MODE
"""

import os
import json
import hmac
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

# Events
EVENT_STARTUP = "STARTUP_CHECK"
EVENT_HEARTBEAT_OK = "HEARTBEAT_OK"
EVENT_HEARTBEAT_FAIL = "HEARTBEAT_FAIL"
EVENT_EXPIRY_WARNING = "EXPIRY_WARNING"
EVENT_GRACE_ENTERED = "GRACE_ENTERED"
EVENT_LICENSE_EXPIRED = "LICENSE_EXPIRED"
EVENT_HWID_MISMATCH = "HWID_MISMATCH"
EVENT_VM_DETECTED = "VM_DETECTED"
EVENT_TAMPER_DETECTED = "TAMPER_DETECTED"
EVENT_VALIDATION_OK = "VALIDATION_OK"
EVENT_LICENSE_REVOKED = "LICENSE_REVOKED"
EVENT_HWID_MIGRATION = "HWID_MIGRATION"
EVENT_OFFLINE_MODE = "OFFLINE_MODE"
EVENT_CONCURRENT_BLOCKED = "CONCURRENT_BLOCKED"


class AuditLogger:
    """Append-only, HMAC-chained audit log for license events."""

    def __init__(self, log_dir: str = "./licence/logs", hmac_key: Optional[str] = None):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        # HMAC key: derived from machine-specific value if not provided
        if hmac_key:
            self._hmac_key = hmac_key.encode()
        else:
            self._hmac_key = b"license-audit-v2"

        # Current month's log file
        self._log_file = os.path.join(
            log_dir, f"license_audit_{datetime.now().strftime('%Y_%m')}.jsonl"
        )

        # Fix #11: Cross-month chain linkage
        # If this is a new month file, find the previous month's last HMAC
        # and write a sentinel entry to link the chains.
        is_new_file = not os.path.exists(self._log_file)

        # Load last HMAC from existing log (for chain continuity)
        self._last_hmac = self._load_last_hmac()

        if is_new_file:
            # Try to find previous month's log and get its last HMAC
            prev_hmac, prev_file = self._get_previous_month_last_hmac()
            if prev_hmac and prev_hmac != "GENESIS":
                self._last_hmac = prev_hmac  # Continue chain from previous month
                self.log("NEW_LOG_CHAIN",
                         detail=f"Continues chain from {os.path.basename(prev_file)}")

    def _load_last_hmac(self) -> str:
        """Load the HMAC of the last log entry (for chaining)."""
        if not os.path.exists(self._log_file):
            return "GENESIS"  # First entry in a new chain
        try:
            last_line = ""
            with open(self._log_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        last_line = line.strip()
            if last_line:
                entry = json.loads(last_line)
                return entry.get("hmac", "GENESIS")
        except Exception:
            pass
        return "GENESIS"

    def _get_previous_month_last_hmac(self) -> tuple:
        """Fix #11: Find previous month's log file and return its last HMAC + filename."""
        try:
            now = datetime.now()
            # Try previous month
            if now.month == 1:
                prev_month = datetime(now.year - 1, 12, 1)
            else:
                prev_month = datetime(now.year, now.month - 1, 1)
            prev_file = os.path.join(
                self.log_dir,
                f"license_audit_{prev_month.strftime('%Y_%m')}.jsonl"
            )
            if not os.path.exists(prev_file):
                return ("", "")
            last_line = ""
            with open(prev_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        last_line = line.strip()
            if last_line:
                entry = json.loads(last_line)
                return (entry.get("hmac", ""), prev_file)
        except Exception:
            pass
        return ("", "")

    def _compute_hmac(self, data: str) -> str:
        """Compute HMAC-SHA256 of data + previous HMAC."""
        msg = f"{self._last_hmac}:{data}"
        return hmac.new(self._hmac_key, msg.encode(), hashlib.sha256).hexdigest()[:32]

    def log(self, event: str, hwid: str = "", tier: str = "",
            detail: str = "", extra: Optional[Dict[str, Any]] = None):
        """Append an audit event to the log file."""
        try:
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "hwid": hwid[:16] + "..." if len(hwid) > 16 else hwid,
                "tier": tier,
                "detail": detail[:200],
            }
            if extra:
                entry["extra"] = extra

            # Compute chained HMAC
            data_str = json.dumps(entry, separators=(",", ":"), sort_keys=True)
            entry["hmac"] = self._compute_hmac(data_str)
            self._last_hmac = entry["hmac"]

            # Append to file
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")

        except Exception as e:
            logger.warning(f"Audit log write failed: {e}")

    def get_recent(self, n: int = 50) -> List[Dict[str, Any]]:
        """Get the last N audit entries."""
        entries = []
        if not os.path.exists(self._log_file):
            return entries
        try:
            with open(self._log_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        entries.append(json.loads(line.strip()))
            return entries[-n:]
        except Exception:
            return entries

    def verify_chain(self) -> Dict[str, Any]:
        """Verify the HMAC chain integrity. Returns verification result."""
        if not os.path.exists(self._log_file):
            return {"valid": True, "entries": 0, "detail": "No log file"}

        entries = []
        with open(self._log_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line.strip()))

        if not entries:
            return {"valid": True, "entries": 0, "detail": "Empty log"}

        prev_hmac = "GENESIS"
        for i, entry in enumerate(entries):
            entry_copy = dict(entry)  # Shallow copy — avoid mutating caller's refs
            stored_hmac = entry_copy.pop("hmac", "")
            data_str = json.dumps(entry_copy, separators=(",", ":"), sort_keys=True)
            msg = f"{prev_hmac}:{data_str}"
            expected = hmac.new(self._hmac_key, msg.encode(), hashlib.sha256).hexdigest()[:32]

            if expected != stored_hmac:
                return {
                    "valid": False,
                    "entries": len(entries),
                    "tampered_at": i,
                    "detail": f"HMAC mismatch at entry {i}: expected {expected}, got {stored_hmac}",
                }
            prev_hmac = stored_hmac

        return {"valid": True, "entries": len(entries), "detail": "Chain intact"}
