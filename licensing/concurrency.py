"""
Concurrent User Enforcement
=============================
Prevents the same license from running on multiple machines simultaneously.

Uses a lockfile with HWID + PID + heartbeat timestamp.
On startup, checks if another instance is active. If the lock is stale
(older than 2x heartbeat interval), it's considered dead and replaced.
"""

import os
import json
import time
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class ConcurrentUseError(Exception):
    """Raised when the same license is already active on another machine."""
    pass


class ConcurrencyGuard:
    """Lockfile-based concurrent use detection."""

    def __init__(
        self,
        lock_dir: str = "./License",
        hwid: str = "",
        stale_seconds: float = 3600,  # Lock stale after 1 hour (2x heartbeat)
    ):
        self._lock_file = os.path.join(lock_dir, ".active_lock")
        self._hwid = hwid
        self._pid = os.getpid()
        self._stale_seconds = stale_seconds

    def _read_lock(self) -> Optional[Dict[str, Any]]:
        """Read existing lock file."""
        if not os.path.exists(self._lock_file):
            return None
        try:
            with open(self._lock_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _write_lock(self):
        """Write/refresh the lock file (Fix #9: atomic via temp+rename)."""
        import tempfile
        lock = {
            "hwid": self._hwid,
            "pid": self._pid,
            "started": time.time(),
            "last_heartbeat": time.time(),
            "hostname": os.environ.get("COMPUTERNAME", os.environ.get("HOSTNAME", "unknown")),
        }
        dir_ = os.path.dirname(self._lock_file) or "."
        os.makedirs(dir_, exist_ok=True)
        # Write to temp file then atomically rename (prevents TOCTOU race)
        fd, tmp_path = tempfile.mkstemp(dir=dir_, prefix=".lock_tmp_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(lock, f, indent=2)
            os.replace(tmp_path, self._lock_file)  # Atomic on POSIX, near-atomic on Windows
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def acquire(self) -> bool:
        """
        Try to acquire the lock.
        Returns True if acquired, raises ConcurrentUseError if another
        instance is active on a different machine.
        """
        existing = self._read_lock()

        if existing is None:
            # No lock = first instance
            self._write_lock()
            logger.info("Concurrency lock acquired (first instance)")
            return True

        # Same machine, same or different PID = OK (restart)
        if existing.get("hwid") == self._hwid:
            self._write_lock()
            logger.info("Concurrency lock acquired (same machine)")
            return True

        # Different machine — check if stale
        last_beat = existing.get("last_heartbeat", 0)
        age = time.time() - last_beat

        if age > self._stale_seconds:
            # Stale lock — previous instance died
            logger.warning(
                f"Stale lock detected (age={age:.0f}s > {self._stale_seconds}s). "
                f"Previous HWID: {existing.get('hwid', '?')[:16]}..."
            )
            self._write_lock()
            return True

        # Active lock on different machine
        raise ConcurrentUseError(
            f"License already active on another machine "
            f"(HWID: {existing.get('hwid', '?')[:16]}..., "
            f"host: {existing.get('hostname', '?')}, "
            f"last seen {age:.0f}s ago)"
        )

    def refresh(self):
        """Refresh the lock timestamp (called on heartbeat).
        Concern C: Uses atomic write consistent with _write_lock().
        """
        import tempfile
        existing = self._read_lock()
        if existing and existing.get("hwid") == self._hwid:
            existing["last_heartbeat"] = time.time()
            dir_ = os.path.dirname(self._lock_file) or "."
            fd, tmp_path = tempfile.mkstemp(dir=dir_, prefix=".lock_ref_")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(existing, f, indent=2)
                os.replace(tmp_path, self._lock_file)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise

    def release(self):
        """Release the lock (called on shutdown)."""
        try:
            if os.path.exists(self._lock_file):
                existing = self._read_lock()
                if existing and existing.get("hwid") == self._hwid:
                    os.remove(self._lock_file)
                    logger.info("Concurrency lock released")
        except Exception as e:
            logger.warning(f"Could not release lock: {e}")
