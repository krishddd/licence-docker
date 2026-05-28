"""
Heartbeat System -- Background License Re-validation
======================================================
Runs a background thread that periodically re-validates the license.
After MAX_FAILURES consecutive failures, marks the license as invalid
and all gated endpoints return 403.

Usage (automatic via startup_license_check):
    heartbeat = LicenseHeartbeat(validator, interval=1800)
    heartbeat.start()
"""

import time
import logging
import threading
from typing import Optional, Callable

logger = logging.getLogger(__name__)


class LicenseHeartbeat:
    """Background thread that periodically re-validates the license."""

    def __init__(
        self,
        validate_fn: Callable,
        on_failure: Optional[Callable] = None,
        on_success: Optional[Callable] = None,
        interval: float = 1800,       # 30 minutes default
        max_failures: int = 3,         # 3 consecutive failures = kill
        audit_fn: Optional[Callable] = None,
    ):
        self._validate_fn = validate_fn
        self._on_failure = on_failure
        self._on_success = on_success
        self._interval = interval
        self._max_failures = max_failures
        self._audit_fn = audit_fn

        self._failure_count = 0
        self._total_beats = 0
        self._last_beat_ok = True
        self._last_beat_time: Optional[float] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @property
    def is_healthy(self) -> bool:
        return self._failure_count < self._max_failures

    @property
    def status(self) -> dict:
        return {
            "running": self._running,
            "healthy": self.is_healthy,
            "total_beats": self._total_beats,
            "consecutive_failures": self._failure_count,
            "max_failures": self._max_failures,
            "interval_seconds": self._interval,
            "last_beat_ok": self._last_beat_ok,
            "last_beat_time": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(self._last_beat_time)
            ) if self._last_beat_time else None,
        }

    def start(self):
        """Start the heartbeat background thread."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name="license-heartbeat"
        )
        self._thread.start()
        logger.info(
            f"Heartbeat started: interval={self._interval}s, "
            f"max_failures={self._max_failures}"
        )

    def stop(self):
        """Stop the heartbeat thread."""
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("Heartbeat stopped")

    def _heartbeat_loop(self):
        """Main heartbeat loop — runs in background thread."""
        # Wait for first interval before first beat
        self._stop_event.wait(self._interval)

        while not self._stop_event.is_set():
            self._total_beats += 1
            self._last_beat_time = time.time()

            try:
                result = self._validate_fn()
                self._failure_count = 0
                self._last_beat_ok = True
                logger.debug(f"Heartbeat #{self._total_beats} OK")

                if self._audit_fn:
                    self._audit_fn("HEARTBEAT_OK", detail=f"Beat #{self._total_beats}")
                if self._on_success:
                    self._on_success(result)

            except Exception as e:
                self._failure_count += 1
                self._last_beat_ok = False
                logger.warning(
                    f"Heartbeat #{self._total_beats} FAILED "
                    f"({self._failure_count}/{self._max_failures}): {e}"
                )

                if self._audit_fn:
                    self._audit_fn(
                        "HEARTBEAT_FAIL",
                        detail=f"Beat #{self._total_beats}: {str(e)[:100]}",
                    )

                if self._failure_count >= self._max_failures:
                    logger.error(
                        f"HEARTBEAT DEAD: {self._max_failures} consecutive failures. "
                        f"License marked INVALID."
                    )
                    if self._on_failure:
                        self._on_failure()
                    # Don't stop — keep trying in case it recovers
                    # but the on_failure callback should invalidate the license

            # Wait for next interval
            self._stop_event.wait(self._interval)
