"""
Runtime Integrity Checker (v3.1 — Security Hardened)
=====================================================
Detects if licensing code has been modified (reverse engineering defense).

On startup: computes SHA-256 hash of all licensing/*.py files.
On heartbeat: re-computes and compares. If mismatch -> TamperDetectedError.

v3.1 Security Hardening:
  - JWT-embedded file hashes: when set_jwt_baseline() is called with hashes
    from the signed license JWT, those hashes become the ONLY reference.
    This defeats the baseline-bypass attack where an attacker modifies code
    BEFORE the container starts (the old self-computed baseline would simply
    hash the hacked files as valid).
  - Cross-platform line-ending normalization: files are read in text mode,
    lines are stripped and joined with \\n before hashing. This prevents
    Windows (\\r\\n) vs Linux (\\n) mismatches when the license is generated
    on Windows but runs in Docker/Linux.
"""

import os
import hashlib
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class TamperDetectedError(Exception):
    """Raised when licensing code has been modified at runtime."""
    pass


class IntegrityChecker:
    """Verify that licensing module files haven't been tampered with."""

    # Files to monitor
    MONITORED_FILES = [
        "license_validator.py",
        "license_middleware.py",
        "hwid_generator.py",
        "tier_manager.py",
        "vm_detector.py",
        "heartbeat.py",
        "revocation.py",
        "audit_logger.py",
        "docker_hwid.py",
        "auto_activator.py",
        "phone_home.py",
        "integrity.py",
        "concurrency.py",
    ]

    def __init__(self, licensing_dir: Optional[str] = None, jwt_hashes: Optional[Dict[str, str]] = None):
        if licensing_dir is None:
            licensing_dir = os.path.dirname(os.path.abspath(__file__))
        self._dir = licensing_dir
        self._jwt_baseline: Optional[Dict[str, str]] = jwt_hashes
        self._baseline: Dict[str, str] = {}
        self._compute_baseline()

    @staticmethod
    def _normalize_content(filepath: str) -> str:
        """
        Read file and normalize line endings for cross-platform hash consistency.

        Opens in text mode (auto-converts platform line endings), then
        joins lines with \\n. This ensures the same hash is produced on
        Windows (\\r\\n) and Linux (\\n).
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()
            # Strip trailing whitespace from each line and join with \n
            normalized = "\n".join(line.rstrip() for line in lines)
            return normalized
        except FileNotFoundError:
            return ""

    @staticmethod
    def _hash_content(content: str) -> str:
        """Compute SHA-256 of normalized string content."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _hash_file(self, filepath: str) -> str:
        """
        Compute SHA-256 hash of a file with line-ending normalization.

        v3.1: Uses text-mode reading + line normalization to ensure
        consistent hashes across Windows and Linux platforms.
        """
        content = self._normalize_content(filepath)
        if not content:
            return "FILE_NOT_FOUND"
        return self._hash_content(content)

    def _compute_baseline(self):
        """Compute baseline hashes of all monitored files."""
        for filename in self.MONITORED_FILES:
            filepath = os.path.join(self._dir, filename)
            if os.path.exists(filepath):
                self._baseline[filename] = self._hash_file(filepath)
        logger.info(f"Integrity baseline: {len(self._baseline)} files hashed")

    def set_jwt_baseline(self, jwt_hashes: Dict[str, str]):
        """
        Set the reference baseline from JWT-embedded hashes.

        When called, the JWT hashes become the ONLY reference for
        integrity checks. This defeats the baseline-bypass attack where
        an attacker modifies code before the container starts.

        Args:
            jwt_hashes: dict of {filename: sha256_hex} from the license JWT
        """
        self._jwt_baseline = jwt_hashes
        logger.info(
            f"Integrity baseline set from JWT claims: {len(jwt_hashes)} file hashes. "
            f"Self-computed baseline will be IGNORED in favor of JWT hashes."
        )

    def get_hashes(self) -> Dict[str, str]:
        """Get current baseline hashes (for embedding in license JWT)."""
        return dict(self._baseline)

    def verify(self, expected_hashes: Optional[Dict[str, str]] = None) -> Dict:
        """
        Verify file integrity.

        Priority for reference hashes:
          1. Explicit expected_hashes parameter (highest priority)
          2. JWT-embedded hashes (set via set_jwt_baseline)
          3. Startup self-computed baseline (fallback, weakest)

        Fix #5: When Cython-compiled (.py files removed), explicitly handle:
          - ALL files missing + JWT baseline → expected Cython build, skip (valid)
          - SOME files missing + JWT baseline → suspicious partial tampering (warning)
          - No JWT baseline → fall back to self-computed (no .py = no baseline = pass)
        """
        # v3.1: JWT baseline takes precedence over self-computed
        reference = expected_hashes or self._jwt_baseline or self._baseline
        current = {}
        tampered = []

        for filename in self.MONITORED_FILES:
            filepath = os.path.join(self._dir, filename)
            if os.path.exists(filepath):
                current[filename] = self._hash_file(filepath)
                if filename in reference and current[filename] != reference[filename]:
                    tampered.append(filename)

        # Fix #5: Handle Cython-compiled deploys
        baseline_source = (
            "explicit" if expected_hashes
            else "jwt" if self._jwt_baseline
            else "self-computed"
        )

        if self._jwt_baseline and len(current) == 0:
            # ALL .py files compiled/removed — expected for Cython build
            logger.info(
                "Integrity: all .py files compiled/removed — "
                "skipping check (expected for Cython build)"
            )
            return {
                "valid": True,
                "files_checked": 0,
                "tampered_files": [],
                "baseline_source": "jwt_cython_skip",
            }

        if self._jwt_baseline and 0 < len(current) < 5:
            # Partial files exist — suspicious (some compiled, some not)
            logger.warning(
                f"Integrity: only {len(current)}/{len(self.MONITORED_FILES)} "
                f"files found — possible partial tampering"
            )

        result = {
            "valid": len(tampered) == 0,
            "files_checked": len(current),
            "tampered_files": tampered,
            "baseline_source": baseline_source,
        }

        if tampered:
            logger.error(f"INTEGRITY VIOLATION: {tampered} (baseline: {result['baseline_source']})")
        else:
            logger.debug(f"Integrity check passed: {len(current)} files OK (baseline: {result['baseline_source']})")

        return result

    def enforce(self, expected_hashes: Optional[Dict[str, str]] = None):
        """Verify and raise TamperDetectedError if tampered."""
        result = self.verify(expected_hashes)
        if not result["valid"]:
            raise TamperDetectedError(
                f"License code tampered: {', '.join(result['tampered_files'])} "
                f"(verified against {result['baseline_source']} baseline)"
            )
