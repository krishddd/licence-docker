"""
Open-Source Licensing System for FastAPI Pipelines (v3.1 Security Hardened)
===========================================================================
Modules:
    hwid_generator    -- Hardware fingerprint (SHA-256 of CPU + Board + MAC)
    docker_hwid       -- Docker-specific HWID from host bind mounts (v3.1: K8s-only + RSA)
    auto_activator    -- First-run auto-activation for Docker containers (v3.1: timestamp monotonicity)
    phone_home        -- License monitoring beacon (v3.1: boot_count + full HWID)
    license_validator -- 6-layer validation (RSA+JWT+HWID+NTP+Revoke+Grace) (v3.1: NTP enforced)
    license_middleware-- FastAPI startup gate + Depends() + heartbeat
    tier_manager      -- Tier-based pipeline access control
    vm_detector       -- VM/container detection (anti-cloning)
    audit_logger      -- Tamper-evident HMAC-chained audit log
    heartbeat         -- Background license re-validation thread
    revocation        -- JTI-based license revocation system
    integrity         -- SHA-256 runtime code integrity checker (v3.1: JWT baseline)
    concurrency       -- Lockfile-based concurrent use guard
"""

from licensing.hwid_generator import generate_hwid
from licensing.license_validator import LicenseValidator, LicenseInfo, LicenseError
from licensing.tier_manager import TierManager
from licensing.vm_detector import VMDetector, enforce_physical_machine
from licensing.audit_logger import AuditLogger
from licensing.heartbeat import LicenseHeartbeat
from licensing.revocation import RevocationChecker, LicenseRevokedError
from licensing.integrity import IntegrityChecker, TamperDetectedError
from licensing.concurrency import ConcurrencyGuard, ConcurrentUseError
from licensing.docker_hwid import (
    generate_docker_hwid, is_docker, DockerHWIDError,
    HWIDSignatureError, BindMountSpoofError,
)
from licensing.auto_activator import AutoActivator, ActivationError, ActivationLimitError
from licensing.phone_home import PhoneHomeBeacon

__all__ = [
    "generate_hwid",
    "LicenseValidator", "LicenseInfo", "LicenseError",
    "TierManager",
    "VMDetector", "enforce_physical_machine",
    "AuditLogger",
    "LicenseHeartbeat",
    "RevocationChecker", "LicenseRevokedError",
    "IntegrityChecker", "TamperDetectedError",
    "ConcurrencyGuard", "ConcurrentUseError",
    # v3.1 Docker (security hardened)
    "generate_docker_hwid", "is_docker", "DockerHWIDError",
    "HWIDSignatureError", "BindMountSpoofError",
    "AutoActivator", "ActivationError", "ActivationLimitError",
    "PhoneHomeBeacon",
]

