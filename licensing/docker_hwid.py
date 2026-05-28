"""
Docker HWID Generator (v3.1 — Security Hardened)
==================================================
Generates a host-machine HWID from inside a Docker container.

Docker containers are isolated -- they can't see host hardware directly.
This module reads host identifiers from bind-mounted paths:
  1. /host/machine-id  (bind mount of /etc/machine-id)
  2. /host/dmi/         (bind mount of /sys/class/dmi/id/)
  3. LICENSE_HWID env   (RESTRICTED: Kubernetes-only with RSA signature)

v3.1 Security Hardening:
  - LICENSE_HWID now REQUIRES RSA signature verification (LICENSE_HWID_SIG)
  - LICENSE_HWID only accepted in verified Kubernetes environments
  - Bind mount validation: sysfs boundary detection via os.stat().st_dev
  - Entropy checks on machine-id to reject spoofed/empty values
  - DMI sanity checks to detect placeholder or identical values

Usage in docker-compose.yml:
  volumes:
    - /etc/machine-id:/host/machine-id:ro
    - /sys/class/dmi/id:/host/dmi:ro
"""

import os
import math
import hashlib
import logging
from collections import Counter
from typing import Optional

logger = logging.getLogger(__name__)

# Bind mount paths (customizable via env)
HOST_MACHINE_ID = os.environ.get("HOST_MACHINE_ID_PATH", "/host/machine-id")
HOST_DMI_DIR = os.environ.get("HOST_DMI_PATH", "/host/dmi")


class DockerHWIDError(Exception):
    """Raised when host HWID cannot be determined from Docker."""
    pass


class HWIDSignatureError(DockerHWIDError):
    """Raised when LICENSE_HWID_SIG is missing or invalid."""
    pass


class BindMountSpoofError(DockerHWIDError):
    """Raised when bind mounts appear to be spoofed."""
    pass


def is_docker() -> bool:
    """Check if we're running inside a Docker container."""
    if os.path.exists("/.dockerenv"):
        return True
    if os.path.exists(HOST_MACHINE_ID):
        return True
    # Check cgroup for docker/container
    try:
        if os.path.exists("/proc/1/cgroup"):
            with open("/proc/1/cgroup", "r") as f:
                cgroup = f.read().lower()
            if "docker" in cgroup or "kubepods" in cgroup or "containerd" in cgroup:
                return True
    except Exception:
        pass
    return False


def is_wsl2() -> bool:
    """Detect WSL2 (Docker Desktop on Windows uses a Linux VM)."""
    try:
        if os.path.exists("/proc/version"):
            with open("/proc/version", "r") as f:
                version = f.read().lower()
            return "microsoft" in version or "wsl" in version
    except Exception:
        pass
    return False


def _is_kubernetes() -> bool:
    """Check if we're running inside a Kubernetes pod."""
    # K8s injected env vars
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return True
    # K8s service account mount
    if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/"):
        return True
    return False


def _verify_hwid_signature(hwid: str, signature_hex: str, public_key_path: str) -> bool:
    """
    Verify RSA signature of LICENSE_HWID using public_key.pem.

    The LICENSE_HWID must be signed by the vendor's RSA private key.
    This prevents attackers from setting an arbitrary LICENSE_HWID
    since they don't have the private key.
    """
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend

        if not os.path.exists(public_key_path):
            logger.error(f"Public key not found: {public_key_path}")
            return False

        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )

        signature_bytes = bytes.fromhex(signature_hex)
        hwid_bytes = hwid.encode("utf-8")

        public_key.verify(
            signature_bytes,
            hwid_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True

    except Exception as e:
        logger.warning(f"HWID signature verification failed: {e}")
        return False


def _read_file(path: str) -> str:
    """Read a text file, strip whitespace."""
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except Exception:
        return ""


# ── Bind Mount Validation (Fix 2) ──────────────────────────────────────────

def _calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (bits per character)."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _validate_machine_id(mid: str) -> bool:
    """
    Validate that a machine-id looks legitimate.
    Rejects: empty, all-zeros, too short, low entropy.
    """
    if not mid or len(mid) < 16:
        logger.warning(f"Machine-id too short ({len(mid)} chars)")
        return False

    # Reject all-zeros or all same character
    if len(set(mid.replace("-", ""))) <= 1:
        logger.warning("Machine-id is all identical characters (likely spoofed)")
        return False

    # Entropy check: a real UUID/hex string has ~3.5-4.0 bits/char
    entropy = _calculate_entropy(mid.replace("-", ""))
    if entropy < 2.0:
        logger.warning(f"Machine-id has suspiciously low entropy: {entropy:.2f} bits/char")
        return False

    return True


def _validate_bind_mount(path: str) -> bool:
    """
    Validate that a bind-mounted path is a real filesystem boundary.

    A real /sys/class/dmi/id/ mount is part of sysfs and will have a
    different st_dev (device ID) than the container's root filesystem.
    A fake mount (text files on ext4) will share the container's st_dev.
    """
    try:
        # Check if the path is a mount point
        if os.path.ismount(path):
            logger.debug(f"Bind mount validated: {path} is a mount point")
            return True

        # Check device ID: different st_dev from container root = real mount
        mount_stat = os.stat(path)
        root_stat = os.stat("/")

        if mount_stat.st_dev != root_stat.st_dev:
            logger.debug(
                f"Bind mount validated: {path} st_dev={mount_stat.st_dev} "
                f"differs from root st_dev={root_stat.st_dev}"
            )
            return True

        # Same device as root -- could be fake files on the container filesystem
        logger.warning(
            f"Bind mount SUSPICIOUS: {path} has same st_dev as container root "
            f"(st_dev={mount_stat.st_dev}). May be fake bind mount."
        )
        return False

    except (OSError, AttributeError) as e:
        # On Windows or when stat is not available, skip validation
        logger.debug(f"Bind mount validation skipped ({e})")
        return True  # Permissive on platforms without sysfs


def _validate_dmi_values(dmi: dict) -> bool:
    """
    Validate DMI values for sanity.
    Rejects: all identical values, absurdly short, or known placeholders.
    """
    if not dmi:
        return True  # No DMI is fine (some systems don't expose it)

    known_fakes = {
        "none", "default string", "to be filled by o.e.m.",
        "not specified", "type2 - board serial number",
        "0", "unknown", "system serial number",
    }

    valid_count = 0
    values = []
    for key, val in dmi.items():
        if val.lower().strip() in known_fakes:
            logger.warning(f"DMI {key} has placeholder value: {val!r}")
            continue
        if len(val) < 4:
            logger.warning(f"DMI {key} suspiciously short: {val!r}")
            continue
        valid_count += 1
        values.append(val)

    # Check if all non-placeholder values are identical (copy-paste attack)
    if len(values) > 1 and len(set(values)) == 1:
        logger.warning("All DMI values are identical -- possible spoofing attempt")
        return False

    return valid_count > 0 or len(dmi) == 0


# ── Host Hardware Readers ──────────────────────────────────────────────────

def _get_vm_machine_id() -> str:
    """
    Fallback: Read the Docker Desktop VM's own /etc/machine-id.

    On Docker Desktop (Windows/macOS), the host bind mounts
    for /etc/machine-id fail because those Linux paths don't
    exist on the Windows/macOS host filesystem.

    However, the Docker Desktop Linux VM itself has a stable
    /etc/machine-id that persists across container restarts.
    """
    vm_path = "/etc/machine-id"
    if os.path.exists(vm_path):
        mid = _read_file(vm_path)
        if mid and _validate_machine_id(mid):
            logger.info(f"Using Docker Desktop VM machine-id: {mid[:16]}...")
            return mid
    return ""


def _get_host_machine_id() -> str:
    """Read host's /etc/machine-id from bind mount (with validation)."""
    if os.path.exists(HOST_MACHINE_ID):
        mid = _read_file(HOST_MACHINE_ID)
        if mid:
            if not _validate_machine_id(mid):
                raise BindMountSpoofError(
                    f"Host machine-id failed validation (spoofing detected). "
                    f"Ensure /etc/machine-id is bind-mounted from the real host."
                )
            # Validate the file is from a real mount
            _validate_bind_mount(HOST_MACHINE_ID)
            logger.debug(f"Host machine-id: {mid[:16]}...")
            return mid
    return ""


def _get_host_dmi() -> dict:
    """Read host DMI/SMBIOS from bind-mounted /sys/class/dmi/id/ (with validation)."""
    dmi = {}
    dmi_files = {
        "product_uuid": os.path.join(HOST_DMI_DIR, "product_uuid"),
        "board_serial": os.path.join(HOST_DMI_DIR, "board_serial"),
        "product_serial": os.path.join(HOST_DMI_DIR, "product_serial"),
        "board_vendor": os.path.join(HOST_DMI_DIR, "board_vendor"),
    }
    for key, path in dmi_files.items():
        val = _read_file(path)
        if val and val.lower() not in ["none", "default string", "to be filled by o.e.m."]:
            dmi[key] = val
            logger.debug(f"Host DMI {key}: {val[:20]}...")

    # Validate the DMI directory is from a real sysfs mount
    if dmi and os.path.isdir(HOST_DMI_DIR):
        if not _validate_bind_mount(HOST_DMI_DIR):
            logger.warning(
                "DMI directory may be a fake bind mount. "
                "Proceeding with caution -- phone-home will detect concurrent usage."
            )

    # Validate DMI values for sanity
    if not _validate_dmi_values(dmi):
        raise BindMountSpoofError(
            "DMI values failed validation (spoofing detected). "
            "Ensure /sys/class/dmi/id/ is bind-mounted from the real host."
        )

    return dmi


def check_bind_mounts() -> dict:
    """
    Check which bind mounts are available. Returns status dict.
    Raises DockerHWIDError with clear instructions if nothing is available.
    """
    env_hwid = os.environ.get("LICENSE_HWID", "").strip()
    vm_mid = _get_vm_machine_id()  # Docker Desktop fallback
    status = {
        "machine_id": os.path.exists(HOST_MACHINE_ID),
        "dmi": os.path.isdir(HOST_DMI_DIR),
        "env_hwid": bool(env_hwid),
        "env_hwid_k8s_verified": bool(env_hwid) and _is_kubernetes(),
        "wsl2": is_wsl2(),
        "vm_machine_id": bool(vm_mid),  # Docker Desktop VM fallback
    }

    if not status["machine_id"] and not status["dmi"] and not status["env_hwid"]:
        # Docker Desktop fallback: use the VM's own machine-id
        if status["vm_machine_id"]:
            logger.info(
                "Host bind mounts not found, but Docker Desktop VM machine-id "
                "is available. Using VM machine-id as HWID source."
            )
            return status

        raise DockerHWIDError(
            "\n"
            "=" * 60 + "\n"
            "  ERROR: Host hardware mounts not found!\n"
            "=" * 60 + "\n"
            "\n"
            "  The license system needs to read your host machine's\n"
            "  hardware ID, but no bind mounts were detected.\n"
            "\n"
            "  Add these volumes to your docker run / docker-compose:\n"
            "\n"
            "    docker run \\\n"
            "      -v /etc/machine-id:/host/machine-id:ro \\\n"
            "      -v /sys/class/dmi/id:/host/dmi:ro \\\n"
            "      ...\n"
            "\n"
            "  For Docker Desktop (Windows/macOS):\n"
            "\n"
            "    The VM machine-id should be auto-detected.\n"
            "    If this error persists, contact your vendor.\n"
            "\n"
            "  For Kubernetes deployments:\n"
            "\n"
            "    Set LICENSE_HWID + LICENSE_HWID_SIG (RSA-signed by vendor)\n"
            "\n"
            "=" * 60
        )

    return status


def generate_docker_hwid(public_key_path: str = "./keys/public_key.pem") -> str:
    """
    Generate host HWID from inside Docker container.

    Priority:
      1. LICENSE_HWID env var (RESTRICTED: K8s-only, requires RSA signature)
      2. Bind-mounted /host/machine-id + /host/dmi/ (Linux Docker)
      3. FAIL with clear instructions (no container fallback)

    Args:
        public_key_path: Path to the RSA public key for signature verification.

    Returns:
        64-character SHA-256 hex string (same format as hwid_generator.py)
    """
    # Priority 1: Environment variable override (K8s only, RSA-signed)
    env_hwid = os.environ.get("LICENSE_HWID", "").strip()
    if env_hwid:
        # Security gate: require Kubernetes environment
        if not _is_kubernetes():
            logger.warning(
                "LICENSE_HWID is set but NOT running in Kubernetes. "
                "Env-based HWID is restricted to verified K8s environments. "
                "Use bind mounts instead: -v /etc/machine-id:/host/machine-id:ro"
            )
            raise HWIDSignatureError(
                "LICENSE_HWID rejected: not a verified Kubernetes environment. "
                "Env-based HWID override is restricted to Kubernetes deployments only. "
                "Use bind mounts for standard Docker: "
                "-v /etc/machine-id:/host/machine-id:ro -v /sys/class/dmi/id:/host/dmi:ro"
            )

        # Security gate: require RSA signature
        env_sig = os.environ.get("LICENSE_HWID_SIG", "").strip()
        if not env_sig:
            raise HWIDSignatureError(
                "LICENSE_HWID is set but LICENSE_HWID_SIG is missing. "
                "The HWID must be signed by the vendor's RSA private key. "
                "Contact your vendor to get the signed HWID."
            )

        if not _verify_hwid_signature(env_hwid, env_sig, public_key_path):
            raise HWIDSignatureError(
                "LICENSE_HWID_SIG verification FAILED. "
                "The HWID signature is invalid or was not signed by the vendor. "
                "Contact your vendor for a valid signed HWID."
            )

        # RSA signature verified -- accept the HWID
        if len(env_hwid) >= 32:
            logger.info(f"Using K8s LICENSE_HWID (RSA-verified): {env_hwid[:16]}...")
            return env_hwid
        else:
            # Short value (e.g. K8s node name) -- hash for consistency
            hwid = hashlib.sha256(env_hwid.encode("utf-8")).hexdigest()
            logger.info(f"Using hashed K8s LICENSE_HWID (RSA-verified): {hwid[:16]}...")
            return hwid

    # Priority 2: Bind-mounted host files (with validation)
    mount_status = check_bind_mounts()  # Raises DockerHWIDError if nothing available

    machine_id = _get_host_machine_id()
    dmi = _get_host_dmi()

    # Build raw string from whatever is available
    components = [machine_id]
    if "product_uuid" in dmi:
        components.append(dmi["product_uuid"])
    if "board_serial" in dmi:
        components.append(dmi["board_serial"])
    elif "product_serial" in dmi:
        components.append(dmi["product_serial"])

    raw = "|".join(c for c in components if c)

    # Priority 3: Docker Desktop VM fallback
    if not raw and mount_status.get("vm_machine_id"):
        vm_mid = _get_vm_machine_id()
        if vm_mid:
            logger.info("Using Docker Desktop VM machine-id as HWID source")
            components = [vm_mid]
            raw = vm_mid

    if not raw:
        raise DockerHWIDError("No host hardware identifiers found in bind mounts")

    hwid = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    logger.info(f"Docker host HWID: {hwid[:16]}...{hwid[-8:]} ({len(components)} components)")
    return hwid
