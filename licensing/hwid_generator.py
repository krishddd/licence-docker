"""
Hardware ID (HWID) Generator
============================
Generates a SHA-256 fingerprint from immutable hardware identifiers:
  - CPU serial / Processor ID
  - Motherboard serial
  - Primary MAC address

Cross-platform: Windows (wmi) / Linux (dmidecode) / macOS (ioreg).
Falls back gracefully if a component is unavailable.

BUG FIXES v1.1:
  - macOS: uses IOPlatformUUID (unique per machine) instead of CPU brand string
  - Linux: tries non-sudo methods first (machine-id, product_serial)
  - Windows: graceful fallback if WMI COM fails
  - All platforms: catches all subprocess errors properly
"""

import hashlib
import platform
import subprocess
import uuid
import logging
import os

logger = logging.getLogger(__name__)

# ── Component Extractors ─────────────────────────────────────────────────────

def _get_mac_address() -> str:
    """Get primary MAC address (universally available)."""
    mac = hex(uuid.getnode())
    logger.debug(f"MAC address: {mac}")
    return mac


def _get_cpu_serial() -> str:
    """Extract CPU serial / Processor ID."""
    system = platform.system()
    try:
        if system == "Windows":
            try:
                import wmi
                c = wmi.WMI()
                cpu_id = c.Win32_Processor()[0].ProcessorId.strip()
                if cpu_id:
                    logger.debug(f"CPU ID (WMI): {cpu_id}")
                    return cpu_id
            except ImportError:
                logger.warning("wmi module not available — using WMIC fallback")
            except Exception as e:
                logger.warning(f"WMI COM error: {e} — using WMIC fallback")
            # Fallback: WMIC command (works without wmi package)
            try:
                out = subprocess.check_output(
                    "wmic cpu get ProcessorId /value",
                    shell=True, timeout=5, stderr=subprocess.DEVNULL
                )
                for line in out.decode(errors="ignore").split("\n"):
                    if "ProcessorId=" in line:
                        cpu_id = line.split("=")[1].strip()
                        if cpu_id:
                            logger.debug(f"CPU ID (WMIC): {cpu_id}")
                            return cpu_id
            except Exception as e:
                logger.warning(f"WMIC cpu fallback failed: {e}")

        elif system == "Linux":
            # Method 1: /etc/machine-id (no sudo required, unique per install)
            for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
                if os.path.exists(path):
                    with open(path, "r") as f:
                        machine_id = f.read().strip()
                        if machine_id:
                            logger.debug(f"Machine ID (Linux): {machine_id[:16]}...")
                            return machine_id
            # Method 2: /proc/cpuinfo (Raspberry Pi has Serial)
            try:
                out = subprocess.check_output(
                    "cat /proc/cpuinfo | grep -i 'serial\\|model name' | head -1",
                    shell=True, timeout=5, stderr=subprocess.DEVNULL
                )
                serial = out.decode().split(":")[-1].strip()
                if serial:
                    logger.debug(f"CPU Info (Linux): {serial[:32]}")
                    return serial
            except Exception:
                pass
            # Method 3: dmidecode (may require sudo)
            try:
                out = subprocess.check_output(
                    "dmidecode -t processor 2>/dev/null | grep 'ID' | head -1",
                    shell=True, timeout=5, stderr=subprocess.DEVNULL
                )
                serial = out.decode().split(":")[-1].strip()
                if serial:
                    logger.debug(f"CPU Serial (dmidecode): {serial}")
                    return serial
            except Exception:
                pass

        elif system == "Darwin":
            # Method 1: IOPlatformUUID (truly unique per machine — FIXED from v1.0)
            try:
                out = subprocess.check_output(
                    "ioreg -rd1 -c IOPlatformExpertDevice | awk '/IOPlatformUUID/{print $3}'",
                    shell=True, timeout=5, stderr=subprocess.DEVNULL
                )
                uuid_val = out.decode().strip().strip('"')
                if uuid_val:
                    logger.debug(f"Platform UUID (macOS): {uuid_val}")
                    return uuid_val
            except Exception:
                pass
            # Method 2: system_profiler hardware UUID
            try:
                out = subprocess.check_output(
                    "system_profiler SPHardwareDataType | awk '/Hardware UUID/{print $3}'",
                    shell=True, timeout=5, stderr=subprocess.DEVNULL
                )
                uuid_val = out.decode().strip()
                if uuid_val:
                    logger.debug(f"Hardware UUID (macOS): {uuid_val}")
                    return uuid_val
            except Exception:
                pass

    except Exception as e:
        logger.warning(f"CPU serial extraction failed: {e}")
    return f"cpu-{platform.node()}"  # Fallback: hostname (better than "unknown")


def _get_board_serial() -> str:
    """Extract motherboard / baseboard serial number."""
    system = platform.system()
    try:
        if system == "Windows":
            try:
                import wmi
                c = wmi.WMI()
                boards = c.Win32_BaseBoard()
                if boards:
                    serial = boards[0].SerialNumber.strip()
                    if serial and serial not in ["None", "Default string", "To Be Filled By O.E.M."]:
                        logger.debug(f"Board Serial (WMI): {serial}")
                        return serial
            except ImportError:
                logger.warning("wmi module not available — using WMIC fallback")
            except Exception as e:
                logger.warning(f"WMI COM error for baseboard: {e}")
            # Fallback: WMIC
            try:
                out = subprocess.check_output(
                    "wmic baseboard get serialnumber /value",
                    shell=True, timeout=5, stderr=subprocess.DEVNULL
                )
                for line in out.decode(errors="ignore").split("\n"):
                    if "SerialNumber=" in line:
                        serial = line.split("=")[1].strip()
                        if serial and serial not in ["None", "Default string", "To Be Filled By O.E.M."]:
                            logger.debug(f"Board Serial (WMIC): {serial}")
                            return serial
            except Exception:
                pass

        elif system == "Linux":
            # Method 1: /sys filesystem (no sudo)
            for path in [
                "/sys/class/dmi/id/board_serial",
                "/sys/class/dmi/id/product_serial",
                "/sys/class/dmi/id/product_uuid",
            ]:
                if os.path.exists(path):
                    try:
                        with open(path, "r") as f:
                            serial = f.read().strip()
                            if serial and serial not in ["None", ""]:
                                logger.debug(f"Board Serial (sysfs): {serial}")
                                return serial
                    except PermissionError:
                        pass
            # Method 2: dmidecode (may need sudo)
            try:
                out = subprocess.check_output(
                    "dmidecode -t baseboard 2>/dev/null | grep 'Serial Number' | head -1",
                    shell=True, timeout=5, stderr=subprocess.DEVNULL
                )
                serial = out.decode().split(":")[-1].strip()
                if serial:
                    logger.debug(f"Board Serial (dmidecode): {serial}")
                    return serial
            except Exception:
                pass

        elif system == "Darwin":
            # IOPlatformSerialNumber (Mac serial number — unique per device)
            try:
                out = subprocess.check_output(
                    "ioreg -rd1 -c IOPlatformExpertDevice | awk '/IOPlatformSerialNumber/{print $3}'",
                    shell=True, timeout=5, stderr=subprocess.DEVNULL
                )
                serial = out.decode().strip().strip('"')
                if serial:
                    logger.debug(f"Board Serial (macOS): {serial}")
                    return serial
            except Exception:
                pass

    except Exception as e:
        logger.warning(f"Board serial extraction failed: {e}")
    return f"board-{platform.node()}"  # Fallback: hostname


# ── Main HWID Generator ──────────────────────────────────────────────────────

def _is_docker_environment() -> bool:
    """Check if running inside a Docker container."""
    try:
        from licensing.docker_hwid import is_docker
        return is_docker()
    except ImportError:
        return False


def generate_hwid() -> str:
    """
    Generate a unique Hardware ID by hashing immutable system identifiers.

    Auto-detects Docker: if running inside a container, uses bind-mounted
    host identifiers instead of direct hardware queries.

    Returns:
        64-character hexadecimal SHA-256 hash string.
    """
    # Docker mode: delegate to docker_hwid.py
    if _is_docker_environment():
        try:
            from licensing.docker_hwid import generate_docker_hwid
            return generate_docker_hwid()
        except Exception as e:
            logger.warning(f"Docker HWID failed, falling back to local: {e}")

    # Bare metal mode: use CPU + Board + MAC
    cpu = _get_cpu_serial()
    board = _get_board_serial()
    mac = _get_mac_address()

    raw_string = f"{cpu}|{board}|{mac}"
    hwid = hashlib.sha256(raw_string.encode("utf-8")).hexdigest()

    logger.info(f"Generated HWID: {hwid[:16]}...{hwid[-8:]}")
    return hwid


def get_hwid_components() -> dict:
    """Return individual hardware components (for diagnostics)."""
    return {
        "cpu_serial": _get_cpu_serial(),
        "board_serial": _get_board_serial(),
        "mac_address": _get_mac_address(),
        "platform": platform.system(),
        "machine": platform.machine(),
        "hostname": platform.node(),
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    print(f"\n  Hardware ID: {generate_hwid()}")
    print(f"  Components: {get_hwid_components()}\n")
