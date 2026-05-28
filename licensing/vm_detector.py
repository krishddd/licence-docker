"""
Virtual Machine Detector — Anti-Cloning Protection
====================================================
Detects if the application is running inside a virtual machine or container.
Prevents license cloning by blocking execution in virtualized environments.

Detection methods:
  - BIOS/DMI strings (VirtualBox, VMware, QEMU, Hyper-V, Xen, Parallels)
  - Registry keys (Windows VM artifacts)
  - MAC address OUI prefixes (VM vendor NICs)
  - CPU hypervisor bit (CPUID leaf 1, ECX bit 31)
  - /proc filesystem indicators (Linux containers)
  - System model/manufacturer strings
  - Docker/container detection

Security note: Determined attackers can spoof these, but it raises the bar
significantly above casual VM cloning.
"""

import os
import platform
import subprocess
import re
import uuid
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)


# ── Known VM Signatures ───────────────────────────────────────────────────────

VM_BIOS_STRINGS = [
    "virtualbox", "vbox", "oracle vm",
    "vmware", "vmw",
    "qemu", "kvm", "bochs",
    "hyper-v", "microsoft corporation virtual",
    "xen", "xenproject",
    "parallels", "prl",
    "bhyve",
    "innotek",  # VirtualBox original vendor
]

VM_MAC_PREFIXES = [
    "08:00:27",   # VirtualBox
    "0a:00:27",   # VirtualBox (alt)
    "00:0c:29",   # VMware
    "00:50:56",   # VMware
    "00:05:69",   # VMware
    "00:1c:14",   # VMware
    "00:15:5d",   # Hyper-V
    "52:54:00",   # QEMU/KVM
    "00:16:3e",   # Xen
    "00:1a:4a",   # Parallels
    "00:0f:4b",   # Virtual Iron
]

VM_PROCESSES = [
    "vboxservice", "vboxtray", "vboxclient",       # VirtualBox
    "vmtoolsd", "vmwaretray", "vmwareuser",         # VMware
    "vmcompute", "vmms",                            # Hyper-V
    "prl_tools", "prl_cc",                          # Parallels
    "xenservice",                                   # Xen
    "qemu-ga",                                      # QEMU guest agent
]

VM_REGISTRY_KEYS = [
    r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions",
    r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools",
    r"HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
    r"HKLM\HARDWARE\DESCRIPTION\System\BIOS\SystemProductName",
]

CONTAINER_INDICATORS = [
    "/.dockerenv",
    "/run/.containerenv",
    "/proc/1/cgroup",  # Check for docker/lxc cgroup
]


# ── Detection Methods ─────────────────────────────────────────────────────────

class VMDetector:
    """Detects virtual machines and containers with multiple heuristic methods."""

    def __init__(self, allow_vm: bool = False):
        """
        Args:
            allow_vm: If True, log warnings but don't block. If False, raise on VM detection.
        """
        self.allow_vm = allow_vm
        self.detections: List[Dict] = []

    @staticmethod
    def _is_wsl2() -> bool:
        """Concern F: Detect WSL2 to avoid false positives.
        WSL2 always shows hypervisor flag + 'microsoft corporation' in DMI,
        which would trigger ≥2 signals and incorrectly block legitimate deployments.
        """
        try:
            if os.path.exists("/proc/version"):
                with open("/proc/version", "r") as f:
                    version = f.read().lower()
                return "microsoft" in version or "wsl" in version
        except Exception:
            pass
        return False

    def check_all(self) -> dict:
        """
        Run all VM detection checks.

        Returns:
            dict with:
                - is_virtual: bool
                - confidence: float (0.0 to 1.0)
                - detections: list of triggered checks
                - details: diagnostic info
        """
        self.detections = []
        system = platform.system()

        # Run platform-appropriate checks
        self._check_mac_address()

        if system == "Windows":
            self._check_windows_bios()
            self._check_windows_registry()
            self._check_windows_wmi()
            self._check_windows_processes()
        if system == "Linux":
            is_wsl = self._is_wsl2()
            if is_wsl:
                logger.info("WSL2 detected — skipping DMI and CPUID checks (would false-positive)")
            self._check_linux_dmi(skip_on_wsl=is_wsl)
            self._check_linux_cpuid(skip_on_wsl=is_wsl)
            self._check_linux_container()
            self._check_linux_processes()
        elif system == "Darwin":
            self._check_macos_model()
            self._check_macos_processes()

        # Calculate confidence
        num_checks = max(len(self.detections), 1)
        positive_checks = sum(1 for d in self.detections if d["detected"])
        confidence = round(positive_checks / max(num_checks, 3), 2)  # Normalize against min 3 checks

        is_virtual = positive_checks >= 2  # Need at least 2 signals

        result = {
            "is_virtual": is_virtual,
            "confidence": min(confidence, 1.0),
            "positive_signals": positive_checks,
            "total_checks": len(self.detections),
            "platform": system,
            "detections": self.detections,
        }

        if is_virtual:
            logger.warning(
                f"VM DETECTED — {positive_checks} signals triggered "
                f"(confidence: {confidence}): "
                f"{[d['method'] for d in self.detections if d['detected']]}"
            )
        else:
            logger.info(f"VM check passed — no virtualization detected ({len(self.detections)} checks)")

        return result

    # ── MAC Address Check (all platforms) ─────────────────────────────────

    def _check_mac_address(self):
        """Check if MAC address belongs to a known VM vendor."""
        try:
            mac_int = uuid.getnode()
            mac_str = ':'.join(f'{(mac_int >> (8 * (5 - i))) & 0xff:02x}' for i in range(6))
            mac_prefix = mac_str[:8].lower()

            detected = any(mac_prefix == prefix.lower() for prefix in VM_MAC_PREFIXES)
            self.detections.append({
                "method": "mac_address_oui",
                "detected": detected,
                "detail": f"MAC: {mac_str}, prefix: {mac_prefix}",
            })
        except Exception as e:
            logger.debug(f"MAC check failed: {e}")

    # ── Windows Checks ────────────────────────────────────────────────────

    def _check_windows_bios(self):
        """Check BIOS strings via WMIC."""
        try:
            for query in [
                "wmic bios get serialnumber,version /value",
                "wmic computersystem get model,manufacturer /value",
                "wmic baseboard get product,manufacturer /value",
            ]:
                out = subprocess.check_output(
                    query, shell=True, timeout=5, stderr=subprocess.DEVNULL
                )
                text = out.decode(errors="ignore").lower()
                for sig in VM_BIOS_STRINGS:
                    if sig in text:
                        self.detections.append({
                            "method": "windows_bios_string",
                            "detected": True,
                            "detail": f"Found '{sig}' in BIOS/system info",
                        })
                        return
            self.detections.append({
                "method": "windows_bios_string",
                "detected": False,
                "detail": "No VM signatures in BIOS strings",
            })
        except Exception as e:
            logger.debug(f"Windows BIOS check failed: {e}")

    def _check_windows_registry(self):
        """Check for VM-specific registry keys."""
        try:
            import winreg
            for key_path in VM_REGISTRY_KEYS:
                hive_str, subkey = key_path.split("\\", 1)
                hive = getattr(winreg, hive_str, winreg.HKEY_LOCAL_MACHINE)
                try:
                    key = winreg.OpenKey(hive, subkey)
                    winreg.CloseKey(key)
                    self.detections.append({
                        "method": "windows_registry",
                        "detected": True,
                        "detail": f"VM registry key found: {key_path}",
                    })
                    return
                except FileNotFoundError:
                    continue
            self.detections.append({
                "method": "windows_registry",
                "detected": False,
                "detail": "No VM registry keys found",
            })
        except ImportError:
            pass  # Not on Windows
        except Exception as e:
            logger.debug(f"Registry check failed: {e}")

    def _check_windows_wmi(self):
        """Check WMI for VM model/manufacturer."""
        try:
            out = subprocess.check_output(
                "wmic computersystem get model /value",
                shell=True, timeout=5, stderr=subprocess.DEVNULL
            )
            model = out.decode(errors="ignore").lower()
            vm_models = ["virtual", "vmware", "vbox", "kvm", "qemu", "hyper-v", "xen"]
            detected = any(vm in model for vm in vm_models)
            self.detections.append({
                "method": "windows_wmi_model",
                "detected": detected,
                "detail": f"System model: {model.strip()[:60]}",
            })
        except Exception as e:
            logger.debug(f"WMI model check failed: {e}")

    def _check_windows_processes(self):
        """Check for VM guest agent processes."""
        try:
            out = subprocess.check_output(
                "tasklist /FO CSV /NH",
                shell=True, timeout=5, stderr=subprocess.DEVNULL
            )
            procs = out.decode(errors="ignore").lower()
            for proc in VM_PROCESSES:
                if proc in procs:
                    self.detections.append({
                        "method": "windows_vm_process",
                        "detected": True,
                        "detail": f"VM process running: {proc}",
                    })
                    return
            self.detections.append({
                "method": "windows_vm_process",
                "detected": False,
                "detail": "No VM guest processes detected",
            })
        except Exception as e:
            logger.debug(f"Process check failed: {e}")

    # ── Linux Checks ──────────────────────────────────────────────────────

    def _check_linux_dmi(self, skip_on_wsl: bool = False):
        """Check DMI/SMBIOS strings for VM signatures."""
        if skip_on_wsl:
            self.detections.append({
                "method": "linux_dmi_string",
                "detected": False,
                "detail": "Skipped (WSL2 — would false-positive on 'microsoft corporation')",
            })
            return
        try:
            texts = []
            for path in [
                "/sys/class/dmi/id/sys_vendor",
                "/sys/class/dmi/id/product_name",
                "/sys/class/dmi/id/board_vendor",
                "/sys/class/dmi/id/bios_vendor",
            ]:
                if os.path.exists(path):
                    try:
                        with open(path, "r") as f:
                            texts.append(f.read().strip().lower())
                    except PermissionError:
                        pass

            combined = " ".join(texts)
            for sig in VM_BIOS_STRINGS:
                if sig in combined:
                    self.detections.append({
                        "method": "linux_dmi_string",
                        "detected": True,
                        "detail": f"Found '{sig}' in DMI data: {combined[:80]}",
                    })
                    return
            self.detections.append({
                "method": "linux_dmi_string",
                "detected": False,
                "detail": f"DMI: {combined[:60]}",
            })
        except Exception as e:
            logger.debug(f"Linux DMI check failed: {e}")

    def _check_linux_cpuid(self, skip_on_wsl: bool = False):
        """Check for hypervisor flag in /proc/cpuinfo."""
        if skip_on_wsl:
            self.detections.append({
                "method": "linux_cpuid_hypervisor",
                "detected": False,
                "detail": "Skipped (WSL2 — hypervisor flag always present)",
            })
            return
        try:
            if os.path.exists("/proc/cpuinfo"):
                with open("/proc/cpuinfo", "r") as f:
                    cpuinfo = f.read().lower()
                detected = "hypervisor" in cpuinfo
                self.detections.append({
                    "method": "linux_cpuid_hypervisor",
                    "detected": detected,
                    "detail": "Hypervisor flag " + ("present" if detected else "absent"),
                })
        except Exception as e:
            logger.debug(f"CPUID check failed: {e}")

    def _check_linux_container(self):
        """Detect Docker, LXC, and other containers."""
        try:
            # Check for container marker files
            for marker in ["/.dockerenv", "/run/.containerenv"]:
                if os.path.exists(marker):
                    self.detections.append({
                        "method": "linux_container",
                        "detected": True,
                        "detail": f"Container marker found: {marker}",
                    })
                    return

            # Check cgroup for docker/lxc
            if os.path.exists("/proc/1/cgroup"):
                with open("/proc/1/cgroup", "r") as f:
                    cgroup = f.read().lower()
                if "docker" in cgroup or "lxc" in cgroup or "kubepods" in cgroup:
                    self.detections.append({
                        "method": "linux_container",
                        "detected": True,
                        "detail": "Container detected via cgroup",
                    })
                    return

            self.detections.append({
                "method": "linux_container",
                "detected": False,
                "detail": "No container markers found",
            })
        except Exception as e:
            logger.debug(f"Container check failed: {e}")

    def _check_linux_processes(self):
        """Check for VM guest agent processes."""
        try:
            out = subprocess.check_output(
                "ps aux 2>/dev/null || ps -ef 2>/dev/null",
                shell=True, timeout=5, stderr=subprocess.DEVNULL
            )
            procs = out.decode(errors="ignore").lower()
            for proc in VM_PROCESSES:
                if proc in procs:
                    self.detections.append({
                        "method": "linux_vm_process",
                        "detected": True,
                        "detail": f"VM process running: {proc}",
                    })
                    return
            self.detections.append({
                "method": "linux_vm_process",
                "detected": False,
                "detail": "No VM guest processes detected",
            })
        except Exception as e:
            logger.debug(f"Linux process check failed: {e}")

    # ── macOS Checks ──────────────────────────────────────────────────────

    def _check_macos_model(self):
        """Check system model identifier for VM signatures."""
        try:
            out = subprocess.check_output(
                "system_profiler SPHardwareDataType 2>/dev/null",
                shell=True, timeout=5, stderr=subprocess.DEVNULL
            )
            text = out.decode(errors="ignore").lower()
            for sig in VM_BIOS_STRINGS:
                if sig in text:
                    self.detections.append({
                        "method": "macos_model",
                        "detected": True,
                        "detail": f"Found '{sig}' in hardware profile",
                    })
                    return
            self.detections.append({
                "method": "macos_model",
                "detected": False,
                "detail": "Physical Mac hardware detected",
            })
        except Exception as e:
            logger.debug(f"macOS model check failed: {e}")

    def _check_macos_processes(self):
        """Check for VM guest agent processes on macOS."""
        try:
            out = subprocess.check_output(
                "ps aux", shell=True, timeout=5, stderr=subprocess.DEVNULL
            )
            procs = out.decode(errors="ignore").lower()
            for proc in VM_PROCESSES:
                if proc in procs:
                    self.detections.append({
                        "method": "macos_vm_process",
                        "detected": True,
                        "detail": f"VM process running: {proc}",
                    })
                    return
            self.detections.append({
                "method": "macos_vm_process",
                "detected": False,
                "detail": "No VM guest processes detected",
            })
        except Exception as e:
            logger.debug(f"macOS process check failed: {e}")


# ── Custom Exception ──────────────────────────────────────────────────────────

class VirtualMachineDetectedError(Exception):
    """Raised when a virtual machine is detected and VM usage is not allowed."""
    pass


# ── Convenience Function ──────────────────────────────────────────────────────

def enforce_physical_machine(allow_vm: bool = False) -> dict:
    """
    Run VM detection and optionally block execution.

    Args:
        allow_vm: If True, just warn. If False, raise VirtualMachineDetectedError.

    Returns:
        Detection result dict.

    Raises:
        VirtualMachineDetectedError if VM detected and allow_vm is False.
    """
    detector = VMDetector(allow_vm=allow_vm)
    result = detector.check_all()

    if result["is_virtual"] and not allow_vm:
        raise VirtualMachineDetectedError(
            f"This application cannot run in a virtual machine. "
            f"VM detected with {result['confidence']*100:.0f}% confidence "
            f"({result['positive_signals']} signals). "
            f"Please run on physical hardware."
        )

    return result


if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.DEBUG)
    result = enforce_physical_machine(allow_vm=True)  # Don't block, just report
    print(f"\n  VM Detection Report")
    print(f"  {'=' * 40}")
    print(f"  Is Virtual : {result['is_virtual']}")
    print(f"  Confidence : {result['confidence']*100:.0f}%")
    print(f"  Signals    : {result['positive_signals']}/{result['total_checks']}")
    print(f"  Platform   : {result['platform']}")
    print(f"\n  Details:")
    for d in result["detections"]:
        icon = "!!" if d["detected"] else "OK"
        print(f"    [{icon}] {d['method']}: {d['detail'][:70]}")
    print()
