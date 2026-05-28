"""
Code Obfuscation & Compilation Script
=======================================
Protects the licensing code from reverse engineering using:

  1. PyArmor — bytecode obfuscation + license binding
  2. Cython — compile .py to native .pyd/.so binaries
  3. Cleanup — remove original .py files from distribution

Usage:
    python tools/obfuscate.py                  # Full pipeline
    python tools/obfuscate.py --method pyarmor # PyArmor only
    python tools/obfuscate.py --method cython  # Cython only
    python tools/obfuscate.py --method both    # Both (recommended)

Distribution:
    After running, ship the dist/ folder to clients instead of the source.
"""

import os
import sys
import shutil
import argparse
import subprocess
import platform

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST_DIR = os.path.join(PROJECT_ROOT, "dist")
LICENSING_DIR = os.path.join(PROJECT_ROOT, "licensing")

# Files to protect (all licensing core modules -- v3.1 expanded)
PROTECT_FILES = [
    "licensing/license_validator.py",
    "licensing/license_middleware.py",
    "licensing/hwid_generator.py",
    "licensing/tier_manager.py",
    "licensing/vm_detector.py",
    "licensing/auto_activator.py",
    "licensing/docker_hwid.py",
    "licensing/heartbeat.py",
    "licensing/phone_home.py",
    "licensing/revocation.py",
    "licensing/integrity.py",
    "licensing/concurrency.py",
    "licensing/audit_logger.py",
]


def run_cmd(cmd, cwd=None):
    """Run a shell command and print output."""
    print(f"  $ {cmd}")
    result = subprocess.run(
        cmd, shell=True, cwd=cwd or PROJECT_ROOT,
        capture_output=True, text=True
    )
    if result.stdout:
        for line in result.stdout.strip().split("\n"):
            print(f"    {line}")
    if result.returncode != 0:
        print(f"    [ERROR] {result.stderr.strip()}")
        return False
    return True


def check_tool(tool_name, install_cmd):
    """Check if a tool is installed."""
    try:
        subprocess.run(
            f"{tool_name} --version", shell=True,
            capture_output=True, timeout=5
        )
        return True
    except Exception:
        print(f"\n  [!] '{tool_name}' not installed.")
        print(f"  [!] Install it: {install_cmd}\n")
        return False


def obfuscate_pyarmor():
    """
    Use PyArmor to obfuscate Python files.
    PyArmor replaces bytecode with encrypted opcodes that are decrypted at runtime.
    """
    print("\n" + "=" * 60)
    print("  STEP 1: PyArmor Obfuscation")
    print("=" * 60)

    if not check_tool("pyarmor", "pip install pyarmor"):
        return False

    dist_pyarmor = os.path.join(DIST_DIR, "pyarmor_build")
    os.makedirs(dist_pyarmor, exist_ok=True)

    # Obfuscate each file
    for filepath in PROTECT_FILES:
        full_path = os.path.join(PROJECT_ROOT, filepath)
        if not os.path.exists(full_path):
            print(f"  [SKIP] {filepath} — not found")
            continue

        print(f"\n  Obfuscating: {filepath}")
        success = run_cmd(
            f'pyarmor gen --output "{dist_pyarmor}" "{full_path}"'
        )
        if success:
            print(f"  [OK] {filepath}")
        else:
            print(f"  [FAIL] {filepath}")

    # Copy non-protected files
    for item in ["app.py", "orchestrator.py", ".env", "requirements.txt"]:
        src = os.path.join(PROJECT_ROOT, item)
        if os.path.exists(src):
            shutil.copy2(src, dist_pyarmor)
    print(f"\n  PyArmor output: {dist_pyarmor}")
    return True


def compile_cython():
    """
    Use Cython to compile Python to C, then to native .pyd (Windows) / .so (Linux/Mac).
    This produces machine code that cannot be easily decompiled back to Python.
    """
    print("\n" + "=" * 60)
    print("  STEP 2: Cython Compilation")
    print("=" * 60)

    if not check_tool("cython", "pip install cython"):
        return False

    dist_cython = os.path.join(DIST_DIR, "cython_build")
    os.makedirs(dist_cython, exist_ok=True)

    # Create a setup.py for Cython compilation
    ext = ".pyd" if platform.system() == "Windows" else ".so"
    setup_content = '''
"""Auto-generated Cython build script."""
from setuptools import setup
from Cython.Build import cythonize

setup(
    ext_modules=cythonize(
        [{FILES}],
        compiler_directives={
            "language_level": "3",
            "boundscheck": False,
            "wraparound": False,
        },
    ),
)
'''.replace("{FILES}", ", ".join(f'"{f}"' for f in PROTECT_FILES))

    setup_path = os.path.join(PROJECT_ROOT, "_cython_setup.py")
    with open(setup_path, "w") as f:
        f.write(setup_content)

    try:
        print(f"\n  Building native extensions ({ext})...")
        success = run_cmd(
            f'python _cython_setup.py build_ext --inplace',
            cwd=PROJECT_ROOT
        )

        # Copy compiled files to dist
        if success:
            for filepath in PROTECT_FILES:
                base = filepath.replace(".py", ext)
                if os.path.exists(os.path.join(PROJECT_ROOT, base)):
                    shutil.copy2(
                        os.path.join(PROJECT_ROOT, base),
                        os.path.join(dist_cython, os.path.basename(base))
                    )
                    print(f"  [OK] {base}")
    finally:
        # Concern E: Always clean up temp setup file, even on build failure
        if os.path.exists(setup_path):
            os.remove(setup_path)

    print(f"\n  Cython output: {dist_cython}")
    return True


def create_distribution():
    """
    Create a clean distribution folder ready to ship.
    Removes .py source files for protected modules.
    """
    print("\n" + "=" * 60)
    print("  STEP 3: Creating Distribution Package")
    print("=" * 60)

    dist_final = os.path.join(DIST_DIR, "release")
    if os.path.exists(dist_final):
        shutil.rmtree(dist_final)

    # Copy everything except tools/ and keys/private_key.pem
    shutil.copytree(PROJECT_ROOT, dist_final, ignore=shutil.ignore_patterns(
        "tools", "dist", "__pycache__", "*.pyc", ".git",
        "private_key.pem", "_cython_setup.py", "build",
        "test_*.py",  # Don't ship test files
    ))

    # Remove source .py for protected modules (keep __init__.py)
    for filepath in PROTECT_FILES:
        src_in_dist = os.path.join(dist_final, filepath)
        if os.path.exists(src_in_dist):
            os.remove(src_in_dist)
            print(f"  [REMOVED] {filepath} (source code)")

    print(f"\n  Distribution package: {dist_final}")
    print(f"  Contents:")
    for root, dirs, files in os.walk(dist_final):
        level = root.replace(dist_final, "").count(os.sep)
        indent = "    " * (level + 1)
        print(f"{indent}{os.path.basename(root)}/")
        sub_indent = "    " * (level + 2)
        for file in files:
            print(f"{sub_indent}{file}")

    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Obfuscate and compile licensing code")
    parser.add_argument(
        "--method",
        choices=["pyarmor", "cython", "both", "dist"],
        default="both",
        help="Obfuscation method (default: both)",
    )
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  CODE PROTECTION PIPELINE")
    print("=" * 60)
    print(f"  Method  : {args.method}")
    print(f"  Platform: {platform.system()} {platform.machine()}")
    print(f"  Python  : {platform.python_version()}")

    os.makedirs(DIST_DIR, exist_ok=True)

    if args.method in ("pyarmor", "both"):
        obfuscate_pyarmor()

    if args.method in ("cython", "both"):
        compile_cython()

    if args.method == "dist":
        create_distribution()

    # Always create distribution
    if args.method in ("pyarmor", "cython", "both"):
        create_distribution()

    print("\n" + "=" * 60)
    print("  PROTECTION COMPLETE")
    print("  Ship the dist/release/ folder to customers.")
    print("  NEVER ship: private_key.pem, tools/, source .py files")
    print("=" * 60 + "\n")
