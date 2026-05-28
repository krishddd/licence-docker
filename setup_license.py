"""
License Setup — One-Shot Setup Script
=======================================
Run this ONCE after copying the licence folder into your project.
Generates RSA keys + a hardware-bound license in a single command.

Usage:
    python setup_license.py                              # 1-year enterprise (default)
    python setup_license.py --tier professional --months 6
    python setup_license.py --tier standard --days 30
    python setup_license.py --tier enterprise --months 12 --customer "Acme Corp"

What it does:
    1. Installs dependencies (if missing)
    2. Generates RSA-4096 key pair (keys/private_key.pem + keys/public_key.pem)
    3. Detects this machine's Hardware ID (HWID)
    4. Generates a signed license file (License/license.key)

After running, your project is ready — just add 3 lines to your FastAPI app.
"""

import os
import sys
import subprocess
import argparse

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def step(num, msg):
    print(f"\n  [{num}] {msg}")
    print(f"  {'-' * 50}")


def run(cmd, **kwargs):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, **kwargs)
    if result.returncode != 0 and result.stderr:
        print(f"      Warning: {result.stderr.strip()[:200]}")
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(
        description="One-shot license setup: generates keys + license",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python setup_license.py                                  # 1-year enterprise
  python setup_license.py --tier standard --days 30        # 30-day trial
  python setup_license.py --tier professional --months 6   # 6-month professional
  python setup_license.py --customer "Acme Corp" --months 12
        """,
    )
    parser.add_argument("--tier", choices=["standard", "professional", "enterprise"],
                        default="enterprise", help="License tier (default: enterprise)")
    parser.add_argument("--days", type=int, default=None, help="License duration in days")
    parser.add_argument("--months", type=int, default=None, help="License duration in months")
    parser.add_argument("--customer", default="default-customer", help="Customer name")
    parser.add_argument("--hwid", default=None, help="HWID (auto-detected if not given)")
    parser.add_argument("--skip-deps", action="store_true", help="Skip dependency installation")
    args = parser.parse_args()

    # Calculate days
    if args.months:
        days = args.months * 30
    elif args.days:
        days = args.days
    else:
        days = 365  # Default: 1 year

    print("\n" + "=" * 56)
    print("  LICENSE SETUP")
    print("=" * 56)
    print(f"  Tier     : {args.tier}")
    print(f"  Duration : {days} days (~{round(days/30.44, 1)} months)")
    print(f"  Customer : {args.customer}")

    # ── Step 1: Install dependencies ──────────────────────────────────
    if not args.skip_deps:
        step(1, "Installing dependencies...")
        run(f"{sys.executable} -m pip install -r {os.path.join(PROJECT_ROOT, 'requirements.txt')} --quiet --user")
        print("      Done.")
    else:
        step(1, "Skipping dependency installation (--skip-deps)")

    # ── Step 2: Generate RSA key pair ─────────────────────────────────
    step(2, "Generating RSA-4096 key pair...")
    keys_dir = os.path.join(PROJECT_ROOT, "keys")
    private_key_path = os.path.join(keys_dir, "private_key.pem")
    public_key_path = os.path.join(keys_dir, "public_key.pem")

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        print("      Keys already exist — skipping (delete keys/ to regenerate)")
    else:
        # Generate key pair inline (no dependency on tools/)
        os.makedirs(keys_dir, exist_ok=True)
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(public_key_path, "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
        print(f"      Private key: {private_key_path}")
        print(f"      Public key : {public_key_path}")

    # ── Step 3: Detect HWID ───────────────────────────────────────────
    step(3, "Detecting hardware ID...")
    sys.path.insert(0, PROJECT_ROOT)
    from licensing.hwid_generator import generate_hwid
    hwid = args.hwid or generate_hwid()
    print(f"      HWID: {hwid[:16]}...{hwid[-8:]}")

    # ── Step 4: Generate license ──────────────────────────────────────
    step(4, "Generating signed license file...")
    tools_dir = os.path.join(PROJECT_ROOT, "tools")
    gen_cmd = (
        f'{sys.executable} "{os.path.join(tools_dir, "generate_license.py")}" '
        f'--hwid {hwid} --tier {args.tier} --days {days} '
        f'--customer "{args.customer}" --private-key "{private_key_path}"'
    )
    run(gen_cmd, cwd=PROJECT_ROOT)

    # ── Done ──────────────────────────────────────────────────────────
    print("\n" + "=" * 56)
    print("  SETUP COMPLETE!")
    print("=" * 56)
    print(f"""
  Your license is ready. Now add these lines to your FastAPI app:

  +-----------------------------------------------------+
  |  from licensing.license_middleware import (          |
  |      startup_license_check, PipelineGate,           |
  |      check_pipeline_access                          |
  |  )                                                  |
  |                                                     |
  |  # In your startup/lifespan:                        |
  |  startup_license_check()                            |
  |                                                     |
  |  # On any protected endpoint:                       |
  |  @app.post("/run")                                  |
  |  async def run(gate=Depends(PipelineGate())):       |
  |      check_pipeline_access("your_pipeline")         |
  +-----------------------------------------------------+

  Files created:
    keys/private_key.pem   (KEEP SECRET -- never ship to clients)
    keys/public_key.pem    (ship with your app)
    License/license.key    (ship with your app)
""")


if __name__ == "__main__":
    main()
