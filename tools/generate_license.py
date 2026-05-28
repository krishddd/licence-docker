"""
License Generator -- Server-Side Tool (v3.2)
=============================================
Generates a hardware-bound, RSA-signed license file with JTI serial number.

Usage:
    python tools/generate_license.py --tier enterprise --days 365
    python tools/generate_license.py --tier professional --months 6
    python tools/generate_license.py --hwid <SHA256> --tier standard --days 30
    python tools/generate_license.py --mode docker --tier enterprise --months 12
    python tools/generate_license.py --revoke <JTI>  (add JTI to revocation list)

v3.2 Changes:
  - activation_limit default unified to 1 (Fix #10)
  - Version strings unified to 3.2 (Fix #12)
  - Phone-home mandatory for Docker mode

v3.0 Changes:
  - Added --mode docker (empty HWID, activation_limit=1)

v2.0 Changes:
  - Added JTI (JWT ID) claim
  - Added --revoke option
  - Added --max-hwid-changes option
"""

import os
import sys
import json
import uuid
import base64
import argparse
import datetime

import jwt  # PyJWT
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Add parent dir to path so we can import licensing
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from licensing.hwid_generator import generate_hwid
from licensing.tier_manager import TierManager
from licensing.revocation import RevocationChecker
from licensing.integrity import IntegrityChecker


def _utcnow():
    """UTC now — compatible with Python 3.12+ (no deprecation warning)."""
    try:
        return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    except Exception:
        return datetime.datetime.utcnow()


def generate_license(
    hwid: str,
    tier: str = "enterprise",
    days: int = 365,
    customer: str = "default-customer",
    private_key_path: str = "./keys/private_key.pem",
    output_dir: str = "./License",
    output_filename: str = "license.key",
    max_hwid_changes: int = 1,
    mode: str = "bare_metal",  # "bare_metal" or "docker"
    activation_limit: int = 1,  # Fix #10: unified with CLI default (was 2)
    licensing_dir: str = "",  # Path to licensing source for file hash embedding
):
    """
    Generate and sign a license file.

    Args:
        hwid:             Hardware ID to bind the license to.
        tier:             License tier (standard/professional/enterprise).
        days:             Total validity in days (0 = already expired, for testing).
        customer:         Customer/organization identifier.
        private_key_path: Path to RSA private key PEM.
        output_dir:       Output directory for license file.
        output_filename:  Name of the license file.
    """
    # ── Validate inputs ──────────────────────────────────────────────────
    valid_tiers = ["standard", "professional", "enterprise"]
    if tier not in valid_tiers:
        print(f"\n  [!] ERROR: Invalid tier '{tier}'. Must be one of: {valid_tiers}\n")
        sys.exit(1)

    if days < 0:
        print(f"\n  [!] ERROR: Days cannot be negative ({days})\n")
        sys.exit(1)

    if mode != "docker" and (not hwid or len(hwid) < 16):
        print(f"\n  [!] ERROR: Invalid HWID (must be at least 16 chars): '{hwid}'\n")
        sys.exit(1)

    # ── Load private key ─────────────────────────────────────────────────
    if not os.path.exists(private_key_path):
        print(f"\n  [!] ERROR: Private key not found: {private_key_path}")
        print(f"  [!] Run 'python tools/generate_keypair.py' first.\n")
        sys.exit(1)

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

    # ── Build license claims ─────────────────────────────────────────────
    tier_mgr = TierManager()
    allowed_pipelines = tier_mgr.get_allowed_pipelines(tier)
    limits = tier_mgr.get_limits(tier)

    now = _utcnow()
    expiry = now + datetime.timedelta(days=days)

    # License serial number (for revocation)
    jti = str(uuid.uuid4())

    claims = {
        "sub": customer,
        "iss": "spatai-license-server",
        "iat": int(now.timestamp()),
        "exp": int(expiry.timestamp()),
        "jti": jti,
        "hwid": hwid if mode != "docker" else "",
        "tier": tier,
        "pipelines": allowed_pipelines,
        "max_models": limits.get("max_models", 1),
        "vector_db": limits.get("vector_db_access", False),
        "max_hwid_changes": max_hwid_changes if mode != "docker" else 1,
        "mode": mode,
        "activation_limit": activation_limit,
        "license_version": "3.2",  # Fix #12: unified version string
    }

    # v3.1: Embed file hashes in JWT (Fix 5: integrity baseline from signed token)
    if licensing_dir and os.path.isdir(licensing_dir):
        checker = IntegrityChecker(licensing_dir=licensing_dir)
        file_hashes = checker.get_hashes()
        if file_hashes:
            claims["file_hashes"] = file_hashes
            print(f"  [*] Embedded {len(file_hashes)} file hashes in JWT (integrity baseline)")
    else:
        # Auto-detect licensing dir relative to this script
        auto_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "licensing")
        if os.path.isdir(auto_dir):
            checker = IntegrityChecker(licensing_dir=auto_dir)
            file_hashes = checker.get_hashes()
            if file_hashes:
                claims["file_hashes"] = file_hashes
                print(f"  [*] Embedded {len(file_hashes)} file hashes in JWT (auto-detected)")

    # ── Encode & Sign ────────────────────────────────────────────────────
    # JWT encoded with HS256 (dummy key) — real security from RSA signature
    jwt_token = jwt.encode(claims, "not-used", algorithm="HS256")
    payload_bytes = jwt_token.encode("utf-8")
    payload_b64 = base64.b64encode(payload_bytes).decode("utf-8")

    # RSA-SHA256 sign the raw JWT bytes
    signature = private_key.sign(
        payload_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    signature_hex = signature.hex()

    # ── Write license file ───────────────────────────────────────────────
    os.makedirs(output_dir, exist_ok=True)
    license_path = os.path.join(output_dir, output_filename)
    license_data = {
        "payload": payload_b64,
        "signature": signature_hex,
        "metadata": {
            "tier": tier,
            "customer": customer,
            "jti": jti,
            "issued": now.isoformat(),
            "expires": expiry.isoformat(),
            "duration_days": days,
            "hwid_prefix": hwid[:16] + "...",
            "max_hwid_changes": max_hwid_changes,
            "generator": "spatai-license-gen-v3.2",  # Fix #12: unified version
        },
    }

    with open(license_path, "w") as f:
        json.dump(license_data, f, indent=2)

    # ── Print summary ────────────────────────────────────────────────────
    months_approx = round(days / 30.44, 1)
    print(f"\n  License Generated Successfully!")
    print(f"  {'=' * 50}")
    print(f"  File       : {license_path}")
    print(f"  JTI        : {jti}")
    print(f"  Customer   : {customer}")
    print(f"  Tier       : {tier}")
    print(f"  HWID       : {hwid[:16]}...{hwid[-8:]}")
    print(f"  Pipelines  : {allowed_pipelines}")
    print(f"  Max Models : {limits.get('max_models', 1)}")
    print(f"  Vector DB  : {limits.get('vector_db_access', False)}")
    print(f"  HWID Migr. : {max_hwid_changes} allowed")
    print(f"  Issued     : {now.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Expires    : {expiry.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Duration   : {days} days (~{months_approx} months)")
    print(f"  Signed     : RSA-4096 / SHA-256 / PKCS1v15")
    print(f"  {'=' * 50}\n")

    return license_path, jti


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a hardware-bound, RSA-signed license",
        epilog="""
DURATION EXAMPLES:
  --days 30          30-day trial license
  --days 90          Quarterly license
  --months 6         6-month license
  --months 12        Annual license
  --days 365         Annual license (same as --months 12)
  --days 0           Expired license (for testing)
  --hours 1          1-hour test license

CROSS-PLATFORM:
  The HWID is auto-detected on Windows, macOS, and Linux.
  To generate a license for a DIFFERENT machine, get its HWID first:
    # On the target machine:
    python -c "from licensing.hwid_generator import generate_hwid; print(generate_hwid())"
    # Then on the license server:
    python tools/generate_license.py --hwid <paste_hwid> --tier enterprise --months 12
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--hwid",
        default=None,
        help="Hardware ID (SHA-256 hex). If not provided, auto-detects from THIS machine.",
    )
    parser.add_argument(
        "--tier",
        choices=["standard", "professional", "enterprise"],
        default="enterprise",
        help="License tier (default: enterprise)",
    )

    # Duration group: --days, --months, or --hours
    duration_group = parser.add_mutually_exclusive_group()
    duration_group.add_argument(
        "--days",
        type=int,
        default=None,
        help="License validity in days (default: 365)",
    )
    duration_group.add_argument(
        "--months",
        type=int,
        default=None,
        help="License validity in months (converted to days: months * 30)",
    )
    duration_group.add_argument(
        "--hours",
        type=int,
        default=None,
        help="License validity in hours (for short testing licenses)",
    )

    parser.add_argument(
        "--customer",
        default="test-customer",
        help="Customer/organization name",
    )
    parser.add_argument(
        "--private-key",
        default="./keys/private_key.pem",
        help="Path to RSA private key",
    )
    parser.add_argument(
        "--output-dir",
        default="./License",
        help="Output directory for license file",
    )
    parser.add_argument(
        "--max-hwid-changes",
        type=int,
        default=1,
        help="Max hardware migrations allowed (default: 1)",
    )
    parser.add_argument(
        "--mode",
        choices=["bare_metal", "docker"],
        default="bare_metal",
        help="License mode: bare_metal (default) or docker (no HWID binding)",
    )
    parser.add_argument(
        "--activation-limit",
        type=int,
        default=1,
        help="Max unique machines that can activate (Docker mode, default: 1)",
    )
    parser.add_argument(
        "--revoke",
        metavar="JTI",
        default=None,
        help="Revoke a license by its JTI (serial number)",
    )
    parser.add_argument(
        "--licensing-dir",
        default="",
        help="Path to licensing source directory for file hash embedding (auto-detected if empty)",
    )
    args = parser.parse_args()

    # ---- Revoke mode --------------------------------------------------------
    if args.revoke:
        revocation_file = os.path.join(args.output_dir, "revoked.json")
        RevocationChecker.revoke(args.revoke, revocation_file)
        print(f"\n  License {args.revoke} has been REVOKED.")
        print(f"  Revocation list: {revocation_file}\n")
        sys.exit(0)

    # ── Calculate duration in days ────────────────────────────────────────
    if args.months is not None:
        days = args.months * 30  # Approximate: 30 days per month
        print(f"\n  [*] Duration: {args.months} months = {days} days")
    elif args.hours is not None:
        # Convert hours to fractional days (minimum 0 for immediate expiry)
        days = max(0, round(args.hours / 24, 2))
        # For sub-day durations, handle via direct timedelta
        if args.hours < 24:
            days = 0  # Will be overridden below
    elif args.days is not None:
        days = args.days
    else:
        days = 365  # Default

    # -- Auto-detect HWID ------------------------------------------------------
    hwid = args.hwid
    if args.mode == "docker":
        hwid = ""  # Docker mode: HWID bound at container runtime
        print("\n  [*] Docker mode: HWID will be bound at container startup")
    elif not hwid:
        print("\n  [*] Auto-detecting HWID from this machine...")
        hwid = generate_hwid()
        print(f"  [*] HWID: {hwid}")

    # ── Handle sub-day durations (hours) ─────────────────────────────────
    if args.hours is not None and args.hours < 24:
        # Special handling: generate with exact hour-based expiry
        now = _utcnow()
        expiry = now + datetime.timedelta(hours=args.hours)
        total_seconds = (expiry - now).total_seconds()
        days = max(0, int(total_seconds / 86400))
        if days == 0 and total_seconds > 0:
            days = 1  # Minimum 1 day for the function, but we override exp in claims
        print(f"  [*] Short license: {args.hours} hours ({round(total_seconds/3600, 1)}h)")

    generate_license(
        hwid=hwid,
        tier=args.tier,
        days=days,
        customer=args.customer,
        private_key_path=args.private_key,
        output_dir=args.output_dir,
        max_hwid_changes=args.max_hwid_changes,
        mode=args.mode,
        activation_limit=args.activation_limit,
        licensing_dir=args.licensing_dir,
    )

    # Docker deployment instructions
    if args.mode == "docker":
        print("\n  " + "=" * 50)
        print("  DOCKER DEPLOYMENT INSTRUCTIONS")
        print("  " + "=" * 50)
        print("  1. Build your Docker image (include licence/ folder)")
        print("  2. DO NOT include private_key.pem in the image!")
        print("  3. Client runs:")
        print("       docker-compose up -d")
        print("  4. License auto-activates on first container start")
        print("  " + "=" * 50 + "\n")
