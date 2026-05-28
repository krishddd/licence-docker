"""
RSA-4096 Key Pair Generator
============================
Generates a private/public key pair for license signing.
  - Private key: kept on the license server (NEVER ship to clients)
  - Public key:  embedded in the client application for verification

Usage:
    python tools/generate_keypair.py
    python tools/generate_keypair.py --output-dir ./keys --key-size 4096
"""

import os
import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def generate_keypair(output_dir: str = "./keys", key_size: int = 4096):
    """Generate RSA key pair and save to PEM files."""
    os.makedirs(output_dir, exist_ok=True)

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )

    # Write private key
    private_path = os.path.join(output_dir, "private_key.pem")
    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    print(f"  [+] Private key saved: {private_path}")

    # Write public key
    public_key = private_key.public_key()
    public_path = os.path.join(output_dir, "public_key.pem")
    with open(public_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    print(f"  [+] Public key saved:  {public_path}")
    print(f"\n  Key size: {key_size} bits")
    print(f"  IMPORTANT: Keep private_key.pem SECRET. Only ship public_key.pem to clients.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate RSA key pair for license signing")
    parser.add_argument("--output-dir", default="./keys", help="Output directory for keys")
    parser.add_argument("--key-size", type=int, default=4096, help="RSA key size in bits")
    args = parser.parse_args()

    print("\n  RSA Key Pair Generator")
    print("  " + "=" * 40)
    generate_keypair(args.output_dir, args.key_size)
    print()
