#!/usr/bin/env python3
"""
Docker Entrypoint -- License Auto-Activation + App Start
==========================================================
This script runs as the Docker container's ENTRYPOINT.

1. Checks bind mounts (/host/machine-id, /host/dmi)
2. Detects host HWID
3. Activates license on first run (or verifies existing activation)
4. Starts the FastAPI application via uvicorn

Usage in Dockerfile:
    ENTRYPOINT ["python", "licence/docker_entrypoint.py"]
"""

import os
import sys
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("docker_entrypoint")

# Ensure the licence directory is in the path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR) if os.path.basename(SCRIPT_DIR) == "licence" else SCRIPT_DIR
sys.path.insert(0, SCRIPT_DIR)
if SCRIPT_DIR != PROJECT_ROOT:
    sys.path.insert(0, PROJECT_ROOT)


def main():
    logger.info("=" * 60)
    logger.info("  DOCKER LICENSE ACTIVATION")
    logger.info("=" * 60)

    # ── Step 1: Check bind mounts ─────────────────────────────────
    logger.info("  Step 1: Checking host bind mounts...")
    try:
        from licensing.docker_hwid import check_bind_mounts, is_wsl2
        status = check_bind_mounts()
        if status["wsl2"]:
            logger.info("  Detected WSL2 (Docker Desktop). Using LICENSE_HWID env var.")
        elif status["machine_id"]:
            logger.info("  Host /etc/machine-id: mounted")
        if status.get("vm_machine_id"):
            logger.info("  Docker Desktop VM machine-id: available (fallback)")
        if status["dmi"]:
            logger.info("  Host /sys/class/dmi/id: mounted")
        if status["env_hwid"]:
            logger.info("  LICENSE_HWID env var: set")
    except Exception as e:
        logger.error(str(e))
        sys.exit(1)

    # ── Step 1.5: Validate PHONE_HOME_URL (v3.2 mandatory) ──────
    # Fix #14 NOTE: We only check URL *presence* here, not connectivity.
    # Rationale: at entrypoint time, the container's DNS / networking may
    # not be fully ready (depends on Docker Compose startup ordering).
    # Actual connectivity is verified in license_middleware.py Layer 8
    # via PhoneHomeBeacon.verify_or_fail() — which retries with backoff.
    logger.info("  Step 1.5: Validating PHONE_HOME_URL (required)...")
    phone_home_url = os.environ.get("PHONE_HOME_URL", "").strip()
    if not phone_home_url:
        logger.error("=" * 60)
        logger.error("  PHONE_HOME_URL is REQUIRED for Docker deployments (v3.2)")
        logger.error("")
        logger.error("  Without phone-home, the same license.key can be shared")
        logger.error("  across multiple machines undetected.")
        logger.error("")
        logger.error("  Set PHONE_HOME_URL in your docker-compose.yml:")
        logger.error("    environment:")
        logger.error("      - PHONE_HOME_URL=https://your-server.com/api/license/beacon")
        logger.error("=" * 60)
        sys.exit(1)
    else:
        logger.info(f"  PHONE_HOME_URL: {phone_home_url[:50]}...")

    # ── Step 2: Detect host HWID ──────────────────────────────────
    logger.info("  Step 2: Detecting host HWID...")
    try:
        from licensing.docker_hwid import generate_docker_hwid
        hwid = generate_docker_hwid()
        logger.info(f"  Host HWID: {hwid[:16]}...{hwid[-8:]}")
    except Exception as e:
        logger.error(f"  HWID detection failed: {e}")
        sys.exit(1)

    # ── Step 3: Activate / Verify ─────────────────────────────────
    logger.info("  Step 3: License activation...")
    try:
        from licensing.auto_activator import AutoActivator

        # Resolve paths relative to the licence directory
        licence_dir = SCRIPT_DIR
        activator = AutoActivator(
            license_dir=os.path.join(licence_dir, "License"),
            data_dir=os.path.join(licence_dir, "data"),
            public_key_path=os.path.join(licence_dir, "keys", "public_key.pem"),
        )

        activation = activator.activate_if_needed(hwid)

        if activation:
            logger.info(f"  Activation OK: JTI={activation['jti'][:8]}..., "
                        f"tier={activation.get('tier', '?')}, "
                        f"count={activation.get('activation_count', 1)}")
        else:
            logger.error("  Activation returned None unexpectedly")
            sys.exit(1)

    except Exception as e:
        logger.error(f"  Activation FAILED: {e}")
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("  Activation complete. Starting application...")
    logger.info("=" * 60)

    # ── Step 4: Start the app ─────────────────────────────────────
    app_module = os.environ.get("APP_MODULE", "app:app")
    app_host = os.environ.get("APP_HOST", "0.0.0.0")
    app_port = os.environ.get("APP_PORT", "8080")

    os.execvp(
        sys.executable,
        [
            sys.executable, "-m", "uvicorn",
            app_module,
            "--host", app_host,
            "--port", app_port,
        ],
    )


if __name__ == "__main__":
    main()
