# Licensing SDK v3.2 — Docker + Industrial Grade

Hardware-bound, RSA-signed license system for FastAPI pipelines.
Supports bare-metal deployment AND Docker containers with zero-touch activation.

> **v3.2** — Security hardening release with 14 bug fixes. See [Changelog](#changelog) below.

## Quick Start

### Option A: Bare Metal (Manual Setup)
```bash
cd licence
python setup_license.py --tier enterprise --months 12 --customer "YourCompany"
```

### Option B: Docker (Zero-Touch)
```bash
# 1. Generate Docker license (vendor side)
cd licence
python tools/generate_license.py --mode docker --tier enterprise --months 12

# 2. Build & run (client side)
docker-compose up -d
# License auto-activates on first container start!
```

---

## FastAPI Integration
```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "licence"))
from licensing.license_middleware import startup_license_check, PipelineGate
from contextlib import asynccontextmanager
from fastapi import Depends

@asynccontextmanager
async def lifespan(app_instance):
    startup_license_check(
        license_dir="./licence/License",
        public_key_path="./licence/keys/public_key.pem",
        # For Docker: add mode="docker", data_dir="./licence/data"
    )
    yield

app = FastAPI(..., lifespan=lifespan)

@app.post("/run")
async def run(gate=Depends(PipelineGate())):
    ...
```

---

## Docker Deployment

### How It Works
1. **Vendor** generates license with `--mode docker` (no HWID, no private key in image)
2. **Client** runs `docker-compose up -d` with host bind mounts
3. **First run**: container reads host HWID from `/etc/machine-id`, creates tamper-proof `activation.json`
4. **Subsequent runs**: verifies activation HMAC + HWID match + all security layers
5. **Phone-home** (v3.2): container registers JTI+HWID with vendor server on every startup

### docker-compose.yml (Required Volumes + Environment)
```yaml
services:
  pipeline:
    image: your-pipeline:latest
    volumes:
      - license_data:/app/licence/data          # Persistent activation + NTP cache
      - /etc/machine-id:/host/machine-id:ro     # Host HWID source
      - /sys/class/dmi/id:/host/dmi:ro          # Host hardware info
      - ./licence/License:/app/licence/License   # License file (renewal via file-drop)
    environment:
      - PHONE_HOME_URL=https://your-server.com/api/license/beacon  # REQUIRED (v3.2)
```

### Docker Desktop (Windows/macOS)
Docker Desktop uses the VM's `/etc/machine-id` as HWID source — no `LICENSE_HWID` needed.
Bind mounts work the same way. If Docker Desktop is reinstalled, the license re-activates automatically.

### Kubernetes
```bash
# Create license secret
kubectl create secret generic pipeline-license --from-file=license-key=license.key
# Deploy
kubectl apply -f k8s-deployment.yml
# HWID = K8s node name (via downward API)
```

---

## Security Layers

| Layer | Feature | Bare Metal | Docker |
|-------|---------|:----------:|:------:|
| 0 | VM Detection | Yes | Skipped |
| 1 | RSA-4096 Signature | Yes | Yes |
| 2 | JWT Claims | Yes | Yes |
| 3 | HWID Binding | Direct | Via activation.json |
| 4 | NTP Time Check | Strict | Strict (v3.2) |
| 5 | Revocation (JTI) | Yes | Yes (HMAC-protected) |
| 6 | Integrity (SHA-256) | Yes | Yes (Cython-aware) |
| 7 | Concurrency Guard | Yes | Yes (atomic locks) |
| **8** | **Phone-Home** | Optional | **MANDATORY (v3.2)** |
| + | Heartbeat | Yes | Yes (monotonic timer) |
| + | Grace Period (72h) | Yes | Yes |
| + | Audit Trail | Yes | Yes (cross-month chain) |
| + | Activation Limit | N/A | 1 machine |

---

## Admin Commands

### Revoke
```bash
python -c "import json; print(json.load(open('License/license.key'))['metadata']['jti'])"
python tools/generate_license.py --revoke <JTI>
```

### License Renewal (Docker)
```bash
# Option 1: File-drop via bind mount (preferred)
cp new_license.key ./licence/License/license.key
docker-compose restart

# Option 2: docker cp
docker cp new_license.key pipeline:/app/licence/License/license.key
docker-compose restart
```

---

## Startup Configuration
```python
startup_license_check(
    license_dir="./licence/License",
    public_key_path="./licence/keys/public_key.pem",
    ntp_strict=True,
    block_vm=True,
    grace_period_hours=72.0,
    offline_grace_hours=48.0,
    heartbeat_interval=1800,
    heartbeat_max_failures=3,
    max_hwid_changes=1,
    enable_audit=True,
    enable_integrity=True,
    enable_concurrency=True,
    # Docker-specific:
    mode="docker",              # "bare_metal" (default) or "docker"
    data_dir="./licence/data",  # Activation + NTP cache + HWID history
    phone_home_url="https://...",  # REQUIRED for Docker (v3.2)
    heartbeat_grace_hours=4.0,  # Industrial network tolerance
)
```

---

## Folder Structure
```
licence/
  setup_license.py            # Bare-metal setup
  docker_entrypoint.py        # Docker entrypoint (auto-activation)
  Dockerfile                  # Production image
  docker-compose.yml          # With required volume mounts
  k8s-deployment.yml          # Kubernetes template
  requirements.txt
  .env
  licensing/                  # SDK core
    __init__.py
    hwid_generator.py         # Hardware fingerprint (Docker-aware)
    docker_hwid.py            # Docker host HWID from bind mounts
    auto_activator.py         # First-run activation + HMAC
    phone_home.py             # Optional license beacon
    license_validator.py      # 6-layer validation (Docker mode)
    license_middleware.py     # FastAPI integration + heartbeat
    tier_manager.py
    vm_detector.py
    audit_logger.py
    heartbeat.py
    revocation.py
    integrity.py
    concurrency.py
  tools/
    generate_keypair.py
    generate_license.py       # --mode docker support
    obfuscate.py
  keys/                       # RSA keys (NEVER ship private!)
  License/                    # Signed license file
  data/                       # Activation data (Docker volume)
  logs/                       # Audit logs
```

## Security Notes
- **NEVER** include `private_key.pem` in Docker images
- Docker mode: `activation_limit=1`, `max_hwid_changes=1`
- Phone-home is **mandatory** for Docker (v3.2) — blocks startup if unreachable
- Grace period restricts to standard tier only
- All state files (`.hwid_history`, `revoked.json`, `activation.json`) are HMAC-protected
- NTP cache + HWID history stored in `data_dir` (persistent Docker volume)
- Monotonic clock used for grace timers (immune to clock rollback)

---

## Changelog

### v3.2 — Security Hardening (14 Fixes)

**Breaking Changes:**
- `PHONE_HOME_URL` is now **REQUIRED** for Docker deployments
- `activation_limit` default changed from 2 → 1
- `license_version` JWT claim is now `3.2` for all modes
- `RevocationChecker` now requires `public_key_path` parameter

**Critical Fixes:**
- `last_seen_utc` included in activation HMAC (prevents clock-rollback bypass)
- Docker phone-home now sends real host HWID (was sending empty string)
- Eliminated double activation (entrypoint handles it, middleware only loads)

**High Fixes:**
- `.hwid_history` HMAC-protected and moved to `data_dir`
- Cython-compiled deploys handled gracefully (no silent integrity skip)

**Medium Fixes:**
- `revoked.json` HMAC tamper protection
- NTP cache moved to persistent `data_dir` volume
- Grace timer uses `time.monotonic()` (immune to clock rollback)
- Lock files use atomic `os.replace()` (no TOCTOU race)

**Low Fixes:**
- Cross-month audit log sentinel (HMAC chain continuity)
- Version strings unified to 3.2
- Beacon payload HMAC-signed
- Documented entrypoint connectivity verification gap

### v3.1 — Docker Hardening
- RSA-signed HWID attestation for Kubernetes
- NTP strict mode for Docker
- File hash baselines embedded in JWT
- Boot count monotonic counter

### v3.0 — Docker Support
- Zero-touch Docker activation
- Host HWID from bind mounts
- Phone-home beacon (optional)
- Concurrency guard
