# Licensing Research Report v2.0 — Docker Process Guide

## Overview

Two actors, two phases:

```
VENDOR (You)                              CLIENT (Customer)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━           ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Step 1: Generate RSA keys                 Step 7: Pull image from GitLab
Step 2: Generate Docker license           Step 8: Run docker-compose up
Step 3: Verify license file               Step 9: Auto-activation happens
Step 4: Build Docker image                Step 10: App starts serving
Step 5: Tag image for GitLab              Step 11: Heartbeat monitors
Step 6: Push to GitLab Registry           Step 12: License renewal (future)
```

---

## VENDOR SIDE (Your Machine)

### Step 1: Generate RSA Key Pair

```bash
cd licence
python tools/generate_keypair.py
```

**What happens internally:**
- Generates RSA-4096 private key → [keys/private_key.pem](file:///c:/Users/hp/Downloads/licence/keys/private_key.pem)
- Derives public key → [keys/public_key.pem](file:///c:/Users/hp/Downloads/licence/keys/public_key.pem)
- Private key = your secret (signs licenses)
- Public key = shipped to client (verifies licenses)

**Files created:**
```
keys/
  private_key.pem   ← KEEP SECRET (never goes in Docker image)
  public_key.pem    ← Goes into Docker image
```

> [!CAUTION]
> You only do this ONCE. Same key pair is used for ALL clients. If you already have keys, skip this step.

---

### Step 2: Generate Docker License

```bash
cd licence
python tools/generate_license.py \
  --mode docker \
  --tier enterprise \
  --months 12 \
  --customer "ClientCompanyName"
```

**What happens internally:**
1. `--mode docker` → sets `hwid=""` (empty — will bind at runtime)
2. Creates JWT with claims:
   ```json
   {
     "sub": "ClientCompanyName",
     "tier": "enterprise",
     "exp": 1774041600,
     "jti": "c87d3f2a-...",
     "hwid": "",
     "mode": "docker",
     "activation_limit": 2,
     "max_hwid_changes": 1,
     "license_version": "3.0"
   }
   ```
3. Signs JWT with RSA private key (PKCS1v15 + SHA-256)
4. Saves signed license to [License/license.key](file:///c:/Users/hp/Downloads/licence/License/license.key)

**Files created:**
```
License/
  license.key       ← Signed license (goes into Docker image)
```

**Key point:** The license has NO HWID — it's bound to the client's machine at first run.

---

### Step 3: Verify License File

```bash
cd licence
python -c "
import json
lic = json.load(open('License/license.key'))
meta = lic.get('metadata', {})
print(f'JTI:    {meta.get(\"jti\", \"n/a\")}')
print(f'Tier:   {meta.get(\"tier\", \"n/a\")}')
print(f'Mode:   {meta.get(\"mode\", \"n/a\")}')
print(f'Expiry: {meta.get(\"expires\", \"n/a\")}')
"
```

**What happens:** Reads the license metadata and prints it. Confirm `mode: docker` and correct expiry date before building.

---

### Step 4: Build Docker Image

```bash
# From your project root (where Dockerfile is)
docker build -t pipeline:latest .
```

**What happens internally:**
1. Copies all application code into the image
2. Installs Python dependencies from [requirements.txt](file:///c:/Users/hp/Downloads/licence/requirements.txt)
3. Copies `licence/licensing/` SDK, `licence/keys/public_key.pem`, `licence/License/license.key`
4. **AUTO-REMOVES** [private_key.pem](file:///c:/Users/hp/Downloads/licence/private_key.pem) (safety net in Dockerfile):
   ```dockerfile
   RUN rm -f licence/keys/private_key.pem
   ```
5. Sets `ENTRYPOINT` to [docker_entrypoint.py](file:///c:/Users/hp/Downloads/licence/docker_entrypoint.py)

**What's IN the image:**
```
✅ Application code (app.py, etc.)
✅ licensing/ SDK (all .py modules)
✅ keys/public_key.pem (public only)
✅ License/license.key (signed, no HWID)
✅ docker_entrypoint.py (auto-activation)
❌ keys/private_key.pem (REMOVED)
```

---

### Step 5: Tag Image for GitLab

```bash
# Tag for your GitLab Container Registry
docker tag pipeline:latest registry.gitlab.com/your-org/your-project/pipeline:latest
docker tag pipeline:latest registry.gitlab.com/your-org/your-project/pipeline:v3.0
```

**What happens:** Creates named references to the image. The GitLab registry URL format is:
`registry.gitlab.com/<namespace>/<project>/<image>:<tag>`

---

### Step 6: Push to GitLab Registry

```bash
# Login to GitLab registry (one-time)
docker login registry.gitlab.com -u <your-username> -p <your-access-token>

# Push both tags
docker push registry.gitlab.com/your-org/your-project/pipeline:latest
docker push registry.gitlab.com/your-org/your-project/pipeline:v3.0
```

**What happens:**
- Uploads image layers to GitLab Container Registry
- Client can now pull this image
- Image contains the license but NO private key
- Generate a GitLab Deploy Token for the client (read-only access to registry)

---

## CLIENT SIDE (Customer's Machine)

### Step 7: Pull Image from GitLab

```bash
# Client logs in with deploy token you provided
docker login registry.gitlab.com -u <deploy-token-name> -p <deploy-token>

# Pull the image
docker pull registry.gitlab.com/your-org/your-project/pipeline:latest
```

**What happens:**
- Downloads all image layers to client's machine
- Image is now stored locally
- No license activation yet — just the image on disk

---

### Step 8: Run with Docker Compose

Client creates or uses the provided [docker-compose.yml](file:///c:/Users/hp/Downloads/licence/docker-compose.yml):

```yaml
services:
  pipeline:
    image: registry.gitlab.com/your-org/your-project/pipeline:latest
    container_name: pipeline
    ports:
      - "8080:8080"
    volumes:
      - license_data:/app/licence/data
      - /etc/machine-id:/host/machine-id:ro
      - /sys/class/dmi/id:/host/dmi:ro
      - ./licence/License:/app/licence/License   # License renewal: file-drop
    restart: unless-stopped

volumes:
  license_data:
```

Then runs:
```bash
docker-compose up -d
```

**What happens:**
1. Docker creates a container from the image
2. Mounts 4 volumes:
   - `license_data` → persistent named volume for activation data
   - `/etc/machine-id` → host's unique machine ID (read-only)
   - `/sys/class/dmi/id` → host's hardware serial numbers (read-only)
   - `./licence/License` → host directory for license file-drop renewal
3. Container starts → runs [docker_entrypoint.py](file:///c:/Users/hp/Downloads/licence/docker_entrypoint.py)

---

### Step 9: Auto-Activation (First Run)

This happens **automatically** inside [docker_entrypoint.py](file:///c:/Users/hp/Downloads/licence/docker_entrypoint.py):

```
============================================================
  DOCKER LICENSE ACTIVATION
============================================================
  Step 1: Checking host bind mounts...
  Host /etc/machine-id: mounted
  Host /sys/class/dmi/id: mounted

  Step 2: Detecting host HWID...
  Host HWID: 9092a77df7b74bb8...0c33856d

  Step 3: License activation...
  Activation OK: JTI=c87d3f2a..., tier=enterprise, count=1
============================================================
  Activation complete. Starting application...
============================================================
```

**What happens internally (Step by Step):**

| Sub-Step | Action | Result |
|----------|--------|--------|
| 9a | Read `/host/machine-id` | Gets host's unique machine UUID |
| 9b | Read `/host/dmi/product_uuid` | Gets motherboard UUID |
| 9c | `SHA-256(machine-id + product_uuid)` | Produces 64-char HWID |
| 9d | Read [License/license.key](file:///c:/Users/hp/Downloads/licence/License/license.key) | Extracts JTI, tier, expiry |
| 9e | Generate 32-byte random salt | For HMAC key derivation |
| 9f | `HMAC-SHA256(hwid+jti+timestamp, key)` | Tamper-proof signature |
| 9g | Write `data/activation.json` | Persists to Docker volume |

**File created in volume:**
```json
{
  "hwid": "9092a77df7b74bb8...0c33856d",
  "jti": "c87d3f2a-...",
  "tier": "enterprise",
  "activated_at": "2026-03-18T06:30:00Z",
  "activation_count": 1,
  "boot_count": 1,
  "salt": "a1b2c3d4...",
  "hmac": "f8e7d6c5...",
  "version": "3.0"
}
```

> [!NOTE]
> `boot_count` increments every container restart (monotonic counter). Even if clock is rolled back, `boot_count` proves the system restarted — defeats clock manipulation on air-gapped machines.

---

### Step 10: Application Starts

After activation, [docker_entrypoint.py](file:///c:/Users/hp/Downloads/licence/docker_entrypoint.py) exec's into:
```bash
python -m uvicorn app:app --host 0.0.0.0 --port 8080
```

**The FastAPI lifespan handler then runs the v2.0 validation:**
```
============================================================
  LICENSE VALIDATION -- STARTUP CHECK (v3.0 Docker)
============================================================
  Layer 0: SKIPPED (Docker mode)
  Layer 1: RSA-4096 signature verified       ✅
  Layer 2: JWT decoded (tier=enterprise)     ✅
  Layer 3: Docker mode -- HWID via activation ✅
  Layer 4: License valid until 2027-03-18    ✅
  Layer 5: JTI not revoked                   ✅
  Layer 6: 12 integrity files verified       ✅
  Layer 7: No concurrent instances           ✅
  Heartbeat started: every 1800s
  STATUS: VALID -- Application authorized
============================================================
```

**App is now serving on port 8080!**

---

### Step 11: Heartbeat Monitoring (Ongoing)

Every 30 minutes (1800 seconds), the heartbeat thread:

1. Re-validates the full license (layers 1-5)
2. Refreshes the concurrency lockfile
3. Sends phone-home beacon (if `PHONE_HOME_URL` is set)

```
Heartbeat #1 OK ─── 30 min ─── Heartbeat #2 OK ─── 30 min ─── ...
```

**Failure handling (72h grace tolerance):**
- First failure → starts a grace timer, logs warning
- Subsequent failures → logs remaining grace time
- If network recovers → grace timer resets completely
- After 72h of continuous failures → license killed, all gated endpoints return 403

> [!TIP]
> The 72h heartbeat grace is crucial for industrial environments (factories, air-gapped OT networks) where network blips are common.

---

### Step 12: License Renewal (When Expires)

When the license is about to expire:

**Vendor generates new license:**
```bash
cd licence
python tools/generate_license.py --mode docker --tier enterprise --months 12
```

**Send new `license.key` to client. Client updates (file-drop — no docker cp needed):**
```bash
# Drop new license.key into the mounted host directory
cp license.key ./licence/License/license.key

# Restart to pick up new license
docker-compose restart
```

**What happens:** Container restarts → re-validates with new license → new expiry date.

> [!IMPORTANT]
> The [License/](file:///c:/Users/hp/Downloads/licence/licensing/license_validator.py#65-99) directory is bind-mounted from the host. Client just replaces the file on the host filesystem — no `docker cp` or container shell access required. Works even in restricted production environments.

---

## What Blocks Abuse

| If Client Tries To... | What Happens |
|------------------------|-------------|
| Copy image to 2nd machine | `activation_limit=2` → allows 1 re-provisioning, then BLOCKED |
| Edit activation.json | HMAC verification fails (includes boot_count) → BLOCKED |
| Roll clock back (air-gapped) | `boot_count` monotonic counter proves restart happened |
| Forward-date system clock | NTP check catches it on next heartbeat |
| Extract private key from image | Not in image (Dockerfile removes it) |
| Override entrypoint to skip check | License check is ALSO in app lifespan handler |
| Run after license expires | 72h grace period → then hard block (403) |
| Modify licensing/*.py code | Integrity checker detects SHA-256 mismatch |

---

## 5 Gaps Identified & Fixed

| # | Gap | Risk | Fix | File Changed |
|---|-----|------|-----|--------------|
| 1 | `docker cp` renewal needed container access | Restricted prod envs block this | License dir is now bind-mounted from host → file-drop renewal | [docker-compose.yml](file:///c:/Users/hp/Downloads/licence/docker-compose.yml) |
| 2 | NTP clock manipulation on air-gapped machines | Clock rollback defeats time checks | `boot_count` monotonic counter in `activation.json` — included in HMAC | [auto_activator.py](file:///c:/Users/hp/Downloads/licence/licensing/auto_activator.py) |
| 3 | `activation_limit=1` + `max_hwid_changes=0` too strict | Cloud VM rotation / hardware swap locks client out | Changed to `activation_limit=2`, `max_hwid_changes=1` — allows 1 reprovisioning | [generate_license.py](file:///c:/Users/hp/Downloads/licence/tools/generate_license.py) |
| 4 | Heartbeat kills license on 3 failures | Industrial networks (factories, air-gapped OT) have flaky connectivity | 72h heartbeat grace window — only kills after 72h continuous failures | [license_middleware.py](file:///c:/Users/hp/Downloads/licence/licensing/license_middleware.py) |
| 5 | Private key is single point of failure | If [private_key.pem](file:///c:/Users/hp/Downloads/licence/private_key.pem) leaks, all client licenses are compromised | Document best practice: store in secrets manager (AWS KMS / HashiCorp Vault) | Documentation |

> [!CAUTION]
> **Gap 5 (Private Key Security):** The private key should NEVER be stored on disk in production. Use AWS KMS, HashiCorp Vault, or Azure Key Vault. The signing operation should happen inside the secrets manager, so the raw key never touches the filesystem.

---

## Quick Reference

### Vendor Commands (You)
```bash
# One-time: generate keys
python tools/generate_keypair.py

# Per-client: generate license
python tools/generate_license.py --mode docker --tier enterprise --months 12

# Build & push
docker build -t pipeline:latest .
docker tag pipeline:latest registry.gitlab.com/your-org/project/pipeline:latest
docker push registry.gitlab.com/your-org/project/pipeline:latest
```

### Client Commands (Customer)
```bash
# Pull & run (first time)
docker login registry.gitlab.com -u <token-name> -p <token>
docker pull registry.gitlab.com/your-org/project/pipeline:latest
docker-compose up -d

# Check logs
docker logs pipeline

# Restart
docker-compose restart

# License renewal (file-drop)
cp new_license.key ./licence/License/license.key
docker-compose restart
```

