<![CDATA[# 🔐 licence-docker

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Kubernetes](https://img.shields.io/badge/k8s-compatible-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-3.2-blue.svg)]()

> **Hardware-bound, RSA-signed software licensing service designed to run
> hardened inside Docker.** Chains RSA signatures, hardens with HMAC, binds
> to hardware IDs, detects WSL2 / VMs, enforces strict NTP, and refreshes
> atomically.

`licence-docker` is the licensing SDK that gates your Python pipelines /
agents. It supports bare-metal deployment **and** Docker / Kubernetes with
zero-touch activation. Designed after a 14-bug hardening pass (v3.2), it
treats every layer — signature, HMAC, HWID, NTP, VM detection — as
independent and fail-closed.

---

## 📑 Table of Contents

- [Threat Model](#-threat-model)
- [Architecture](#-architecture)
- [Activation Flow](#-activation-flow)
- [Runtime Check Flow](#-runtime-check-flow-every-container-start)
- [Atomic Refresh](#-atomic-refresh)
- [NTP Enforcement inside Docker](#-ntp-enforcement-inside-docker)
- [Tooling](#-tooling)
- [Quickstart](#-quickstart)
- [Project Structure](#-project-structure)
- [Configuration](#%EF%B8%8F-configuration)
- [Security: What Blocks Abuse](#-security-what-blocks-abuse)
- [Changelog](#-v32-changelog-14-hardening-fixes)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🛡️ Threat Model

Cracking a licensing system usually means defeating **one** of these:
signature, hardware binding, time check, or container isolation. This
service is designed so an attacker has to defeat **all of them at once**:

| Layer | Defence | Detail |
|:-----:|---------|--------|
| 1 | **RSA Signature** | All license artefacts are RSA-4096 signed by a private key held only on the licensing server. Public-key copies are embedded in the client and obfuscated. |
| 2 | **HMAC Layer** | Every refresh request carries an HMAC over the request body keyed on a rolling secret tied to the license ID. Replay attempts without the rolling secret fail. |
| 3 | **Hardware ID** | Licenses are bound to a HWID derived from stable hardware identifiers. The HWID phones home on every refresh so the server can spot duplicates. |
| 4 | **NTP Time Check** | Inside Docker, the entrypoint enforces strict NTP and refuses to start if the container clock drifts beyond a threshold — defeating "set clock back to bypass expiry" attacks. |
| 5 | **VM / WSL2 Detection** | The activator detects WSL2 and common hypervisor signatures so customers cannot move a license to a throw-away VM. |
| 6 | **Atomic Refresh** | Refresh writes happen via a temp-file + rename so a crash mid-refresh cannot leave a half-written license file. |
| 7 | **Tamper Protection** | `tools/obfuscate.py` shrouds the runtime checks; integrity hashes of the binary are validated before any privileged operation. |

---

## 🏗️ Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                          VENDOR (Server)                          │
│                                                                   │
│  generate_keypair.py ──► RSA-4096 Key Pair                       │
│  generate_license.py ──► Signed JWT License (HWID + tier + exp)  │
│  obfuscate.py ─────────► Tamper-proofed runtime checks            │
│                                                                   │
│  ┌─────────────────┐    ┌──────────────────┐                     │
│  │ private_key.pem │    │  public_key.pem  │                     │
│  │   (NEVER ship)  │    │ (embedded in app)│                     │
│  └─────────────────┘    └──────────────────┘                     │
└───────────────────────────────────────────────────────────────────┘
                              │
                    license.jwt + Docker image
                              │
                              ▼
┌───────────────────────────────────────────────────────────────────┐
│                        CLIENT (Container)                         │
│                                                                   │
│  docker_entrypoint.py                                             │
│  ├── NTP enforcement    (refuse if clock drift > threshold)       │
│  ├── VM/WSL2 detection  (refuse if unauthorized env)              │
│  ├── HWID derivation    (SHA-256 of machine-id + DMI)             │
│  ├── Auto-activation    (bind HWID on first run)                  │
│  ├── RSA verification   (validate signature chain)                │
│  ├── Integrity check    (SHA-256 hash of runtime modules)         │
│  └── Phone-home beacon  (rolling-HMAC heartbeat)                  │
│                                                                   │
│  licensing/                                                       │
│  ├── license_validator   (6-layer validation stack)               │
│  ├── license_middleware   (FastAPI gate + Depends())              │
│  ├── hwid_generator      (bare-metal HWID)                       │
│  ├── docker_hwid          (container-aware HWID)                 │
│  ├── auto_activator       (zero-touch Docker activation)         │
│  ├── phone_home           (anti-fraud beacon)                    │
│  ├── heartbeat            (background re-validation)             │
│  ├── vm_detector          (hypervisor fingerprinting)            │
│  ├── integrity            (code tamper detection)                │
│  ├── concurrency          (lockfile-based use guard)             │
│  ├── revocation           (JTI-based revocation)                 │
│  ├── tier_manager         (pipeline access control)              │
│  └── audit_logger         (HMAC-chained audit trail)             │
└───────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Activation Flow

```
client (first run)
        │
        ▼
setup_license.py
        │  ├─ derive HWID
        │  ├─ open browser-less device-code flow
        │  └─ submit (HWID, activation_code) to server
        ▼
server
        │  ├─ verify activation_code
        │  ├─ generate license payload (license_id, HWID, expiry, plan)
        │  ├─ RSA-sign payload
        │  ├─ wrap signed payload + rolling HMAC seed in JWT
        │  └─ return license.jwt
        ▼
client
        │  ├─ verify RSA signature (embedded public key)
        │  ├─ store license.jwt atomically (temp + rename)
        │  ├─ store rolling HMAC seed in keyring (or .env in dev)
        │  └─ write activation marker
        ▼
ready ✅
```

## 🔍 Runtime Check Flow (every container start)

```
docker_entrypoint.py
        │
        ▼
1. NTP check         ← refuse start if clock drift > threshold
2. VM / WSL2 detect  ← refuse start if running in unauthorised env
3. Load license.jwt
4. RSA verify        ← reject if signature invalid or public key tampered
5. HWID match        ← reject if current HWID != license.hwid
6. JWT exp verify    ← reject if expired (verify_exp=False is NEVER used)
7. Integrity hash    ← reject if binary hashes mismatch
8. Phone home        ← rolling-HMAC refresh; rotate HMAC seed
9. Start the gated app ✅
```

Any failure short-circuits the boot with a clear diagnostic in
`/var/log/licence/` (or the configured log path).

---

## 🔁 Atomic Refresh

`licensing/refresh.py` writes refreshes via a temp file in the same
directory, fsyncs, then renames over the current license. If the process
is killed mid-write, the old license remains valid until next refresh —
the system never ends up with a half-written license.

```
license.jwt           ← current
license.jwt.tmp.<pid> ← in-progress write
        │
        ▼ rename (atomic on POSIX)
license.jwt           ← new
```

---

## ⏱️ NTP Enforcement inside Docker

`docker_entrypoint.py` runs an NTP probe against a configurable pool and
refuses to start if drift exceeds `LICENSE_MAX_CLOCK_DRIFT_SECONDS`
(default 30s). The Dockerfile adds `tzdata` and `ntpdate`; the compose
file mounts `/etc/localtime` read-only.

This blocks the easiest license-bypass: setting the container clock to a
date when the license was still valid.

---

## 🧰 Tooling

| Script | Purpose |
|--------|---------|
| `setup_license.py` | Bare-metal client-side activation |
| `tools/generate_keypair.py` | Server-side: generate RSA-4096 key pair |
| `tools/generate_license.py` | Server-side: produce a signed license for a (HWID, plan) |
| `tools/obfuscate.py` | Tamper-proofing pass over the runtime checks |
| `docker_entrypoint.py` | NTP-strict + integrity-checked container entrypoint |
| `docker-compose.yml` | One-command local activation + run |
| `k8s-deployment.yml` | Kubernetes manifest with strict securityContext |

---

## 🚀 Quickstart

### Prerequisites

- **Python** 3.11+
- **Docker** 20.10+ (for containerized deployment)
- **Docker Compose** v2+ (included with Docker Desktop)

### Docker (recommended)

```bash
git clone https://github.com/krishddd/licence-docker.git
cd licence-docker
cp .env.example .env          # configure your environment
docker compose up --build
```

The compose file activates the license on first start, persists the JWT in
a named volume, and refuses to re-run if the volume is wiped.

### Bare metal

```bash
git clone https://github.com/krishddd/licence-docker.git
cd licence-docker
pip install -r requirements.txt
python setup_license.py
python -m your_pipeline   # gated by license check at startup
```

### Generate a license (server-side)

```bash
python tools/generate_license.py \
       --hwid <client-hwid> \
       --plan pro \
       --expiry 2026-12-31 \
       --out licenses/<client>.jwt
```

### Kubernetes

```bash
# Create the license secret
kubectl create secret generic pipeline-license \
  --from-file=license-key=License/license.key

# Deploy
kubectl apply -f k8s-deployment.yml
```

---

## 📁 Project Structure

```
licence-docker/
├── licensing/                    # Core licensing SDK
│   ├── __init__.py               Package exports
│   ├── license_validator.py      RSA signature verification (6-layer stack)
│   ├── license_middleware.py     FastAPI startup gate + Depends()
│   ├── hwid_generator.py        Hardware ID derivation (bare-metal)
│   ├── docker_hwid.py           Docker-specific HWID (host bind mounts)
│   ├── auto_activator.py        Zero-touch Docker activation
│   ├── phone_home.py            Anti-fraud beacon with rolling HMAC
│   ├── heartbeat.py             Background license re-validation thread
│   ├── vm_detector.py           WSL2 / hypervisor detection
│   ├── integrity.py             SHA-256 runtime code integrity checker
│   ├── concurrency.py           Lockfile-based concurrent use guard
│   ├── revocation.py            JTI-based license revocation
│   ├── tier_manager.py          Tier-based pipeline access control
│   └── audit_logger.py          HMAC-chained tamper-evident audit log
├── keys/
│   ├── public_key.pem            Embedded in client; verified at runtime
│   └── private_key.pem           Server-only (NEVER commit; gitignored)
├── tools/
│   ├── generate_keypair.py       RSA-4096 key pair generator
│   ├── generate_license.py       Server-side license minter
│   └── obfuscate.py              Runtime-check tamper-proofing
├── docker_entrypoint.py          NTP-strict + integrity-checked entrypoint
├── docker-compose.yml            Local + production compose
├── Dockerfile                    Multi-stage hardened image (Cython build)
├── k8s-deployment.yml            Kubernetes manifest
├── setup_license.py              Bare-metal activation entry point
├── requirements.txt              Python dependencies
├── .env.example                  Environment variable template
├── .gitignore                    Git ignore rules
└── licensing_research_report.md  Threat model notes and bug fixes
```

---

## ⚙️ Configuration

All configuration is via environment variables. Copy `.env.example` to `.env` for local development.

| Env Var | Default | Description |
|---------|---------|-------------|
| `LICENSE_PUBLIC_KEY_PATH` | `/app/keys/public_key.pem` | Path to embedded public key |
| `LICENSE_PATH` | `./License/license.key` | Where the JWT lives (atomic-write target) |
| `LICENSE_MAX_CLOCK_DRIFT_SECONDS` | `30` | NTP drift tolerance at boot |
| `LICENSE_NTP_POOL` | `pool.ntp.org` | Comma-separated NTP server pool |
| `LICENSE_REFRESH_INTERVAL_SECONDS` | `1800` | How often to phone home (seconds) |
| `LICENSE_DENY_WSL2` | `true` (prod) | Refuse to run under WSL2 |
| `LICENSE_DENY_VM` | `true` | Refuse to run under detected hypervisors |
| `LICENSE_HMAC_KEYRING_NAME` | — | Keyring slot for rolling HMAC secret |
| `PHONE_HOME_URL` | — | **Required** for Docker deployments (v3.2) |
| `LICENSE_HWID` | — | Kubernetes only: explicit HWID (requires RSA sig) |
| `LICENSE_HWID_SIG` | — | RSA signature of `LICENSE_HWID` (vendor-signed) |
| `NTP_STRICT` | `true` | Enforce strict NTP validation |
| `SKIP_HWID_CHECK` | `false` | Skip HWID check (development only) |
| `BLOCK_VM` | `false` | Block VM environments |
| `CACHE_TTL` | `3600` | Cache time-to-live in seconds |

---

## 🔒 Security: What Blocks Abuse

| Attack Vector | Defence |
|---------------|---------|
| Copy image to 2nd machine | `activation_limit=2` → allows 1 re-provisioning, then **BLOCKED** |
| Edit `activation.json` | HMAC verification fails (includes `boot_count`) → **BLOCKED** |
| Roll clock back (air-gapped) | `boot_count` monotonic counter proves restart happened |
| Forward-date system clock | NTP check catches it on next heartbeat |
| Extract private key from image | Not in image — Dockerfile removes it automatically |
| Override entrypoint to skip check | License check is **also** in app lifespan handler |
| Run after license expires | 72h grace period → then hard block (403) |
| Modify `licensing/*.py` code | Integrity checker detects SHA-256 mismatch |

---

## 📋 v3.2 Changelog (14 hardening fixes)

- ✅ Strict NTP enforcement inside Docker
- ✅ `JWT verify_exp=False` removed everywhere
- ✅ Atomic refresh via temp-file + rename
- ✅ HWID phone-home with rolling HMAC
- ✅ WSL2 / VM detection in entrypoint
- ✅ `verify_chain` uses dict copy (no mutation of cached license)
- ✅ Auto-activator JWT verify uses `verify_exp=False` **only** in the activation-pending state, never afterwards
- ✅ Tamper protection — integrity hashes validated before privileged ops
- ✅ 8 additional fixes documented in `licensing_research_report.md`

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'feat: add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup

```bash
git clone https://github.com/krishddd/licence-docker.git
cd licence-docker
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
```

---

## 📊 Status

**v3.2** — Production-grade hardening pass complete. Personal portfolio
project; designed to gate commercial pipeline deployments.

---

## 📄 License

[MIT](https://opensource.org/licenses/MIT) — Note: the license model itself
is unrelated to this project's open-source license.

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/krishddd">krishddd</a>
</p>
]]>
