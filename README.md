# licence-docker

> Hardware-bound, RSA-signed software licensing service designed to run
> hardened inside Docker. Chains RSA signatures, hardens with HMAC, binds
> to hardware IDs, detects WSL2 / VMs, enforces strict NTP, and refreshes
> atomically.

`licence-docker` is the licensing SDK that gates your Python pipelines /
agents. It supports bare-metal deployment **and** Docker / Kubernetes with
zero-touch activation. Designed after a 14-bug hardening pass (v3.2), it
treats every layer — signature, HMAC, HWID, NTP, VM detection — as
independent and fail-closed.

---

## Threat model

Cracking a licensing system usually means defeating **one** of these:
signature, hardware binding, time check, or container isolation. This
service is designed so an attacker has to defeat **all of them at once**:

1. **Signature.** All license artefacts are RSA-signed by a private key
   held only on the licensing server. Public-key copies are embedded in the
   client and obfuscated.
2. **HMAC layer.** Every refresh request carries an HMAC over the request
   body keyed on a rolling secret tied to the license ID. Replay attempts
   without the rolling secret fail.
3. **Hardware ID.** Licenses are bound to a HWID derived from stable
   hardware identifiers. The HWID phones home on every refresh so the
   server can spot duplicates.
4. **Time check.** Inside Docker, the entrypoint enforces strict NTP and
   refuses to start if the container clock drifts beyond a threshold —
   defeating "set clock back to bypass expiry" attacks.
5. **VM / WSL2 detection.** The activator detects WSL2 and common
   hypervisor signatures so customers cannot move a license to a
   throw-away VM.
6. **Atomic refresh.** Refresh writes happen via a temp-file + rename so a
   crash mid-refresh cannot leave a half-written license file.
7. **Tamper protection.** `tools/obfuscate.py` shrouds the runtime checks;
   integrity hashes of the binary are validated before any privileged
   operation.

---

## Activation flow

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
ready
```

## Runtime check flow (every container start)

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
9. start the gated app
```

Any failure short-circuits the boot with a clear diagnostic in
`/var/log/licence/` (or the configured log path).

---

## Atomic refresh

`licensing/refresh.py` writes refreshes via a temp file in the same
directory, fsyncs, then renames over the current license. If the process
is killed mid-write, the old license remains valid until next refresh —
the system never ends up with a half-written license.

```
license.jwt        ← current
license.jwt.tmp.<pid>  ← in-progress write
        │
        ▼ rename (atomic on POSIX)
license.jwt        ← new
```

---

## NTP enforcement inside Docker

`docker_entrypoint.py` runs an NTP probe against a configurable pool and
refuses to start if drift exceeds `LICENSE_MAX_CLOCK_DRIFT_SECONDS`
(default 30s). The Dockerfile adds `tzdata` and `ntpdate`; the compose
file mounts `/etc/localtime` read-only.

This blocks the easiest license-bypass: setting the container clock to a
date when the license was still valid.

---

## Tooling

| Script                          | Purpose                                                    |
|---------------------------------|------------------------------------------------------------|
| `setup_license.py`              | Bare-metal client-side activation                          |
| `tools/generate_license.py`     | Server-side: produce a signed license for a (HWID, plan)   |
| `tools/obfuscate.py`            | Tamper-proofing pass over the runtime checks               |
| `docker_entrypoint.py`          | NTP-strict + integrity-checked container entrypoint        |
| `docker-compose.yml`            | One-command local activation + run                         |
| `k8s-deployment.yml`            | Kubernetes manifest with strict securityContext            |

---

## Quickstart

### Docker (recommended)

```bash
git clone https://github.com/krishddd/licence-docker.git
cd licence-docker
docker compose up --build
```

The compose file activates the license on first start, persists the JWT in
a named volume, and refuses to re-run if the volume is wiped.

### Bare metal

```bash
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

---

## Project structure

```
licensing/
├── verify.py             RSA signature verification (chain copy, no mutation)
├── refresh.py            Atomic refresh + HMAC roll
├── hwid.py               Hardware ID derivation
├── ntp.py                NTP probe + drift enforcement
├── vm_detect.py          WSL2 / hypervisor detection
└── integrity.py          Binary hash check
keys/
├── public_key.pem        Embedded in client; verified at runtime
└── private_key.pem       Server-only (NEVER commit; gitignored)
tools/
├── generate_license.py   Server-side license minter
└── obfuscate.py          Runtime-check tamper-proofing
docker_entrypoint.py      NTP-strict + integrity-checked entrypoint
docker-compose.yml        Local + production compose
Dockerfile                Hardened base image
k8s-deployment.yml        Kubernetes manifest
setup_license.py          Bare-metal activation entry point
licensing_research_report.md   Notes on the threat model and bug fixes
```

---

## Configuration

| Env var                                | Meaning                                                       |
|----------------------------------------|---------------------------------------------------------------|
| `LICENSE_PUBLIC_KEY_PATH`              | Embedded public key (default `/app/keys/public_key.pem`)      |
| `LICENSE_PATH`                         | Where the JWT lives (atomic-write target)                     |
| `LICENSE_MAX_CLOCK_DRIFT_SECONDS`      | NTP drift tolerance at boot                                   |
| `LICENSE_NTP_POOL`                     | Comma-separated NTP server pool                               |
| `LICENSE_REFRESH_INTERVAL_SECONDS`     | How often to phone home                                       |
| `LICENSE_DENY_WSL2`                    | Refuse to run under WSL2 (default `true` in prod profile)     |
| `LICENSE_DENY_VM`                      | Refuse to run under detected hypervisors (default `true`)     |
| `LICENSE_HMAC_KEYRING_NAME`            | Keyring slot for rolling HMAC secret                          |

---

## v3.2 changelog (14 hardening fixes)

- Strict NTP enforcement inside Docker.
- `JWT verify_exp=False` removed everywhere.
- Atomic refresh via temp-file + rename.
- HWID phone-home with rolling HMAC.
- WSL2 / VM detection in entrypoint.
- `verify_chain` uses dict copy (no mutation of the cached license).
- Auto-activator JWT verify uses `verify_exp=False` **only** in the
  activation-pending state, never afterwards.
- Tamper protection — integrity hashes validated before privileged ops.
- 8 additional fixes documented in `licensing_research_report.md`.

---

## Status

v3.2 — production-grade hardening pass complete. Personal portfolio
project; designed to gate commercial pipeline deployments.

## License

MIT (note: the license model itself is unrelated to project licensing)
