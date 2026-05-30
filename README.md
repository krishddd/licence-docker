# licence-docker

> Hardware-bound, RSA-signed software licensing service designed to run
> hardened inside Docker.

`licence-docker` is a Python licensing SDK for FastAPI / agent pipelines that
supports bare-metal **and** Docker deployment with zero-touch activation. It
chains RSA signatures, hardens with HMAC, binds to hardware IDs, detects
WSL2 / VMs, and enforces strict NTP inside containers so clock-rollback
attacks fail.

## Features

- **RSA-signed license chains** — verified with an in-memory copy to avoid
  mutation.
- **HMAC hardening** on every request.
- **HWID phone-home** for hardware binding.
- **Atomic license refresh** — no race conditions on rotate.
- **JWT exp verification** kept explicit (no silent skips).
- **WSL2 / VM detection** so containers can't masquerade.
- **Tamper protection** — obfuscation, integrity checks.
- **Strict NTP** in Docker — refuses to start if container clock drifts.
- **Tools** — auto-activator, license generator, obfuscation pipeline.

## Tech stack

Python · Docker · Kubernetes · JWT · RSA + HMAC

## Quickstart

Build and run inside Docker:

```bash
git clone https://github.com/krishddd/licence-docker.git
cd licence-docker
docker compose up --build
```

Generate a license key (server-side):

```bash
python tools/generate_license.py --hwid <client-hwid> --expiry 2026-12-31
```

Bare-metal client activation:

```bash
python setup_license.py
```

## Project structure

```
licensing/           Core verification + chain logic
keys/                RSA key material (NEVER commit private_key.pem)
tools/               generate_license.py, obfuscate.py
docker_entrypoint.py NTP-strict entrypoint
docker-compose.yml   Compose definition
k8s-deployment.yml   Kubernetes manifest
setup_license.py     Bare-metal activation
```

## Status

v3.2 — incorporates 14 hardening fixes (HMAC, HWID phone-home, NTP strictness,
VM detection, atomic refresh, JWT exp checks). Personal portfolio.

## License

MIT
