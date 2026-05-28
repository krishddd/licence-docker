# =============================================================================
# Dockerfile -- Pipeline with Licensing v3.2 (Security Hardened)
# =============================================================================
# IMPORTANT: Do NOT include private_key.pem in this image!
#
# Build (with Cython compilation):
#   python tools/generate_license.py --mode docker --tier enterprise --months 12
#   docker build -t pipeline:latest .
#
# Run:
#   docker-compose up -d
#
# v3.1: Multi-stage build with Cython compilation of licensing modules.
#   The licensing Python source is compiled to native .so binaries,
#   making reverse engineering significantly harder.
# =============================================================================

# ── Stage 1: Cython Build ────────────────────────────────────────────────────
FROM python:3.11-slim AS cython-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Install Cython
RUN pip install --no-cache-dir cython setuptools

# Copy licensing source for compilation
COPY licensing/ ./licensing/

# Create Cython setup script
RUN echo 'from setuptools import setup, Extension\n\
from Cython.Build import cythonize\n\
import os\n\
\n\
modules = [\n\
    "licensing/license_validator.py",\n\
    "licensing/license_middleware.py",\n\
    "licensing/hwid_generator.py",\n\
    "licensing/tier_manager.py",\n\
    "licensing/vm_detector.py",\n\
    "licensing/auto_activator.py",\n\
    "licensing/docker_hwid.py",\n\
    "licensing/heartbeat.py",\n\
    "licensing/phone_home.py",\n\
    "licensing/revocation.py",\n\
    "licensing/integrity.py",\n\
    "licensing/concurrency.py",\n\
    "licensing/audit_logger.py",\n\
]\n\
\n\
existing = [m for m in modules if os.path.exists(m)]\n\
\n\
setup(\n\
    ext_modules=cythonize(\n\
        existing,\n\
        compiler_directives={"language_level": "3"},\n\
    ),\n\
)' > setup_cython.py

# Compile to .so (fail gracefully -- fallback to .py if Cython fails)
RUN python setup_cython.py build_ext --inplace 2>/dev/null || echo "Cython compilation skipped (non-critical)"

# ── Stage 2: Production ─────────────────────────────────────────────────────
FROM python:3.11-slim AS production

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Copy compiled .so files from Cython builder (overwrite .py where .so exists)
COPY --from=cython-builder /build/licensing/*.so /app/licensing/ 2>/dev/null || true

# Remove .py source for compiled modules (keep __init__.py)
# Only remove if the .so exists (graceful fallback)
RUN for so_file in /app/licensing/*.cpython-*.so; do \
        if [ -f "$so_file" ]; then \
            base=$(echo "$so_file" | sed 's/\.cpython-[^.]*\.so/.py/'); \
            if [ -f "$base" ] && [ "$(basename $base)" != "__init__.py" ]; then \
                rm -f "$base"; \
                echo "Removed source: $base (compiled to .so)"; \
            fi; \
        fi; \
    done

# Remove private key if accidentally included (safety net)
# Covers all possible locations the key might exist
RUN rm -f keys/private_key.pem \
    && rm -f licence/keys/private_key.pem \
    && rm -f licence/private_key.pem \
    && rm -f Licence_Docker/keys/private_key.pem \
    && rm -f private_key.pem

# Ensure data directory exists for activation + NTP cache + HWID history
RUN mkdir -p data \
    && mkdir -p licence/data \
    && mkdir -p Licence_Docker/data

# Environment defaults
ENV APP_MODULE=app:app \
    APP_HOST=0.0.0.0 \
    APP_PORT=8080 \
    PHONE_HOME_URL="" \
    LICENSE_HWID=""

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Entrypoint: auto-activate license, then start app
# docker_entrypoint.py is at project root (/app/) after COPY . .
ENTRYPOINT ["python", "docker_entrypoint.py"]
