# -- License notices: also built alone in CI to verify the Docker context --
FROM scratch AS license-notices
COPY THIRD_PARTY_NOTICES.md /THIRD_PARTY_NOTICES.md
COPY third_party_licenses/ /third_party_licenses/

# -- Stage 1: builder ------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libzbar0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock .
RUN pip install --no-cache-dir --only-binary=:all: --require-hashes --prefix=/install -r requirements.lock

# -- Stage 2: runtime ------------------------------------------------
FROM python:3.11-slim AS runtime

# System deps only - no build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzbar0 \
    libatomic1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd --system safescan && useradd --system --gid safescan --no-create-home safescan

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Keep the reviewed notice bundle in the deployed artifact. The same stage is
# exported and compared against source in CI, including nested Markdown files.
COPY --from=license-notices /THIRD_PARTY_NOTICES.md ./THIRD_PARTY_NOTICES.md
COPY --from=license-notices /third_party_licenses/ ./third_party_licenses/

# Copy only application code
COPY distribute.py scrop.py db.py storage.py ml_model_final.py \
     safescan_allowlist.py ./
COPY hackabull/ ./hackabull/
COPY safescan_model_calibration/ ./safescan_model_calibration/
COPY templates/ ./templates/
COPY static/ ./static/
COPY models/ ./models/
COPY removals/ ./removals/
# Tranco top-10K CSV ships with the code so the allowlist short-circuit is
# hermetic - no external fetch at boot, no failure mode if Tranco is down.
COPY data/ ./data/

# /app/data already exists from the COPY above; /var/data is the Render
# persistent volume mount and only appears at runtime, so we have to
# create it here before chowning. -p so re-runs / cached layers don't
# fail if the dir already exists.
RUN mkdir -p /var/data && chown -R safescan:safescan /app/data /var/data

USER safescan

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f "http://localhost:${PORT:-8000}/health/ready" || exit 1

CMD ["sh", "-c", "python -m uvicorn hackabull:qr_app --host 0.0.0.0 --port ${PORT:-8000} --workers ${WEB_CONCURRENCY:-1} --no-access-log"]
