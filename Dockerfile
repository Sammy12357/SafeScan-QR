# -- Stage 1: builder ------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libzbar0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# -- Stage 2: runtime ------------------------------------------------
FROM python:3.11-slim AS runtime

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# System deps only - no build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzbar0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd --system safescan && useradd --system --gid safescan --no-create-home safescan

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy only application code
COPY hackabull.py distribute.py scrop.py db.py storage.py ml_model_final.py \
     safescan_allowlist.py safescan_model_calibration.py ./
COPY templates/ ./templates/
COPY static/ ./static/
COPY models/ ./models/
COPY removals/ ./removals/
# Tranco top-10K CSV ships with the code so the allowlist short-circuit is
# hermetic - no external fetch at boot, no failure mode if Tranco is down.
COPY data/ ./data/

RUN python -m playwright install --with-deps chromium

# /app/data already exists from the COPY above; /var/data is the Render
# persistent volume mount and only appears at runtime, so we have to
# create it here before chowning. -p so re-runs / cached layers don't
# fail if the dir already exists.
RUN mkdir -p /var/data && chown -R safescan:safescan /app/data /var/data /ms-playwright

USER safescan

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f "http://localhost:${PORT:-8000}/health/ready" || exit 1

CMD ["sh", "-c", "python -m uvicorn hackabull:qr_app --host 0.0.0.0 --port ${PORT:-8000} --workers ${WEB_CONCURRENCY:-1}"]
