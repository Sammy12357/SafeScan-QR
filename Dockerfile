# Use a lightweight Python image
FROM python:3.11-slim

# Install runtime libraries
RUN apt-get update && apt-get install -y libzbar0 curl && rm -rf /var/lib/apt/lists/*

# Set up the folder
WORKDIR /app
COPY . .

# Install your Python libraries
RUN pip install --no-cache-dir -r requirements.txt

RUN addgroup --system safescan && adduser --system --ingroup safescan safescan
USER safescan

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Start the server
CMD uvicorn hackabull:qr_app --host 0.0.0.0 --port ${PORT:-8000}
