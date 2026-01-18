# Multi-stage Dockerfile for DNA Ledger Vault
# Builds production-ready container with minimal attack surface

# Stage 1: Build dependencies
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt requirements-lock.txt ./

# Install Python dependencies to /install directory
RUN pip install --no-cache-dir --prefix=/install -r requirements-lock.txt

# Stage 2: Production runtime
FROM python:3.12-slim

# Create non-root user
RUN useradd --create-home --shell /bin/bash dna_ledger && \
    mkdir -p /app /app/state /app/keys && \
    chown -R dna_ledger:dna_ledger /app

WORKDIR /app

# Copy installed dependencies from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY --chown=dna_ledger:dna_ledger . .

# Switch to non-root user
USER dna_ledger

# Expose ports
EXPOSE 8080 8081

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/api/health')" || exit 1

# Default command: Start both v1 and v2 APIs
CMD ["sh", "-c", "gunicorn -w 4 -b 0.0.0.0:8080 api.server:app & uvicorn api.v2.observability:app --host 0.0.0.0 --port 8081"]
