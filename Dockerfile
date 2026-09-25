# ============================================================
# UniShield — Dockerfile
# Multi-stage build for the API server
# ============================================================

FROM python:3.11-slim AS base

# Prevent Python from writing bytecode and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Install the package in development mode
RUN pip install -e .

# Create necessary directories
RUN mkdir -p logs data/raw data/processed data/samples models/saved models/metadata reports

# Expose API and dashboard ports
EXPOSE 8000 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import httpx; r = httpx.get('http://localhost:8000/health'); assert r.status_code == 200"

# Default: run the API server
CMD ["uvicorn", "unishield.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
