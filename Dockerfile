# ============================================================
# UniShield — Dockerfile (API server + built-in dashboard)
# ============================================================

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Pinned runtime dependencies first, for layer caching
COPY requirements.txt .
RUN pip install -r requirements.txt

# Install UniShield itself (non-editable; dashboard HTML ships as package data)
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-deps .

# Configuration is read from ./configs relative to the working directory
COPY configs ./configs

# Run as an unprivileged user
RUN useradd --create-home --uid 10001 unishield \
    && mkdir -p logs data \
    && chown -R unishield:unishield /app/logs
USER unishield

EXPOSE 8000

# Health check against the container's own API (loopback only)
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5).status == 200 else 1)"

CMD ["uvicorn", "unishield.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
