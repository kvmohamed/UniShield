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

# Run as an unprivileged user. /app/state holds the SQLite database and
# /app/exports the analyst-side export files: they are created here so the
# named volumes mounted on them inherit this ownership.
RUN useradd --create-home --uid 10001 unishield \
    && mkdir -p logs data state exports \
    && chown -R unishield:unishield /app/logs /app/state /app/exports
USER unishield

# Listen on all container interfaces; publish the port on the host's
# loopback (docker-compose.yml) or behind a TLS reverse proxy.
ENV UNISHIELD_API_HOST=0.0.0.0 \
    UNISHIELD_API_PORT=8000 \
    UNISHIELD_DB_URL=sqlite:////app/state/unishield.db

EXPOSE 8000

# /health answers 503 when storage is unavailable ("degraded" is still 200).
# With tls.certfile set inside the container, switch this to https.
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5).status == 200 else 1)"

# unishield.main applies the configuration (TLS, trusted proxies, graceful
# shutdown); SIGTERM from "docker stop" stops a running replay cleanly.
STOPSIGNAL SIGTERM
CMD ["python", "-m", "unishield.main"]
