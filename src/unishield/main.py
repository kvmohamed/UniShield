"""
UniShield — Application Entry Point

Starts the Uvicorn server with the FastAPI application, applying the
server settings from the configuration: address, HTTPS (``tls.certfile`` /
``tls.keyfile``), which reverse proxies may set X-Forwarded-For/-Proto
(``api.forwarded_allow_ips``) and the graceful-shutdown timeout.
Logging is configured by the application's startup hook, so it also
applies when the app is launched directly with ``uvicorn``.
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Any

import uvicorn

from unishield.config import UnishieldConfig, load_config

logger = logging.getLogger("unishield.main")


class StartupError(SystemExit):
    """Configuration that cannot be served; the message is printed and the process exits with status 1."""

    def __init__(self, message: str):
        super().__init__(f"UniShield: {message}")


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def uvicorn_options(config: UnishieldConfig) -> dict[str, Any]:
    """Keyword arguments for ``uvicorn.run``; raises StartupError for unusable TLS files."""
    options: dict[str, Any] = dict(
        host=config.api.host,
        port=config.api.port,
        workers=config.api.workers,
        reload=config.api.reload,
        log_level=config.log_level.lower(),
        timeout_graceful_shutdown=config.api.shutdown_timeout_sec,
        proxy_headers=True,
        forwarded_allow_ips=config.api.forwarded_allow_ips,
    )
    tls = config.tls
    if tls.enabled:
        for name, value in (("tls.certfile", tls.certfile), ("tls.keyfile", tls.keyfile)):
            if value and not Path(value).is_file():
                raise StartupError(f"{name} {value!r} is not a readable file")
        options.update(ssl_certfile=tls.certfile, ssl_keyfile=tls.keyfile,
                       ssl_keyfile_password=tls.keyfile_password)
    elif not _is_loopback(config.api.host):
        logger.warning("Serving plain HTTP on %s: set tls.certfile/tls.keyfile or put UniShield behind a "
                       "TLS-terminating reverse proxy (docs/deployment.md)", config.api.host)
    return options


def main() -> None:
    """Start the UniShield API server."""
    config = load_config()
    uvicorn.run("unishield.api.app:app", **uvicorn_options(config))


if __name__ == "__main__":
    main()
