"""
UniShield — Application Entry Point

Starts the Uvicorn server with the FastAPI application.
Logging is configured by the application's startup hook, so it also
applies when the app is launched directly with ``uvicorn``.
"""

from __future__ import annotations

import uvicorn

from unishield.config import load_config


def main() -> None:
    """Start the UniShield API server."""
    config = load_config()

    uvicorn.run(
        "unishield.api.app:app",
        host=config.api.host,
        port=config.api.port,
        workers=config.api.workers,
        reload=config.api.reload,
        log_level=config.log_level.lower(),
    )


if __name__ == "__main__":
    main()
