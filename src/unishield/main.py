"""
UniShield — Application Entry Point

Starts the Uvicorn server with the FastAPI application.
"""

from __future__ import annotations

import uvicorn

from unishield.config import load_config
from unishield.logging_config import setup_logging


def main() -> None:
    """Start the UniShield API server."""
    config = load_config()
    setup_logging()

    uvicorn.run(
        "unishield.api.app:app",
        host=config.api.host,
        port=config.api.port,
        workers=config.api.workers,
        reload=config.debug,
        log_level="info",
    )


if __name__ == "__main__":
    main()
