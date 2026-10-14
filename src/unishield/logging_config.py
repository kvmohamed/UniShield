"""
UniShield — Logging Configuration

Sets up structured logging from YAML config with console + file output.
Called once at API startup (see api/app.py lifespan); safe to call again.
"""

from __future__ import annotations

import logging
import logging.config
from pathlib import Path

import yaml

_configured = False


def setup_logging(
    config_path: Path | None = None,
    log_level: str | None = None,
    logs_dir: Path | str | None = None,
    force: bool = False,
) -> None:
    """
    Configure logging for UniShield.

    Args:
        config_path: Path to logging.yaml. Defaults to <configs dir>/logging.yaml.
        log_level: Override level for the ``unishield`` loggers (e.g. "DEBUG").
        logs_dir: Directory for file handlers. Defaults to ``paths.logs_dir``.
        force: Reconfigure even if logging was already set up.
    """
    global _configured
    if _configured and not force:
        return

    # Imported here to avoid a circular import at module load.
    from unishield.config import config_dir, get_config

    config = get_config()
    if config_path is None:
        config_path = config_dir() / "logging.yaml"
    log_dir = Path(logs_dir or config.paths.logs_dir)
    level = (log_level or config.log_level).upper()

    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            log_config = yaml.safe_load(f)

        # Point every file handler at the configured log directory.
        for handler in log_config.get("handlers", {}).values():
            if "filename" in handler:
                log_dir.mkdir(parents=True, exist_ok=True)
                handler["filename"] = str(log_dir / Path(handler["filename"]).name)

        for name, logger_cfg in log_config.get("loggers", {}).items():
            if name == "unishield" or name.startswith("unishield."):
                logger_cfg["level"] = level

        logging.config.dictConfig(log_config)
    else:
        logging.basicConfig(
            level=getattr(logging, level, logging.INFO),
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
        logging.getLogger("unishield").warning(
            "Logging config not found at %s; using basic console logging", config_path
        )

    _configured = True
    logging.getLogger("unishield").info(
        "UniShield logging initialised (level=%s, logs_dir=%s)", level, log_dir
    )


def get_logger(name: str) -> logging.Logger:
    """Get a logger under the unishield namespace."""
    return logging.getLogger(f"unishield.{name}")
