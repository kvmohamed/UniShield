"""
UniShield — Logging Configuration

Sets up structured logging from YAML config with console + file output.
"""

from __future__ import annotations

import logging
import logging.config
import os
from pathlib import Path

import yaml


def setup_logging(
    config_path: Path | None = None,
    log_level: str | None = None,
) -> None:
    """
    Configure logging for UniShield.

    Args:
        config_path: Path to logging.yaml. Defaults to configs/logging.yaml.
        log_level: Override log level (e.g. "DEBUG", "INFO").
    """
    if config_path is None:
        project_root = Path(__file__).resolve().parent.parent.parent
        config_path = project_root / "configs" / "logging.yaml"

    # Ensure log directory exists
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            log_config = yaml.safe_load(f)

        # Apply override if provided
        if log_level:
            for logger_cfg in log_config.get("loggers", {}).values():
                logger_cfg["level"] = log_level

        logging.config.dictConfig(log_config)
    else:
        # Fallback to basic config
        level = getattr(logging, (log_level or "INFO").upper(), logging.INFO)
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )

    logger = logging.getLogger("unishield")
    logger.info("UniShield logging initialised (level=%s)", logger.level)


def get_logger(name: str) -> logging.Logger:
    """Get a logger under the unishield namespace."""
    return logging.getLogger(f"unishield.{name}")
