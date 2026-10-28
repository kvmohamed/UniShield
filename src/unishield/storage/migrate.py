"""
UniShield — Database Migrations

The schema is owned by the Alembic revisions in ``storage/migrations/versions``;
``storage/database.py`` describes the same tables for queries. ``upgrade``
brings a database to the latest revision. A database created before
migrations existed (``alerts``/``runs`` tables, no ``alembic_version``) is
first stamped at ``0001_initial``, which matches the oldest such schema
exactly, and then upgraded, so existing alerts are kept; revisions for
tables that later ``create_all`` versions also built (threat intel) leave
existing tables in place.

From the command line: ``unishield-admin db upgrade`` / ``db current``
(or ``alembic -c alembic.ini ...`` in a source checkout).
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Optional

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.engine import Engine

logger = logging.getLogger("unishield.storage.migrate")

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
INITIAL_REVISION = "0001_initial"
_LEGACY_TABLES = {"alerts", "runs"}


def alembic_config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    return cfg


@lru_cache(maxsize=1)
def head_revision() -> str:
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


def current_revision(engine: Engine) -> Optional[str]:
    """The revision the database is at, or None for an empty or pre-migration database."""
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def is_current(engine: Engine) -> bool:
    return current_revision(engine) == head_revision()


def upgrade(engine: Engine, revision: str = "head") -> None:
    """Apply all revisions up to ``revision`` in one transaction."""
    with engine.begin() as conn:
        cfg = alembic_config()
        cfg.attributes["connection"] = conn
        tables = set(inspect(conn).get_table_names())
        if "alembic_version" not in tables and _LEGACY_TABLES <= tables:
            logger.info("Existing database without migration history: stamping %s", INITIAL_REVISION)
            command.stamp(cfg, INITIAL_REVISION)
        command.upgrade(cfg, revision)


def downgrade(engine: Engine, revision: str) -> None:
    with engine.begin() as conn:
        cfg = alembic_config()
        cfg.attributes["connection"] = conn
        command.downgrade(cfg, revision)
