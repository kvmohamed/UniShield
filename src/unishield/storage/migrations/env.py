"""
Alembic environment for UniShield.

Programmatic use (``unishield.storage.migrate``) passes an open connection in
``config.attributes["connection"]``. The ``alembic`` command line (see
``alembic.ini`` in the project root) connects to ``sqlalchemy.url`` if set,
otherwise to ``database.url`` / ``UNISHIELD_DB_URL``.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from unishield.storage.database import metadata

config = context.config
target_metadata = metadata
if config.config_file_name:                       # alembic command line: logging from alembic.ini
    fileConfig(config.config_file_name, disable_existing_loggers=False)


def _url() -> str:
    url = config.get_main_option("sqlalchemy.url")
    if url:
        return url
    from unishield.config import get_config

    return get_config().database.url


def _configure(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata,
                      render_as_batch=connection.dialect.name == "sqlite")
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True,
                      dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _configure(connection)
        return
    engine = create_engine(_url(), poolclass=NullPool)
    with engine.connect() as connection:
        _configure(connection)
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
