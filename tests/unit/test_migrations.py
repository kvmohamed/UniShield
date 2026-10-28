"""Schema migrations: upgrade from empty, legacy databases, schema/metadata agreement, downgrade, CLI."""

from __future__ import annotations

from datetime import datetime

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import insert, inspect, select, text

from unishield import cli
from unishield.storage import AlertRepository, migrate
from unishield.storage.database import alerts_table, make_engine, metadata


def _url(tmp_path, name="unishield.db"):
    return f"sqlite:///{(tmp_path / name).as_posix()}"


def test_upgrade_from_empty_database_reaches_head(tmp_path):
    engine = make_engine(_url(tmp_path), migrate=False)
    assert migrate.current_revision(engine) is None and not migrate.is_current(engine)
    assert inspect(engine).get_table_names() == []
    migrate.upgrade(engine)
    assert migrate.current_revision(engine) == migrate.head_revision()
    assert {"alerts", "runs", "alembic_version"} <= set(inspect(engine).get_table_names())
    migrate.upgrade(engine)                                         # idempotent
    assert migrate.is_current(engine)


def test_migrated_schema_matches_query_metadata(tmp_path):
    engine = make_engine(_url(tmp_path))
    with engine.connect() as conn:
        diffs = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), metadata)
    assert diffs == []


def _legacy(url: str, revision: str):
    """A database as metadata.create_all built it before migrations existed: the schema of ``revision``
    without an alembic_version table."""
    engine = make_engine(url, migrate=False)
    migrate.upgrade(engine, revision)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE alembic_version"))
    return engine


def test_legacy_database_is_stamped_and_keeps_its_alerts(tmp_path):
    url = _url(tmp_path)
    legacy = _legacy(url, migrate.INITIAL_REVISION)
    now = datetime(2026, 1, 1)
    with legacy.begin() as conn:
        conn.execute(insert(alerts_table).values(
            alert_id="US-LEGACY", timestamp=now, window_start=now, window_end=now, threat_class="PORT_SCAN",
            severity="HIGH", confidence=0.9, detector_name="scan_detector", model_version="v1",
            source_type="simulated"))
    legacy.dispose()

    repo = AlertRepository.from_url(url)
    assert migrate.is_current(repo.engine)
    assert repo.get("US-LEGACY").threat_class.value == "PORT_SCAN"
    assert {"intel_indicators", "intel_imports"} <= set(inspect(repo.engine).get_table_names())


def test_legacy_database_with_intel_tables_keeps_its_indicators(tmp_path):
    """Built by the version that added threat-intel imports (alerts, runs and intel tables, no history)."""
    from unishield.storage.database import intel_table

    url = _url(tmp_path)
    legacy = _legacy(url, "0002_intel_indicators")
    with legacy.begin() as conn:
        conn.execute(insert(intel_table).values(source="feed", kind="ip", value="198.51.100.7",
                                                imported_at=datetime(2026, 1, 1)))
    legacy.dispose()

    engine = make_engine(url)
    assert migrate.is_current(engine)
    with engine.connect() as conn:
        assert conn.execute(select(intel_table.c.value)).scalars().all() == ["198.51.100.7"]


def test_downgrade_to_base_and_upgrade_again(tmp_path):
    engine = make_engine(_url(tmp_path))
    migrate.downgrade(engine, "base")
    assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
    migrate.upgrade(engine)
    with engine.connect() as conn:
        assert conn.execute(select(alerts_table)).all() == []


def test_api_refuses_to_start_on_outdated_schema(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from unishield.api.app import create_app
    from unishield.config import reset_config

    monkeypatch.setenv("UNISHIELD_DB_URL", "sqlite://")
    reset_config()
    app = create_app(AlertRepository(make_engine(_url(tmp_path), migrate=False)))
    with pytest.raises(RuntimeError, match="unishield-admin db upgrade"):
        with TestClient(app):
            pass
    reset_config()


def test_cli_db_current_and_upgrade(tmp_path, capsys):
    url = _url(tmp_path)
    assert cli.main(["--db-url", url, "db", "current"]) == 1
    assert "not at the latest revision" in capsys.readouterr().err
    assert cli.main(["--db-url", url, "db", "upgrade"]) == 0
    assert f"-> {migrate.head_revision()}" in capsys.readouterr().out
    assert cli.main(["--db-url", url, "db", "current"]) == 0
