"""Alembic migrations must produce exactly the schema the models describe."""

from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from quantumkey.server.models import Base

ROOT = Path(__file__).resolve().parents[2]


def _config() -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    return config


def _upgrade(url: str, revision: str = "head") -> None:
    import os

    previous = os.environ.get("QK_DATABASE_URL")
    os.environ["QK_DATABASE_URL"] = url
    try:
        command.upgrade(_config(), revision)
    finally:
        if previous is None:
            os.environ.pop("QK_DATABASE_URL")
        else:
            os.environ["QK_DATABASE_URL"] = previous


def test_migration_matches_models(tmp_path):
    url = "sqlite:///" + (tmp_path / "m.sqlite3").as_posix()
    _upgrade(url)
    engine = create_engine(url)
    with engine.connect() as connection:
        diff = compare_metadata(MigrationContext.configure(connection), Base.metadata)
    engine.dispose()
    assert diff == []


def test_downgrade_removes_everything(tmp_path):
    import os

    url = "sqlite:///" + (tmp_path / "m.sqlite3").as_posix()
    _upgrade(url)
    os.environ["QK_DATABASE_URL"] = url
    try:
        command.downgrade(_config(), "base")
    finally:
        os.environ.pop("QK_DATABASE_URL")
    engine = create_engine(url)
    tables = set(inspect(engine).get_table_names()) - {"alembic_version"}
    engine.dispose()
    assert tables == set()


def test_app_runs_on_a_migrated_database_without_create_all(tmp_path):
    from fastapi.testclient import TestClient

    from quantumkey.server.app import create_app

    url = "sqlite:///" + (tmp_path / "m.sqlite3").as_posix()
    _upgrade(url)
    client = TestClient(create_app(url, create_schema=False))
    invite = client.app.state.rp.issue_invite("alice")
    response = client.post("/auth/register/start", json={"username": "alice", "invite": invite})
    assert response.status_code == 200
