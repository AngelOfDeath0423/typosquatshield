
"""
Tests for TyposquatShield database backend selection.

These tests do not require a running PostgreSQL server.
"""

import pytest

from backend.services.assessment_history_service import (
    get_database_backend,
    get_database_path,
    get_database_url,
)


def test_sqlite_is_default(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("TPS_DATABASE_PATH", raising=False)

    assert get_database_backend() == "sqlite"


def test_custom_sqlite_path(monkeypatch, tmp_path):
    path = tmp_path / "custom.db"

    monkeypatch.setenv("TPS_DATABASE_PATH", str(path))
    monkeypatch.delenv("DATABASE_URL", raising=False)

    assert get_database_backend() == "sqlite"
    assert get_database_path() == path


def test_postgresql_url_selects_postgresql(monkeypatch):
    monkeypatch.delenv("TPS_DATABASE_PATH", raising=False)
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://test:test@localhost:5432/testdb",
    )

    assert get_database_backend() == "postgresql"


def test_postgres_url_selects_postgresql(monkeypatch):
    monkeypatch.delenv("TPS_DATABASE_PATH", raising=False)
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgres://test:test@localhost:5432/testdb",
    )

    assert get_database_backend() == "postgresql"


def test_sqlite_path_overrides_postgresql(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "TPS_DATABASE_PATH",
        str(tmp_path / "test.db"),
    )
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://test:test@localhost:5432/testdb",
    )

    assert get_database_backend() == "sqlite"


def test_invalid_database_url_rejected(monkeypatch):
    monkeypatch.delenv("TPS_DATABASE_PATH", raising=False)
    monkeypatch.setenv(
        "DATABASE_URL",
        "mysql://test:test@localhost:3306/testdb",
    )

    with pytest.raises(ValueError):
        get_database_backend()


def test_database_url_read_from_environment(monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://test:test@localhost:5432/testdb",
    )

    assert get_database_url() == (
        "postgresql://test:test@localhost:5432/testdb"
    )
