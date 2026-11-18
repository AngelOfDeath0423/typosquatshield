
"""
Shared pytest configuration for TyposquatShield.

Every test uses an isolated temporary SQLite database
instead of the development assessment history database.
"""

import pytest


@pytest.fixture(autouse=True)
def isolated_assessment_database(
    monkeypatch,
    tmp_path,
):
    """
    Redirect assessment history to a temporary database.

    pytest creates a separate temporary directory for
    each test, preventing test records from entering
    the development database.
    """
    database_path = (
        tmp_path / "typosquatshield_test.db"
    )

    monkeypatch.setenv(
        "TPS_DATABASE_PATH",
        str(database_path),
    )

    yield
