
"""
Tests for persistent assessment history and
pytest database isolation.
"""

import sqlite3

from backend.services.assessment_history_service import (
    get_database_path,
    save_assessment,
    list_assessments,
    get_assessment,
)


def sample_assessment(package, risk="Caution"):
    return {
        "package": package,
        "version": "1.0.0",
        "assessment_context": "pypi",
        "assessment_status": "test_assessment",
        "risk_level": risk,
        "advisory_reasons": [
            "Test assessment explanation."
        ],
        "static_analysis": {
            "scan_status": "not_scanned",
        },
    }


def test_database_uses_temporary_path(tmp_path):
    database_path = get_database_path()

    assert database_path.parent == tmp_path
    assert database_path.name == "typosquatshield_test.db"


def test_save_assessment():
    record_id = save_assessment(
        sample_assessment("example-package")
    )

    assert isinstance(record_id, int)
    assert record_id > 0
    assert get_database_path().is_file()


def test_list_assessments():
    save_assessment(
        sample_assessment("requests", "Low Risk")
    )
    save_assessment(
        sample_assessment("requestss", "High Risk")
    )

    records = list_assessments()

    assert len(records) == 2
    assert records[0]["package_name"] == "requestss"
    assert records[0]["risk_level"] == "High Risk"
    assert records[1]["package_name"] == "requests"


def test_get_complete_assessment():
    original = sample_assessment(
        "example-package",
        "Caution",
    )

    record_id = save_assessment(original)

    record = get_assessment(record_id)

    assert record is not None
    assert record["id"] == record_id
    assert record["package_name"] == "example-package"
    assert record["result"] == original


def test_unknown_assessment_returns_none():
    assert get_assessment(999999) is None


def test_list_assessments_pagination():
    for index in range(5):
        save_assessment(
            sample_assessment(f"package-{index}")
        )

    records = list_assessments(
        limit=2,
        offset=1,
    )

    assert len(records) == 2
    assert records[0]["package_name"] == "package-3"
    assert records[1]["package_name"] == "package-2"


def test_database_schema():
    save_assessment(
        sample_assessment("schema-test")
    )

    with sqlite3.connect(
        str(get_database_path())
    ) as connection:
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(assessment_history)"
            )
        }

    expected_columns = {
        "id",
        "created_at",
        "package_name",
        "package_version",
        "assessment_context",
        "assessment_status",
        "risk_level",
        "static_scan_status",
        "result_json",
    }

    assert expected_columns.issubset(columns)
