
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend import main


client = TestClient(main.app)


@pytest.fixture
def mock_dependencies(monkeypatch):
    monkeypatch.setattr(
        main,
        "load_reference_names",
        lambda: ["requests", "numpy"],
    )

    monkeypatch.setattr(
        main,
        "analyze_package",
        lambda name, references: {
            "potential_typo": name == "requestss",
            "exact_reference_match": name == "requests",
            "suggestions": (
                [{"reference_package": "requests"}]
                if name == "requestss"
                else []
            ),
        },
    )


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert "api_status" in response.json()


def test_empty_package_name():
    response = client.post(
        "/assess",
        json={"package_name": "   "},
    )

    assert response.status_code == 400


def test_missing_package_with_typo(mock_dependencies, monkeypatch):
    async def fake_fetch(name):
        raise HTTPException(
            status_code=404,
            detail="Package not found",
        )

    monkeypatch.setattr(
        main, "fetch_pypi_metadata", fake_fetch
    )

    response = client.post(
        "/assess",
        json={"package_name": "requestss"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["risk_level"] == "High Risk"
    assert data["assessment_status"] == "similarity_only"
    assert data["ml_prediction"] is None


def test_missing_package_without_typo(
    mock_dependencies, monkeypatch
):
    async def fake_fetch(name):
        raise HTTPException(status_code=404)

    monkeypatch.setattr(
        main, "fetch_pypi_metadata", fake_fetch
    )

    response = client.post(
        "/assess",
        json={"package_name": "unknown-package"},
    )

    assert response.status_code == 200
    assert response.json()["risk_level"] == "Caution"


def test_available_reference_package(
    mock_dependencies, monkeypatch
):
    async def fake_fetch(name):
        return {
            "package_name": name,
            "version": "1.0.0",
            "summary": "Example package",
            "project_urls": {
                "Homepage": "https://example.org"
            },
        }

    def fake_ml(metadata, typo_result=None):
        return {
            "assessment_status":
                "exact_reference_match_ml_not_applicable",
            "ml_prediction": None,
            "reputation": {
                "prior_release_count": 10
            },
        }

    monkeypatch.setattr(
        main, "fetch_pypi_metadata", fake_fetch
    )
    monkeypatch.setattr(
        main, "assess_with_ml", fake_ml
    )

    response = client.post(
        "/assess",
        json={"package_name": "requests"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["risk_level"] == "Low Risk"
    assert data["assessment_status"] == (
        "exact_reference_match_ml_not_applicable"
    )


def test_ml_feature_failure(
    mock_dependencies, monkeypatch
):
    async def fake_fetch(name):
        return {
            "package_name": name,
            "version": "1.0.0",
        }

    def fake_ml(metadata, typo_result=None):
        raise ValueError("Feature mismatch")

    monkeypatch.setattr(
        main, "fetch_pypi_metadata", fake_fetch
    )
    monkeypatch.setattr(
        main, "assess_with_ml", fake_ml
    )

    response = client.post(
        "/assess",
        json={"package_name": "example-package"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "ML assessment is temporarily unavailable."
    )
