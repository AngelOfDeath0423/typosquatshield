
import pytest
from fastapi.testclient import TestClient

from backend import main
from backend.services.stdlib_service import (
    get_standard_library_info,
    is_standard_library_name,
)


client = TestClient(main.app)


# --------------------------------------------------
# Standard-library detection service
# --------------------------------------------------

def test_argparse_is_standard_library():
    assert is_standard_library_name("argparse") is True


def test_json_is_standard_library():
    assert is_standard_library_name("json") is True


def test_requests_is_not_standard_library():
    assert is_standard_library_name("requests") is False


def test_standard_library_information():
    info = get_standard_library_info("argparse")

    assert info is not None
    assert info["module_name"] == "argparse"
    assert info["is_standard_library"] is True
    assert info["installation_required"] is False


def test_non_standard_library_returns_none():
    assert get_standard_library_info("requests") is None


@pytest.mark.parametrize(
    "invalid_name",
    ["", " ", None, 123],
)
def test_invalid_standard_library_names(invalid_name):
    assert is_standard_library_name(invalid_name) is False


# --------------------------------------------------
# API standard-library behaviour
# --------------------------------------------------

@pytest.mark.parametrize("name", ["argparse", "json"])
def test_auto_detects_standard_library(name, monkeypatch):
    async def unexpected_fetch(package_name):
        pytest.fail(
            "Standard-library detection must not fetch PyPI metadata."
        )

    monkeypatch.setattr(
        main, "fetch_pypi_metadata", unexpected_fetch
    )

    response = client.post(
        "/assess",
        json={
            "package_name": name,
            "assessment_context": "auto",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["package"] == name
    assert data["assessment_context"] == "stdlib"
    assert data["assessment_status"] == "standard_library"
    assert data["risk_level"] == "Not Applicable"
    assert data["ml_prediction"] is None
    assert data["metadata"] is None
    assert data["static_analysis"]["scan_status"] == "not_applicable"
    assert data["standard_library"]["installation_required"] is False


def test_explicit_stdlib_context(monkeypatch):
    async def unexpected_fetch(package_name):
        pytest.fail("PyPI should not be queried.")

    monkeypatch.setattr(
        main, "fetch_pypi_metadata", unexpected_fetch
    )

    response = client.post(
        "/assess",
        json={
            "package_name": "argparse",
            "assessment_context": "stdlib",
        },
    )

    assert response.status_code == 200
    assert response.json()["assessment_context"] == "stdlib"


def test_invalid_stdlib_context():
    response = client.post(
        "/assess",
        json={
            "package_name": "requests",
            "assessment_context": "stdlib",
        },
    )

    assert response.status_code == 400


def test_invalid_assessment_context():
    response = client.post(
        "/assess",
        json={
            "package_name": "argparse",
            "assessment_context": "invalid",
        },
    )

    assert response.status_code == 422


# --------------------------------------------------
# Explicit PyPI distribution behaviour
# --------------------------------------------------

def test_argparse_pypi_context_uses_pypi_pipeline(monkeypatch):
    calls = {"fetch": 0, "ml": 0}

    monkeypatch.setattr(
        main,
        "load_reference_names",
        lambda: ["requests", "numpy"],
    )

    monkeypatch.setattr(
        main,
        "analyze_package",
        lambda name, references: {
            "potential_typo": False,
            "exact_reference_match": False,
            "suggestions": [],
        },
    )

    async def fake_fetch(name):
        calls["fetch"] += 1

        assert name == "argparse"

        return {
            "package_name": name,
            "version": "1.4.0",
            "summary": "Python command-line parsing library",
            "project_urls": {},
        }

    def fake_ml(metadata, typo_result=None):
        calls["ml"] += 1

        return {
            "assessment_status": "experimental_ml_completed",
            "ml_prediction": None,
            "reputation": {},
        }

    monkeypatch.setattr(
        main, "fetch_pypi_metadata", fake_fetch
    )
    monkeypatch.setattr(
        main, "assess_with_ml", fake_ml
    )

    response = client.post(
        "/assess",
        json={
            "package_name": "argparse",
            "assessment_context": "pypi",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["assessment_context"] == "pypi"
    assert data["package"] == "argparse"
    assert data["version"] == "1.4.0"
    assert data["assessment_status"] == "experimental_ml_completed"
    assert data["standard_library"]["is_standard_library"] is True

    assert calls["fetch"] == 1
    assert calls["ml"] == 1


def test_requests_auto_uses_pypi_pipeline(monkeypatch):
    monkeypatch.setattr(
        main,
        "load_reference_names",
        lambda: ["requests", "numpy"],
    )

    monkeypatch.setattr(
        main,
        "analyze_package",
        lambda name, references: {
            "potential_typo": False,
            "exact_reference_match": True,
            "suggestions": [],
        },
    )

    async def fake_fetch(name):
        return {
            "package_name": name,
            "version": "2.32.3",
            "summary": "HTTP library",
            "project_urls": {},
        }

    def fake_ml(metadata, typo_result=None):
        return {
            "assessment_status":
                "exact_reference_match_ml_not_applicable",
            "ml_prediction": None,
            "reputation": {"prior_release_count": 10},
        }

    monkeypatch.setattr(
        main, "fetch_pypi_metadata", fake_fetch
    )
    monkeypatch.setattr(
        main, "assess_with_ml", fake_ml
    )

    response = client.post(
        "/assess",
        json={
            "package_name": "requests",
            "assessment_context": "auto",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["assessment_context"] == "pypi"
    assert data["assessment_status"] == (
        "exact_reference_match_ml_not_applicable"
    )
    assert data["standard_library"] is None
    assert data["package"] == "requests"
    assert data["version"] == "2.32.3"
    assert data["risk_level"] in {
        "Low Risk",
        "Caution",
        "High Risk",
    }


def test_stdlib_skips_static_analysis(monkeypatch):
    def unexpected_scan(*args, **kwargs):
        pytest.fail(
            "Static analysis must not run for a stdlib result."
        )

    monkeypatch.setattr(
        main, "assess_static_package", unexpected_scan
    )

    response = client.post(
        "/assess",
        json={
            "package_name": "argparse",
            "assessment_context": "auto",
            "include_static_analysis": True,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["assessment_context"] == "stdlib"
    assert data["static_analysis"]["scan_status"] == "not_applicable"
