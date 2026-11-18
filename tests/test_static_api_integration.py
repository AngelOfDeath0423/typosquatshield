
from fastapi.testclient import TestClient

from backend import main


client = TestClient(main.app)


def mock_assessment_dependencies(monkeypatch):
    monkeypatch.setattr(
        main,
        "load_reference_names",
        lambda: ["requests"],
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

    async def fake_pypi(name):
        return {
            "package_name": "requests",
            "version": "2.0.0",
            "summary": "Example HTTP library",
            "project_urls": {
                "Homepage": "https://example.org"
            },
        }

    monkeypatch.setattr(
        main,
        "fetch_pypi_metadata",
        fake_pypi,
    )

    monkeypatch.setattr(
        main,
        "assess_with_ml",
        lambda metadata, typo_result=None: {
            "assessment_status":
                "exact_reference_match_ml_not_applicable",
            "ml_prediction": None,
            "reputation": {
                "prior_release_count": 10,
            },
        },
    )


def test_optional_static_analysis(monkeypatch):
    mock_assessment_dependencies(monkeypatch)

    calls = []

    async def fake_static(name, version):
        calls.append((name, version))

        return {
            "scan_status": "complete",
            "artifact_filename": "requests-2.0.0.tar.gz",
            "processed_python_files": 2,
            "features": {
                "network_call_count": 1,
            },
        }

    monkeypatch.setattr(
        main,
        "assess_static_package",
        fake_static,
    )

    response = client.post(
        "/assess",
        json={"package_name": "requests"},
    )

    assert response.status_code == 200
    assert (
        response.json()["static_analysis"]["scan_status"]
        == "not_scanned"
    )
    assert calls == []

    response = client.post(
        "/assess",
        json={
            "package_name": "requests",
            "include_static_analysis": True,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert calls == [("requests", "2.0.0")]
    assert data["static_analysis"]["scan_status"] == "complete"
    assert data["static_analysis"]["features"]["network_call_count"] == 1
    assert data["risk_level"] == "Low Risk"


def test_static_scanner_failure_is_nonfatal(monkeypatch):
    mock_assessment_dependencies(monkeypatch)

    async def failing_scanner(name, version):
        raise RuntimeError("Scanner failed")

    monkeypatch.setattr(
        main,
        "assess_static_package",
        failing_scanner,
    )

    response = client.post(
        "/assess",
        json={
            "package_name": "requests",
            "include_static_analysis": True,
        },
    )

    assert response.status_code == 200
    assert (
        response.json()["static_analysis"]["scan_status"]
        == "failed"
    )
    assert response.json()["risk_level"] == "Low Risk"
