
import pytest

from backend.services import static_analysis_service as service


def test_select_source_distribution():
    data = {
        "urls": [
            {
                "filename": "example-1.0-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/example.whl",
                "digests": {"sha256": "a" * 64},
                "size": 1000,
            },
            {
                "filename": "example-1.0.tar.gz",
                "url": "https://files.pythonhosted.org/example.tar.gz",
                "digests": {"sha256": "b" * 64},
                "size": 2000,
            },
        ]
    }

    result = service.select_artifact(data)

    assert result is not None
    assert result["artifact_type"] == "sdist_tar_gz"
    assert result["filename"] == "example-1.0.tar.gz"


def test_select_wheel_when_no_sdist():
    data = {
        "urls": [
            {
                "filename": "example-1.0-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/example.whl",
                "digests": {"sha256": "a" * 64},
                "size": 1000,
            }
        ]
    }

    result = service.select_artifact(data)

    assert result["artifact_type"] == "wheel"


def test_no_supported_artifact():
    data = {
        "urls": [
            {
                "filename": "example-1.0.zip",
                "url": "https://files.pythonhosted.org/example.zip",
                "digests": {"sha256": "a" * 64},
                "size": 1000,
            }
        ]
    }

    assert service.select_artifact(data) is None


def test_missing_urls():
    assert service.select_artifact({}) is None


def test_missing_checksum():
    data = {
        "urls": [
            {
                "filename": "example-1.0.tar.gz",
                "url": "https://files.pythonhosted.org/example.tar.gz",
                "digests": {},
                "size": 1000,
            }
        ]
    }

    assert service.select_artifact(data) is None


def test_failed_download(monkeypatch):
    monkeypatch.setattr(
        service,
        "download_verified",
        lambda artifact, destination: (
            "checksum_mismatch",
            "SHA-256 verification failed",
        ),
    )

    artifact = {
        "filename": "example-1.0.tar.gz",
        "artifact_type": "sdist_tar_gz",
        "download_url": "https://files.pythonhosted.org/example.tar.gz",
        "sha256": "a" * 64,
        "size_bytes": 1000,
    }

    result = service.scan_selected_artifact(artifact)

    assert result["scan_status"] == "checksum_mismatch"
    assert result["features"] is None


def test_successful_scan(monkeypatch):
    monkeypatch.setattr(
        service,
        "download_verified",
        lambda artifact, destination: ("verified", None),
    )

    monkeypatch.setattr(
        service,
        "scan_archive",
        lambda destination: {
            "scan_status": "complete",
            "processed_python_files": 2,
            "features": {
                "network_call_count": 1,
            },
        },
    )

    artifact = {
        "filename": "example-1.0.tar.gz",
        "artifact_type": "sdist_tar_gz",
        "download_url": "https://files.pythonhosted.org/example.tar.gz",
        "sha256": "a" * 64,
        "size_bytes": 1000,
    }

    result = service.scan_selected_artifact(artifact)

    assert result["scan_status"] == "complete"
    assert result["processed_python_files"] == 2
    assert result["features"]["network_call_count"] == 1


def test_malformed_digest_object():
    data = {
        "urls": [
            {
                "filename": "example-1.0.tar.gz",
                "url": "https://files.pythonhosted.org/example.tar.gz",
                "digests": None,
                "size": 1000,
            }
        ]
    }

    # Malformed metadata must not crash artifact selection.
    assert service.select_artifact(data) is None


def test_invalid_urls_type():
    data = {"urls": "not-a-list"}

    assert service.select_artifact(data) is None
