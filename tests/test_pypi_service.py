
import httpx
import pytest
from fastapi import HTTPException

from backend.services import pypi_service


def make_response(status_code=200, data=None):
    request = httpx.Request(
        "GET", "https://pypi.org/pypi/requests/json"
    )
    return httpx.Response(
        status_code,
        json=data,
        request=request,
    )


def mock_http(monkeypatch, response=None, error=None):
    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, url):
            if error is not None:
                raise error
            return response

    monkeypatch.setattr(
        pypi_service.httpx,
        "AsyncClient",
        FakeClient,
    )


@pytest.mark.anyio
async def test_valid_pypi_response(monkeypatch):
    mock_http(
        monkeypatch,
        make_response(
            data={
                "info": {
                    "name": "requests",
                    "version": "2.0.0",
                    "summary": "HTTP library",
                    "project_urls": {
                        "Homepage": "https://example.org"
                    },
                },
                "releases": {
                    "2.0.0": [
                        {
                            "upload_time_iso_8601":
                                "2024-01-01T10:00:00Z"
                        }
                    ]
                },
            }
        ),
    )

    result = await pypi_service.fetch_pypi_metadata(
        "requests"
    )

    assert result["package_name"] == "requests"
    assert result["version"] == "2.0.0"
    assert result["release_count"] == 1
    assert len(result["release_history"]) == 1


@pytest.mark.anyio
async def test_package_not_found(monkeypatch):
    mock_http(
        monkeypatch,
        make_response(status_code=404, data={}),
    )

    with pytest.raises(HTTPException) as exc:
        await pypi_service.fetch_pypi_metadata(
            "missing-package"
        )

    assert exc.value.status_code == 404


@pytest.mark.anyio
async def test_connection_timeout(monkeypatch):
    request = httpx.Request(
        "GET", "https://pypi.org/pypi/requests/json"
    )

    mock_http(
        monkeypatch,
        error=httpx.ConnectTimeout(
            "Connection timed out",
            request=request,
        ),
    )

    with pytest.raises(HTTPException) as exc:
        await pypi_service.fetch_pypi_metadata(
            "requests"
        )

    assert exc.value.status_code == 503


@pytest.mark.anyio
async def test_server_error(monkeypatch):
    mock_http(
        monkeypatch,
        make_response(status_code=500, data={}),
    )

    with pytest.raises(HTTPException) as exc:
        await pypi_service.fetch_pypi_metadata(
            "requests"
        )

    assert exc.value.status_code == 502


@pytest.mark.anyio
async def test_invalid_json_structure(monkeypatch):
    mock_http(
        monkeypatch,
        make_response(data=["unexpected", "list"]),
    )

    with pytest.raises(HTTPException) as exc:
        await pypi_service.fetch_pypi_metadata(
            "requests"
        )

    assert exc.value.status_code == 502


@pytest.mark.anyio
async def test_invalid_release_structure(monkeypatch):
    mock_http(
        monkeypatch,
        make_response(
            data={
                "info": {
                    "name": "requests",
                    "version": "2.0.0",
                },
                "releases": {
                    "2.0.0": "not-a-list"
                },
            }
        ),
    )

    with pytest.raises(HTTPException) as exc:
        await pypi_service.fetch_pypi_metadata(
            "requests"
        )

    assert exc.value.status_code == 502
