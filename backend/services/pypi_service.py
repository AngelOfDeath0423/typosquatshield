
import re
from datetime import datetime, timezone

import httpx
from fastapi import HTTPException
from packaging.utils import canonicalize_name


def normalize_package_name(package_name):
    name = canonicalize_name(package_name.strip())

    if not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
        name,
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid PyPI package name.",
        )

    return name


def parse_upload_time(value):
    if not value or not isinstance(value, str):
        return None

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except (TypeError, ValueError, OverflowError):
        return None


def invalid_pypi_response():
    raise HTTPException(
        status_code=502,
        detail="Invalid response structure from PyPI.",
    )


def extract_release_history(releases):
    if not isinstance(releases, dict):
        invalid_pypi_response()

    records = []

    for version, files in releases.items():
        if not isinstance(version, str):
            invalid_pypi_response()

        if not isinstance(files, list):
            invalid_pypi_response()

        timestamps = []

        for file_info in files:
            if not isinstance(file_info, dict):
                invalid_pypi_response()

            uploaded = parse_upload_time(
                file_info.get("upload_time_iso_8601")
                or file_info.get("upload_time")
            )

            if uploaded is not None:
                timestamps.append(uploaded)

        if timestamps:
            records.append({
                "version": version,
                "first_upload_time": min(
                    timestamps
                ).isoformat(),
            })

    records.sort(
        key=lambda item: (
            item["first_upload_time"],
            item["version"],
        )
    )

    return records


async def fetch_pypi_metadata(package_name: str):
    name = normalize_package_name(package_name)

    url = f"https://pypi.org/pypi/{name}/json"

    try:
        async with httpx.AsyncClient(
            timeout=15.0,
            follow_redirects=False,
        ) as client:
            response = await client.get(url)

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=503,
            detail="PyPI is temporarily unavailable.",
        ) from exc

    if response.status_code == 404:
        raise HTTPException(
            status_code=404,
            detail=f"Package '{name}' not found on PyPI.",
        )

    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve PyPI metadata.",
        )

    try:
        data = response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=502,
            detail="Invalid response from PyPI.",
        ) from exc

    # Validate the top-level JSON response.
    if not isinstance(data, dict):
        invalid_pypi_response()

    info = data.get("info")
    releases = data.get("releases")

    if not isinstance(info, dict):
        invalid_pypi_response()

    if not isinstance(releases, dict):
        invalid_pypi_response()

    # Validate required package information.
    version = info.get("version")
    package_display_name = info.get("name") or name

    if not isinstance(version, str) or not version.strip():
        invalid_pypi_response()

    if not isinstance(package_display_name, str):
        invalid_pypi_response()

    # Validate optional metadata.
    summary = info.get("summary") or ""
    requires_python = info.get("requires_python")
    license_value = info.get("license")
    project_urls = info.get("project_urls") or {}

    if not isinstance(summary, str):
        invalid_pypi_response()

    if requires_python is not None and not isinstance(
        requires_python, str
    ):
        invalid_pypi_response()

    if license_value is not None and not isinstance(
        license_value, (str, dict)
    ):
        invalid_pypi_response()

    if not isinstance(project_urls, dict):
        invalid_pypi_response()

    release_history = extract_release_history(releases)

    return {
        "package_name": package_display_name,
        "version": version,
        "summary": summary,
        "requires_python": requires_python,
        "license": license_value,
        "project_urls": project_urls,
        "release_count": len(releases),
        "release_history": release_history,
        "release_history_coverage": (
            "Currently retained PyPI release files only"
        ),
        "source": "PyPI JSON API",
    }
