
import asyncio
import tempfile
from pathlib import Path

import httpx

from scripts.batch_static_feature_extraction import (
    download_verified,
)
from scripts.static_archive_scanner import scan_archive


def unavailable_result(status, reason):
    return {
        "scan_status": status,
        "artifact_filename": None,
        "features": None,
        "processed_python_files": 0,
        "limitations": [
            reason,
            "Static indicators are not proof of maliciousness.",
        ],
    }


def select_artifact(data):
    urls = data.get("urls")

    if not isinstance(urls, list):
        return None

    candidates = []

    for item in urls:
        if not isinstance(item, dict):
            continue

        filename = item.get("filename", "")
        url = item.get("url", "")
        digests = item.get("digests")

        if not isinstance(digests, dict):
            continue

        digest = digests.get("sha256")
        size = item.get("size")

        if not isinstance(filename, str):
            continue

        if filename.endswith(".tar.gz"):
            artifact_type = "sdist_tar_gz"
            priority = 0
        elif filename.endswith(".whl"):
            artifact_type = "wheel"
            priority = 1
        else:
            continue

        if not isinstance(url, str):
            continue

        if not isinstance(digest, str):
            continue

        candidates.append((
            priority,
            filename,
            {
                "filename": filename,
                "artifact_type": artifact_type,
                "download_url": url,
                "sha256": digest,
                "size_bytes": size,
            },
        ))

    if not candidates:
        return None

    candidates.sort(key=lambda item: (item[0], item[1]))

    return candidates[0][2]


def scan_selected_artifact(artifact):
    suffix = (
        ".tar.gz"
        if artifact["artifact_type"] == "sdist_tar_gz"
        else ".whl"
    )

    with tempfile.TemporaryDirectory(
        prefix="typosquatshield_live_"
    ) as folder:
        destination = Path(folder) / ("artifact" + suffix)

        status, error = download_verified(
            artifact,
            destination,
        )

        if status != "verified":
            return unavailable_result(status, error)

        result = scan_archive(destination)

        if result["scan_status"] != "complete":
            return {
                **result,
                "artifact_filename": artifact["filename"],
                "features": None,
            }

        return {
            **result,
            "artifact_filename": artifact["filename"],
        }


async def assess_static_package(package_name, version):
    """
    Optional supplementary static analysis.

    Downloads a version-specific artifact from PyPI,
    verifies its SHA-256, and scans Python source
    without installing or executing package code.
    """

    if not package_name or not version:
        return unavailable_result(
            "not_scanned",
            "Package name or version is unavailable.",
        )

    try:
        async with httpx.AsyncClient(
            timeout=15.0,
            follow_redirects=False,
        ) as client:
            response = await client.get(
                f"https://pypi.org/pypi/"
                f"{package_name}/{version}/json"
            )

        if response.status_code != 200:
            return unavailable_result(
                "metadata_unavailable",
                "Version-specific PyPI metadata could not be retrieved.",
            )

        data = response.json()

        if not isinstance(data, dict):
            return unavailable_result(
                "invalid_metadata",
                "Invalid version-specific PyPI metadata.",
            )

        artifact = select_artifact(data)

        if artifact is None:
            return unavailable_result(
                "no_supported_artifact",
                "No supported wheel or source archive was found.",
            )

        return await asyncio.to_thread(
            scan_selected_artifact,
            artifact,
        )

    except (httpx.RequestError, ValueError, TypeError, KeyError) as exc:
        return unavailable_result(
            "scan_unavailable",
            f"Static assessment unavailable: {type(exc).__name__}",
        )
