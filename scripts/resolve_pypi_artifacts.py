
"""
TyposquatShield - PyPI Artifact Resolver

Resolves distribution artifacts for exact PyPI package
versions using the public PyPI JSON API.

This script:
- Does not download package artifacts.
- Does not install or execute package code.
- Records wheel and source distribution metadata.
- Verifies that SHA-256 digests are advertised.
- Handles unavailable and deleted versions.
- Saves results to CSV and JSON.

Usage:
    python scripts/resolve_pypi_artifacts.py requests 2.31.0
"""

from pathlib import Path
from datetime import datetime, timezone
import argparse
import json
import re

import pandas as pd
import requests


BASE = Path(__file__).resolve().parent.parent

OUTPUT_DIR = BASE / "data" / "artifacts"
REPORT_DIR = BASE / "reports"

TIMEOUT = 15

USER_AGENT = (
    "TyposquatShield-FYP/0.1 "
    "(Academic PyPI artifact metadata research)"
)


def normalize_name(name):
    """Normalize package names using PEP 503 rules."""
    return re.sub(r"[-_.]+", "-", name).lower()


def validate_name(name):
    """Validate a PyPI distribution name."""
    return bool(
        re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?",
            name,
        )
    )


def classify_artifact(filename, packagetype):
    """Classify supported Python distribution artifacts."""

    if filename.lower().endswith(".whl"):
        return "wheel"

    if filename.lower().endswith(".tar.gz"):
        return "sdist_tar_gz"

    return "unsupported"


def resolve_artifacts(package_name, version):
    """
    Retrieve artifact metadata for one exact package version.

    Returns a dictionary containing resolution status
    and artifact metadata.
    """

    if not validate_name(package_name):
        raise ValueError(
            f"Invalid package name: {package_name}"
        )

    if not version or "/" in version or "\\" in version:
        raise ValueError(
            f"Invalid version: {version}"
        )

    normalized = normalize_name(package_name)

    url = (
        f"https://pypi.org/pypi/"
        f"{normalized}/{version}/json"
    )

    result = {
        "requested_package": package_name,
        "normalized_name": normalized,
        "requested_version": version,
        "resolution_status": "unknown",
        "artifact_count": 0,
        "artifacts": [],
        "error": None,
        "resolved_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    try:
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT,
            allow_redirects=False,
        )

        if response.status_code == 404:
            result["resolution_status"] = "not_found"
            result["error"] = (
                "Package version not available through "
                "the current PyPI JSON API."
            )
            return result

        if response.status_code != 200:
            result["resolution_status"] = "http_error"
            result["error"] = (
                f"HTTP {response.status_code}"
            )
            return result

        data = response.json()

        artifacts = []

        for item in data.get("urls", []):

            filename = item.get("filename", "")
            packagetype = item.get("packagetype", "")

            artifact_type = classify_artifact(
                filename,
                packagetype,
            )

            if artifact_type == "unsupported":
                continue

            digests = item.get("digests") or {}

            artifacts.append({
                "filename": filename,
                "artifact_type": artifact_type,
                "packagetype": packagetype,
                "download_url": item.get("url"),
                "size_bytes": item.get("size"),
                "sha256": digests.get("sha256"),
                "upload_time_iso_8601": item.get(
                    "upload_time_iso_8601"
                ),
                "yanked": item.get("yanked", False),
                "yanked_reason": item.get("yanked_reason"),
                "has_sha256": bool(
                    digests.get("sha256")
                ),
            })

        result["artifacts"] = artifacts
        result["artifact_count"] = len(artifacts)

        if artifacts:
            result["resolution_status"] = "resolved"
        else:
            result["resolution_status"] = "no_supported_artifacts"

    except requests.Timeout:
        result["resolution_status"] = "timeout"
        result["error"] = "PyPI API request timed out."

    except requests.RequestException as exc:
        result["resolution_status"] = "network_error"
        result["error"] = str(exc)

    except ValueError as exc:
        result["resolution_status"] = "invalid_response"
        result["error"] = str(exc)

    return result


def save_results(result):
    """Save resolver results to JSON and CSV."""

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    package = result["normalized_name"]

    version = result["requested_version"]

    safe_version = re.sub(
        r"[^A-Za-z0-9._-]",
        "_",
        version,
    )

    prefix = f"{package}-{safe_version}"

    json_path = OUTPUT_DIR / f"{prefix}.json"

    csv_path = OUTPUT_DIR / f"{prefix}.csv"

    json_path.write_text(
        json.dumps(result, indent=2),
        encoding="utf-8",
    )

    rows = []

    for artifact in result["artifacts"]:
        rows.append({
            "normalized_name": package,
            "version": version,
            "resolution_status": result[
                "resolution_status"
            ],
            **artifact,
        })

    if rows:
        df = pd.DataFrame(rows)
    else:
        df = pd.DataFrame([{
            "normalized_name": package,
            "version": version,
            "resolution_status": result[
                "resolution_status"
            ],
            "filename": None,
            "artifact_type": None,
            "download_url": None,
            "sha256": None,
        }])

    df.to_csv(
        csv_path,
        index=False,
    )

    return json_path, csv_path


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Resolve exact PyPI package version artifacts."
        )
    )

    parser.add_argument(
        "package",
        help="PyPI package name",
    )

    parser.add_argument(
        "version",
        help="Exact package version",
    )

    args = parser.parse_args()

    print("=" * 65)
    print("TYPOSQUATSHIELD - PYPI ARTIFACT RESOLVER")
    print("=" * 65)

    result = resolve_artifacts(
        args.package,
        args.version,
    )

    print()
    print(json.dumps(result, indent=2))

    json_path, csv_path = save_results(result)

    print()
    print("Saved JSON:", json_path)
    print("Saved CSV:", csv_path)

    if result["resolution_status"] == "resolved":
        print("[SUCCESS] Artifact metadata resolved.")
    else:
        print(
            "[INFO] Resolution status:",
            result["resolution_status"],
        )


if __name__ == "__main__":
    main()
