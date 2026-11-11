
from pathlib import Path
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import json
import time

import pandas as pd

from typosquatting_similarity import (
    load_reference_names,
    normalize_name,
)

BASE = Path(__file__).resolve().parent.parent

OUTPUT = BASE / "data/reference/historical_reference_evidence.csv"
REPORT = BASE / "reports/historical_reference_collection_report.txt"

API = "https://pypi.org/pypi/{}/json"
EXPECTED_REFERENCES = 100
TIMEOUT = 20
RETRIES = 3


def fetch_package_metadata(name):
    url = API.format(name)

    for attempt in range(RETRIES):
        try:
            request = Request(
                url,
                headers={
                    "User-Agent": (
                        "TyposquatShield-FYP/"
                        "historical-reference-research"
                    ),
                    "Accept": "application/json",
                },
            )

            with urlopen(
                request,
                timeout=TIMEOUT,
            ) as response:
                return (
                    json.load(response),
                    "success",
                    "",
                )

        except HTTPError as exc:
            if exc.code == 404:
                return None, "not_found", "HTTP 404"

            if exc.code not in (429, 500, 502, 503, 504):
                return (
                    None,
                    "http_error",
                    f"HTTP {exc.code}",
                )

            error = f"HTTP {exc.code}"

        except (
            URLError,
            TimeoutError,
            OSError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            error = str(exc)

        if attempt < RETRIES - 1:
            time.sleep(2 ** attempt)

    return None, "request_failed", error


def extract_earliest_distribution(data):
    releases = data.get("releases", {})

    timestamps = []
    distribution_count = 0
    versions_with_files = 0

    for version, files in releases.items():
        if not isinstance(files, list) or not files:
            continue

        versions_with_files += 1

        for file_info in files:
            distribution_count += 1

            upload_time = (
                file_info.get("upload_time_iso_8601")
                or file_info.get("upload_time")
            )

            if not upload_time:
                continue

            parsed = pd.to_datetime(
                upload_time,
                utc=True,
                errors="coerce",
            )

            if pd.notna(parsed):
                timestamps.append((parsed, version))

    if not timestamps:
        return None, None, distribution_count, versions_with_files

    earliest_time, earliest_version = min(
        timestamps,
        key=lambda item: item[0],
    )

    return (
        earliest_time.isoformat(),
        earliest_version,
        distribution_count,
        versions_with_files,
    )


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - HISTORICAL REFERENCE COLLECTION")
    print("=" * 65)

    references = sorted({
        normalize_name(name)
        for name in load_reference_names()
    })

    if len(references) != EXPECTED_REFERENCES:
        raise ValueError(
            f"Expected {EXPECTED_REFERENCES} unique references, "
            f"found {len(references)}"
        )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    records = []

    for index, name in enumerate(references, start=1):
        data, status, error = fetch_package_metadata(name)

        record = {
            "reference_package": name,
            "collection_status": status,
            "earliest_observed_upload_time": None,
            "earliest_observed_version": None,
            "distribution_file_count": 0,
            "versions_with_files": 0,
            "metadata_project_name": None,
            "collection_time_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "error": error,
        }

        if data is not None:
            info = data.get("info") or {}

            record["metadata_project_name"] = info.get("name")

            (
                earliest_time,
                earliest_version,
                distribution_count,
                versions_with_files,
            ) = extract_earliest_distribution(data)

            record["earliest_observed_upload_time"] = earliest_time
            record["earliest_observed_version"] = earliest_version
            record["distribution_file_count"] = distribution_count
            record["versions_with_files"] = versions_with_files

            if earliest_time is None:
                record["collection_status"] = "no_dated_files"

        records.append(record)

        print(
            f"[{index:03d}/{len(references)}] "
            f"{name:30s} "
            f"{record['collection_status']:16s} "
            f"{record['earliest_observed_upload_time'] or 'UNKNOWN'}"
        )

        # Small delay to avoid unnecessary request bursts.
        time.sleep(0.2)

    df = pd.DataFrame(records)

    if len(df) != EXPECTED_REFERENCES:
        raise ValueError("Reference collection count mismatch.")

    if df["reference_package"].duplicated().any():
        raise ValueError("Duplicate reference package names.")

    df.to_csv(OUTPUT, index=False)

    dated = int(
        df["earliest_observed_upload_time"].notna().sum()
    )

    status_counts = (
        df["collection_status"]
        .value_counts(dropna=False)
        .to_string()
    )

    lines = [
        "TYPOSQUATSHIELD - HISTORICAL REFERENCE COLLECTION",
        "=" * 65,
        f"Reference packages: {len(df)}",
        f"References with dated distribution evidence: {dated}",
        f"References without dated distribution evidence: "
        f"{len(df) - dated}",
        "",
        "COLLECTION STATUS",
        status_counts,
        "",
        "LIMITATIONS",
        "Data obtained from the current public PyPI JSON API.",
        "The earliest retained distribution upload timestamp",
        "is not necessarily the original package publication date.",
        "Deleted files and historical gaps may affect coverage.",
        "Current project metadata is not historical reputation.",
        "Historical popularity and trust are not established.",
        "Network failures do not prove package nonexistence.",
        "No existing ML features or labels were modified.",
        "No model training was performed.",
    ]

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print()
    print("\n".join(lines))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Reference collection completed.")


if __name__ == "__main__":
    main()
