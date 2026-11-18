
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

import argparse
import hashlib
import json
import os
import tempfile
import time

import pandas as pd

from scripts.static_archive_scanner import scan_archive
from scripts.static_feature_extractor import FEATURES

BASE = Path(__file__).resolve().parent.parent

INVENTORY = (
    BASE / "data/artifacts/batch_artifact_inventory.csv"
)

OUTPUT = (
    BASE / "data/artifacts/batch_static_features.csv"
)

REPORT = (
    BASE / "reports/batch_static_feature_report.txt"
)

MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024
CHUNK_SIZE = 64 * 1024

ALLOWED_HOSTS = {
    "files.pythonhosted.org",
}

ALLOWED_TYPES = {
    "wheel",
    "sdist_tar_gz",
}

RETRYABLE_STATUSES = {
    "download_error",
    "scan_failed",
    "hash_mismatch",
    "missing_checksum",
}

REQUIRED_COLUMNS = {
    "normalized_name",
    "version",
    "candidate_group",
    "filename",
    "artifact_type",
    "download_url",
    "size_bytes",
    "sha256",
}

RESULT_COLUMNS = [
    "normalized_name",
    "version",
    "candidate_group",
    "filename",
    "artifact_type",
    "scan_status",
    "processed_python_files",
    "skipped_python_files",
    "processed_source_bytes",
    "elapsed_seconds",
    "error_details",
] + list(FEATURES)


def clean_string(value):
    if pd.isna(value):
        return ""
    return str(value).strip()


def valid_sha256(value):
    value = clean_string(value).lower()

    return (
        len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def validate_url(url):
    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise ValueError("Only HTTPS downloads are allowed.")

    if (
        parsed.hostname not in ALLOWED_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.fragment
    ):
        raise ValueError("Unapproved artifact URL.")

    return url


class NoRedirectHandler(
    __import__("urllib.request", fromlist=["HTTPRedirectHandler"])
    .HTTPRedirectHandler
):
    def redirect_request(
        self, req, fp, code, msg, headers, newurl
    ):
        raise ValueError(
            "Redirects are not permitted for artifact downloads."
        )


def download_verified(row, destination):
    url = validate_url(
        clean_string(row["download_url"])
    )

    expected_hash = clean_string(
        row["sha256"]
    ).lower()

    if not valid_sha256(expected_hash):
        return "missing_checksum", "Missing or invalid SHA-256"

    declared_size = pd.to_numeric(
        row["size_bytes"], errors="coerce"
    )

    if pd.notna(declared_size):
        if declared_size < 0:
            return "invalid_size", "Negative artifact size"

        if declared_size > MAX_DOWNLOAD_BYTES:
            return "too_large", "Declared size exceeds limit"

    request = Request(
        url,
        headers={
            "User-Agent": (
                "TyposquatShield-FYP/1.0 "
                "(static artifact research)"
            ),
            "Accept": "application/octet-stream",
        },
    )

    opener = __import__(
        "urllib.request", fromlist=["build_opener"]
    ).build_opener(NoRedirectHandler())

    digest = hashlib.sha256()
    total_bytes = 0

    try:
        with opener.open(request, timeout=30) as response:
            with destination.open("wb") as output:
                while True:
                    chunk = response.read(CHUNK_SIZE)

                    if not chunk:
                        break

                    total_bytes += len(chunk)

                    if total_bytes > MAX_DOWNLOAD_BYTES:
                        return (
                            "too_large",
                            "Downloaded content exceeds limit",
                        )

                    digest.update(chunk)
                    output.write(chunk)

    except (
        HTTPError,
        URLError,
        TimeoutError,
        OSError,
        ValueError,
    ) as exc:
        return "download_error", (
            f"{type(exc).__name__}: {exc}"
        )

    if pd.notna(declared_size):
        if total_bytes != int(declared_size):
            return (
                "size_mismatch",
                f"Expected {int(declared_size)} bytes, "
                f"received {total_bytes}",
            )

    if digest.hexdigest() != expected_hash:
        return (
            "hash_mismatch",
            "Downloaded SHA-256 does not match inventory",
        )

    return "verified", ""


def make_key(row):
    return (
        clean_string(row["normalized_name"]),
        clean_string(row["version"]),
        clean_string(row["filename"]),
    )


def save_results(records):
    OUTPUT.parent.mkdir(
        parents=True, exist_ok=True
    )

    frame = pd.DataFrame(
        records,
        columns=RESULT_COLUMNS,
    )

    temporary = OUTPUT.with_suffix(".csv.tmp")
    frame.to_csv(temporary, index=False)
    os.replace(temporary, OUTPUT)

    return frame


def process_artifact(row):
    started = time.monotonic()

    result = {
        "normalized_name": clean_string(
            row["normalized_name"]
        ),
        "version": clean_string(row["version"]),
        "candidate_group": clean_string(
            row["candidate_group"]
        ),
        "filename": clean_string(row["filename"]),
        "artifact_type": clean_string(
            row["artifact_type"]
        ),
        "scan_status": "not_processed",
        "processed_python_files": 0,
        "skipped_python_files": 0,
        "processed_source_bytes": 0,
        "elapsed_seconds": 0.0,
        "error_details": "",
    }

    for feature in FEATURES:
        result[feature] = None

    artifact_type = result["artifact_type"]

    if artifact_type not in ALLOWED_TYPES:
        result["scan_status"] = "unsupported"
        result["error_details"] = (
            "Unsupported artifact type"
        )
        return result

    suffix = (
        ".whl"
        if artifact_type == "wheel"
        else ".tar.gz"
    )

    with tempfile.TemporaryDirectory(
        prefix="typosquatshield_scan_"
    ) as temporary_dir:

        archive = Path(temporary_dir) / (
            "artifact" + suffix
        )

        status, error = download_verified(
            row, archive
        )

        if status != "verified":
            result["scan_status"] = status
            result["error_details"] = error

        else:
            try:
                scan = scan_archive(archive)

                scan_status = scan.get(
                    "scan_status", "failed"
                )

                if scan_status == "failed":
                    result["scan_status"] = "scan_failed"
                elif scan_status in (
                    "complete",
                    "partial",
                ):
                    result["scan_status"] = scan_status
                else:
                    result["scan_status"] = "scan_failed"

                result["processed_python_files"] = (
                    scan.get("processed_python_files", 0)
                )

                result["skipped_python_files"] = (
                    scan.get("skipped_python_files", 0)
                )

                result["processed_source_bytes"] = (
                    scan.get("processed_source_bytes", 0)
                )

                errors = scan.get("errors", [])

                result["error_details"] = json.dumps(
                    errors,
                    ensure_ascii=False,
                )

                # Only retain features for a complete scan.
                # Partial scans remain diagnostic.
                if result["scan_status"] == "complete":
                    scanned_features = scan.get(
                        "features", {}
                    )

                    for feature in FEATURES:
                        result[feature] = (
                            scanned_features.get(feature)
                        )

            except Exception as exc:
                result["scan_status"] = "scan_failed"
                result["error_details"] = (
                    f"{type(exc).__name__}: {exc}"
                )

    result["elapsed_seconds"] = round(
        time.monotonic() - started, 4
    )

    return result


def create_report(frame, inventory_count):
    completed = frame[
        frame["scan_status"] == "complete"
    ]

    lines = [
        "TYPOSQUATSHIELD - BATCH STATIC FEATURE REPORT",
        "=" * 65,
        f"Artifact inventory records: {inventory_count}",
        f"Processed inventory records: {len(frame)}",
        f"Complete scans: {len(completed)}",
        "",
        "SCAN STATUS",
        frame["scan_status"].value_counts(
            dropna=False
        ).to_string() if len(frame) else "No scans",
        "",
        "SCAN STATUS BY CANDIDATE GROUP",
        pd.crosstab(
            frame["candidate_group"],
            frame["scan_status"],
        ).to_string() if len(frame) else "No scans",
        "",
        "FEATURE TOTALS FOR COMPLETE SCANS",
    ]

    if len(completed):
        totals = (
            completed[list(FEATURES)]
            .apply(pd.to_numeric, errors="coerce")
            .sum()
        )

        lines.append(totals.to_string())
    else:
        lines.append("No complete scans yet.")

    lines += [
        "",
        "LIMITATIONS",
        "Artifacts are downloaded but never installed or executed.",
        "SHA-256 is checked against the inventory metadata.",
        "Only approved PyPI artifact URLs are accepted.",
        "Archives are processed by the existing scanner.",
        "Partial scans are excluded from complete feature totals.",
        "Source-level static indicators are not malware proof.",
        "Scanner limits do not guarantee complete sandbox isolation.",
        "Use an isolated environment for untrusted artifacts.",
        "Candidate labels remain provisional.",
        "No ML training performed.",
    ]

    REPORT.parent.mkdir(
        parents=True, exist_ok=True
    )

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Maximum new artifacts to process",
    )

    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help="Retry previously failed artifacts",
    )

    args = parser.parse_args()

    if args.limit < 1:
        raise ValueError("--limit must be positive.")

    print("=" * 65)
    print("TYPOSQUATSHIELD - BATCH STATIC EXTRACTION")
    print("=" * 65)

    inventory = pd.read_csv(
        INVENTORY,
        dtype={
            "normalized_name": str,
            "version": str,
            "filename": str,
            "sha256": str,
        },
    )

    missing = REQUIRED_COLUMNS - set(
        inventory.columns
    )

    if missing:
        raise ValueError(
            f"Missing inventory columns: {sorted(missing)}"
        )

    if inventory.apply(
        make_key, axis=1
    ).duplicated().any():
        raise ValueError(
            "Duplicate artifact inventory keys."
        )

    records = []

    if OUTPUT.exists():
        existing = pd.read_csv(
            OUTPUT,
            dtype={
                "normalized_name": str,
                "version": str,
                "filename": str,
            },
        )

        records = existing.to_dict(
            orient="records"
        )

    completed_keys = set()

    for row in records:
        if (
            not args.retry_failed
            or row.get("scan_status")
            not in RETRYABLE_STATUSES
        ):
            completed_keys.add(make_key(row))

    pending = inventory[
        ~inventory.apply(
            make_key, axis=1
        ).isin(completed_keys)
    ].head(args.limit)

    print(f"Inventory records: {len(inventory)}")
    print(f"Previously recorded: {len(records)}")
    print(f"Selected for this run: {len(pending)}")
    print()

    for index, (_, row) in enumerate(
        pending.iterrows(), start=1
    ):
        outcome = process_artifact(row)

        key = make_key(outcome)

        records = [
            old for old in records
            if make_key(old) != key
        ]

        records.append(outcome)

        print(
            f"[{index}/{len(pending)}] "
            f"{outcome['normalized_name']}=="
            f"{outcome['version']} | "
            f"{outcome['filename']} | "
            f"{outcome['scan_status']}"
        )

        # Save after every artifact to support resuming.
        save_results(records)

    frame = save_results(records)

    report = create_report(
        frame, len(inventory)
    )

    print()
    print(report)
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Batch processing finished.")


if __name__ == "__main__":
    main()
