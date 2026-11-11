
from pathlib import Path
import argparse
import os
import tempfile
import time

import pandas as pd
from google.cloud import bigquery
from google.api_core.exceptions import (
    GoogleAPICallError,
    RetryError,
)

# ============================================================
# TYPOSQUATSHIELD - AUTOMATED BIGQUERY COLLECTION
# ============================================================

BASE = Path(__file__).resolve().parent.parent

BATCH_DIR = BASE / "data" / "full" / "bigquery_batches"
EXPORT_DIR = BASE / "data" / "full" / "historical_exports"
TRACKER_PATH = BATCH_DIR / "collection_tracker.csv"

PROJECT_ID = "typosquatshield-fyp"

EXPECTED_COLUMNS = [
    "package_name",
    "normalized_name",
    "version",
    "first_upload_time",
    "distribution_file_count",
    "summary",
    "requires_python",
]

EXPORT_DIR.mkdir(parents=True, exist_ok=True)


def load_tracker():
    if not TRACKER_PATH.exists():
        raise FileNotFoundError(TRACKER_PATH)

    tracker = pd.read_csv(
        TRACKER_PATH,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )

    required = {
        "batch_id",
        "package_count",
        "status",
        "query_completed",
        "export_completed",
        "export_file",
        "returned_rows",
        "notes",
    }

    missing = required - set(tracker.columns)

    if missing:
        raise ValueError(
            f"Missing tracker columns: {sorted(missing)}"
        )

    if tracker["batch_id"].duplicated().any():
        raise ValueError("Duplicate batch IDs in tracker.")

    return tracker


def save_tracker(tracker):
    # Write to a temporary file first, then replace.
    fd, temp_path = tempfile.mkstemp(
        suffix=".csv",
        dir=TRACKER_PATH.parent,
    )
    os.close(fd)

    try:
        tracker.to_csv(
            temp_path,
            index=False,
            encoding="utf-8-sig",
        )
        os.replace(temp_path, TRACKER_PATH)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def validate_results(frame, expected_names):
    problems = []

    if list(frame.columns) != EXPECTED_COLUMNS:
        problems.append("Unexpected output columns.")
        return problems

    if frame.empty:
        problems.append(
            "No rows returned; requires manual review."
        )
        return problems

    for col in [
        "package_name",
        "normalized_name",
        "version",
        "first_upload_time",
        "distribution_file_count",
    ]:
        if frame[col].isna().any():
            problems.append(f"Missing values: {col}")

    for col in ["normalized_name", "version"]:
        if frame[col].astype(str).str.strip().eq("").any():
            problems.append(f"Empty values: {col}")

    duplicate_count = frame.duplicated(
        ["normalized_name", "version"]
    ).sum()

    if duplicate_count:
        problems.append(
            f"Duplicate package-version pairs: {duplicate_count}"
        )

    names = set(frame["normalized_name"].astype(str))

    unexpected = names - expected_names

    if unexpected:
        problems.append(
            f"Unexpected package names: {len(unexpected)}"
        )

    dates = pd.to_datetime(
        frame["first_upload_time"],
        utc=True,
        errors="coerce",
    )

    if dates.isna().any():
        problems.append("Invalid upload timestamps.")

    counts = pd.to_numeric(
        frame["distribution_file_count"],
        errors="coerce",
    )

    if counts.isna().any() or (counts <= 0).any():
        problems.append(
            "Invalid distribution file counts."
        )

    return problems


def collect_one(client, tracker, batch_id, max_bytes):
    matching = tracker.index[
        tracker["batch_id"] == batch_id
    ].tolist()

    if not matching:
        raise ValueError(
            f"Batch not found in tracker: {batch_id}"
        )

    index = matching[0]
    row = tracker.loc[index]

    exported = (
        str(row["export_completed"]).lower() == "true"
    )

    if exported or str(row["status"]).lower() == "exported":
        print(f"[SKIP] {batch_id}: already exported")
        return True

    sql_path = BATCH_DIR / f"{batch_id}.sql"
    names_path = BATCH_DIR / f"{batch_id}_names.csv"
    export_path = EXPORT_DIR / f"{batch_id}_historical.csv"

    if not sql_path.exists():
        raise FileNotFoundError(sql_path)

    if not names_path.exists():
        raise FileNotFoundError(names_path)

    if export_path.exists():
        raise FileExistsError(
            f"Existing untracked export: {export_path}. "
            "Review it before rerunning."
        )

    sql = sql_path.read_text(encoding="utf-8")

    if (
        "bigquery-public-data.pypi.distribution_metadata"
        not in sql
        or "WHERE FALSE" in sql.upper()
    ):
        raise ValueError(
            f"{batch_id}: SQL source is not finalized."
        )

    names_df = pd.read_csv(
        names_path,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )

    expected_names = set(
        names_df["normalized_name"]
    )

    if len(names_df) != int(row["package_count"]):
        raise ValueError(
            f"{batch_id}: package count mismatch."
        )

    if len(expected_names) != len(names_df):
        raise ValueError(
            f"{batch_id}: duplicate input names."
        )

    print(f"\n{'=' * 60}")
    print(f"Processing {batch_id}")
    print(f"Input package names: {len(expected_names)}")

    # DRY RUN: estimate bytes without executing the query.
    dry_job = client.query(
        sql,
        job_config=bigquery.QueryJobConfig(
            dry_run=True,
            use_query_cache=False,
        ),
    )

    estimated_bytes = dry_job.total_bytes_processed or 0
    estimated_gib = estimated_bytes / (1024 ** 3)

    print(f"Estimated bytes scanned: {estimated_gib:.3f} GiB")

    if estimated_bytes > max_bytes:
        print(
            "[STOP] Query exceeds per-batch byte limit."
        )
        return False

    # This is an additional per-query safeguard,
    # not an overall billing or cost guarantee.
    job = client.query(
        sql,
        job_config=bigquery.QueryJobConfig(
            maximum_bytes_billed=max_bytes,
            use_query_cache=True,
        ),
    )

    print(f"BigQuery job ID: {job.job_id}")

    rows = job.result()
    frame = rows.to_dataframe(
        create_bqstorage_client=False
    )

    print(f"Returned records: {len(frame)}")

    # Save a temporary diagnostic copy before validation.
    diagnostic_path = (
        EXPORT_DIR / f"{batch_id}_diagnostic.csv"
    )

    frame.to_csv(
        diagnostic_path,
        index=False,
        encoding="utf-8-sig",
    )

    print(f"Diagnostic CSV saved: {diagnostic_path}")

    problems = validate_results(
        frame,
        expected_names,
    )

    if problems:
        print("[FAILED] Validation problems:")
        for problem in problems:
            print(" -", problem)

        print(
            "Tracker unchanged. "
            "Review the batch before retrying."
        )
        return False

    # Save export atomically.
    fd, temp_path = tempfile.mkstemp(
        suffix=".csv",
        dir=EXPORT_DIR,
    )
    os.close(fd)

    try:
        frame.to_csv(
            temp_path,
            index=False,
            encoding="utf-8-sig",
        )
        os.replace(temp_path, export_path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    recovered_names = frame["normalized_name"].nunique()
    missing_names = len(expected_names) - recovered_names

    tracker.at[index, "status"] = "exported"
    tracker.at[index, "query_completed"] = "True"
    tracker.at[index, "export_completed"] = "True"
    tracker.at[index, "export_file"] = str(
        export_path.relative_to(BASE)
    ).replace("\\", "/")
    tracker.at[index, "returned_rows"] = str(len(frame))
    tracker.at[index, "notes"] = (
        f"{recovered_names} names recovered; "
        f"{missing_names} not recovered; "
        "structural validation passed; "
        "version evidence review pending"
    )

    save_tracker(tracker)

    print(f"[SUCCESS] {batch_id}")
    print(f"Unique names recovered: {recovered_names}")
    print(f"Names not recovered: {missing_names}")
    print(f"Saved: {export_path}")
    print("Tracker updated.")

    return True


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--start",
        type=int,
        default=3,
    )

    parser.add_argument(
        "--end",
        type=int,
        default=3,
    )

    parser.add_argument(
        "--max-gib",
        type=float,
        default=5.0,
        help="Maximum estimated GiB per query.",
    )

    args = parser.parse_args()

    if not (1 <= args.start <= args.end <= 24):
        parser.error("Batch range must be between 1 and 24.")

    if args.max_gib <= 0:
        parser.error("--max-gib must be positive.")

    max_bytes = int(args.max_gib * (1024 ** 3))

    print("=" * 65)
    print("TYPOSQUATSHIELD - AUTOMATED BIGQUERY COLLECTION")
    print("=" * 65)
    print("Project:", PROJECT_ID)
    print("Start batch:", args.start)
    print("End batch:", args.end)
    print("Per-query byte limit:", args.max_gib, "GiB")

    tracker = load_tracker()

    client = bigquery.Client(project=PROJECT_ID)

    for number in range(args.start, args.end + 1):
        batch_id = f"batch_{number:03d}"

        try:
            success = collect_one(
                client,
                tracker,
                batch_id,
                max_bytes,
            )
        except (
            GoogleAPICallError,
            RetryError,
            Exception,
        ) as exc:
            print(f"[ERROR] {batch_id}: {exc}")
            success = False

        if not success:
            print(
                "\nCollection stopped. "
                "Resolve this batch before continuing."
            )
            raise SystemExit(1)

        # Small pause between successful batches.
        if number < args.end:
            time.sleep(2)

    print()
    print("=" * 65)
    print("Requested batch collection completed.")
    print("=" * 65)


if __name__ == "__main__":
    main()
