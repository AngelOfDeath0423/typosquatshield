
from pathlib import Path
import argparse

import pandas as pd
from google.cloud import bigquery
from packaging.utils import canonicalize_name


BASE = Path(__file__).resolve().parent.parent
PROJECT_ID = "typosquatshield-fyp"

SELECTED = BASE / "data/legitimate/legitimate_selected_10000.csv"
OUTPUT_DIR = BASE / "data/legitimate/historical_batches"

BATCH_SIZE = 500
MAX_BYTES = 5 * 1024**3

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

SQL = """
WITH selected_names AS (
  SELECT name AS normalized_name
  FROM UNNEST(@package_names) AS name
),
historical_source AS (
  SELECT
    name AS package_name,
    LOWER(REGEXP_REPLACE(name, r'[-_.]+', '-')) AS normalized_name,
    version,
    upload_time,
    summary,
    requires_python
  FROM `bigquery-public-data.pypi.distribution_metadata`
  WHERE name IS NOT NULL
    AND version IS NOT NULL
    AND upload_time IS NOT NULL
),
matched AS (
  SELECT h.*
  FROM historical_source h
  INNER JOIN selected_names s
    ON h.normalized_name = s.normalized_name
)
SELECT
  ARRAY_AGG(
    package_name
    ORDER BY upload_time, package_name
    LIMIT 1
  )[OFFSET(0)] AS package_name,
  normalized_name,
  version,
  MIN(upload_time) AS first_upload_time,
  COUNT(*) AS distribution_file_count,
  ARRAY_AGG(
    summary IGNORE NULLS
    ORDER BY upload_time
    LIMIT 1
  )[SAFE_OFFSET(0)] AS summary,
  ARRAY_AGG(
    requires_python IGNORE NULLS
    ORDER BY upload_time
    LIMIT 1
  )[SAFE_OFFSET(0)] AS requires_python
FROM matched
GROUP BY normalized_name, version
ORDER BY normalized_name, version
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch", type=int, default=1)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute after a successful dry run",
    )
    args = parser.parse_args()

    selected = pd.read_csv(
        SELECTED,
        dtype={"normalized_name": str},
        encoding="utf-8-sig",
    )

    if "normalized_name" not in selected.columns:
        raise ValueError("Missing normalized_name column")

    names = selected["normalized_name"].map(canonicalize_name)

    if names.duplicated().any():
        raise ValueError("Duplicate selected package names")

    start = (args.batch - 1) * BATCH_SIZE
    end = min(start + BATCH_SIZE, len(names))

    if args.batch < 1 or start >= len(names):
        raise ValueError("Invalid batch number")

    batch_names = names.iloc[start:end].tolist()
    batch_id = f"batch_{args.batch:03d}"

    output = OUTPUT_DIR / f"{batch_id}_historical.csv"

    print("=" * 60)
    print("TYPOSQUATSHIELD - LEGITIMATE HISTORICAL COLLECTION")
    print("=" * 60)
    print("Batch:", batch_id)
    print("Requested names:", len(batch_names))
    print("Output:", output)

    if output.exists():
        print("[SKIP] Output already exists; not overwriting.")
        return

    client = bigquery.Client(project=PROJECT_ID)

    parameters = [
        bigquery.ArrayQueryParameter(
            "package_names",
            "STRING",
            batch_names,
        )
    ]

    dry_config = bigquery.QueryJobConfig(
        query_parameters=parameters,
        dry_run=True,
        use_query_cache=False,
    )

    dry_job = client.query(SQL, job_config=dry_config)
    estimated = dry_job.total_bytes_processed

    print(
        "Estimated bytes scanned:",
        round(estimated / 1024**3, 3),
        "GiB",
    )

    if estimated > MAX_BYTES:
        raise ValueError("Query exceeds 5 GiB safety limit")

    if not args.execute:
        print("[DRY RUN] No data query executed.")
        return

    job_config = bigquery.QueryJobConfig(
        query_parameters=parameters,
        maximum_bytes_billed=MAX_BYTES,
    )

    job = client.query(SQL, job_config=job_config)
    df = job.to_dataframe()

    print("BigQuery job ID:", job.job_id)
    print("Returned records:", len(df))

    required = {
        "package_name",
        "normalized_name",
        "version",
        "first_upload_time",
        "distribution_file_count",
        "summary",
        "requires_python",
    }

    if not required.issubset(df.columns):
        raise ValueError("Missing expected output columns")

    if df.empty:
        raise ValueError("No historical records returned")

    if df.duplicated(["normalized_name", "version"]).any():
        raise ValueError("Duplicate package-version pairs")

    if not set(df["normalized_name"]).issubset(set(batch_names)):
        raise ValueError("Unexpected package names returned")

    timestamps = pd.to_datetime(
        df["first_upload_time"],
        format="mixed",
        utc=True,
        errors="coerce",
    )

    if timestamps.isna().any():
        raise ValueError("Invalid upload timestamps")

    counts = pd.to_numeric(
        df["distribution_file_count"],
        errors="coerce",
    )

    if counts.isna().any() or (counts <= 0).any():
        raise ValueError("Invalid distribution counts")

    if df["version"].isna().any():
        raise ValueError("Missing versions")

    df["label_status"] = "presumed_legitimate"
    df["label_verified"] = False
    df["selection_source"] = "historical_bigquery_stratified_sample"

    temp_output = output.with_suffix(".tmp")
    df.to_csv(
        temp_output,
        index=False,
        encoding="utf-8-sig",
    )
    temp_output.replace(output)

    recovered = df["normalized_name"].nunique()

    print("Unique names recovered:", recovered)
    print("Names not recovered:", len(batch_names) - recovered)
    print("Duplicate package-version pairs: 0")
    print("Saved:", output)
    print("[SUCCESS] Batch collection completed.")


if __name__ == "__main__":
    main()
