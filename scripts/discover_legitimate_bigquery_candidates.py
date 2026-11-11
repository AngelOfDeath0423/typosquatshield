
from pathlib import Path
import re

import pandas as pd
from google.cloud import bigquery
from packaging.utils import canonicalize_name

BASE = Path(__file__).resolve().parent.parent

PROJECT_ID = "typosquatshield-fyp"
OUTPUT_DIR = BASE / "data" / "legitimate"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

LABELS = BASE / "data/labels/openssf_pypi_labels_reviewed.csv"
PILOT = BASE / "data/legitimate/legitimate_pypi_pilot_100.csv"

# Safety limit for the discovery query.
MAX_BYTES = 5 * 1024**3

# This stage only estimates the query cost.
# Change to True after reviewing the dry-run result.
EXECUTE_QUERY = True

QUERY = """
WITH candidate_names AS (
  SELECT
    LOWER(REGEXP_REPLACE(name, r'[-_.]+', '-')) AS normalized_name,
    COUNT(*) AS distribution_file_count,
    COUNT(DISTINCT version) AS version_count,
    MIN(upload_time) AS first_upload_time,
    MAX(upload_time) AS latest_upload_time
  FROM `bigquery-public-data.pypi.distribution_metadata`
  WHERE name IS NOT NULL
    AND version IS NOT NULL
    AND upload_time IS NOT NULL
  GROUP BY normalized_name
)
SELECT *
FROM candidate_names
WHERE MOD(
  MOD(FARM_FINGERPRINT(normalized_name), 1000) + 1000,
  1000
) < 100
ORDER BY normalized_name
"""

def main():
    print("=" * 60)
    print("TYPOSQUATSHIELD - LEGITIMATE CANDIDATE DISCOVERY")
    print("=" * 60)

    labels = pd.read_csv(
        LABELS,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )

    excluded = set(
        labels["package_name"].map(canonicalize_name)
    )

    if PILOT.exists():
        pilot = pd.read_csv(
            PILOT,
            dtype=str,
            keep_default_na=False,
            encoding="utf-8-sig",
        )
        excluded.update(
            pilot["normalized_name"].map(canonicalize_name)
        )

    print("Excluded OpenSSF/pilot names:", len(excluded))

    client = bigquery.Client(project=PROJECT_ID)

    dry_config = bigquery.QueryJobConfig(
        dry_run=True,
        use_query_cache=False,
    )

    dry_job = client.query(QUERY, job_config=dry_config)
    estimated_bytes = dry_job.total_bytes_processed

    print(
        "Estimated bytes scanned:",
        round(estimated_bytes / 1024**3, 3),
        "GiB",
    )

    if estimated_bytes > MAX_BYTES:
        print("[STOP] Query exceeds the 5 GiB safety limit.")
        return

    if not EXECUTE_QUERY:
        print("[DRY RUN] No data query executed.")
        print("Review the estimate before enabling collection.")
        return

    job_config = bigquery.QueryJobConfig(
        maximum_bytes_billed=MAX_BYTES
    )

    df = client.query(
        QUERY,
        job_config=job_config,
    ).to_dataframe()

    print("Candidate names returned:", len(df))

    df["normalized_name"] = (
        df["normalized_name"].map(canonicalize_name)
    )

    df = df[
        ~df["normalized_name"].isin(excluded)
    ].copy()

    df = df.drop_duplicates("normalized_name")

    # These are candidates, not verified benign packages.
    df["label_status"] = "presumed_legitimate"
    df["label_verified"] = False
    df["selection_source"] = "historical_bigquery_hash_sample"

    output = OUTPUT_DIR / "bigquery_legitimate_candidate_pool.csv"
    df.to_csv(
        output,
        index=False,
        encoding="utf-8-sig",
    )

    print("Candidates after exclusions:", len(df))
    print("Saved:", output)
    print("[SUCCESS] Candidate discovery completed.")


if __name__ == "__main__":
    main()
