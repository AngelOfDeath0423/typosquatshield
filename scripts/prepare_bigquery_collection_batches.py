
from pathlib import Path
import csv
import json
import math
import re

import pandas as pd
from packaging.utils import canonicalize_name


# ============================================================
# TYPOSQUATSHIELD - BIGQUERY BATCH PREPARATION
# ============================================================

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data" / "full" / "malicious_manifest.csv"

OUTPUT_DIR = BASE / "data" / "full" / "bigquery_batches"
REPORT_DIR = BASE / "reports"

BATCH_SIZE = 500

INDEX_FILE = OUTPUT_DIR / "batch_index.csv"
TRACKER_FILE = OUTPUT_DIR / "collection_tracker.csv"
SUMMARY_FILE = REPORT_DIR / "bigquery_batch_preparation_summary.txt"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# 1. LOAD AND VALIDATE MANIFEST
# ============================================================

print("=" * 65)
print("TYPOSQUATSHIELD - BIGQUERY BATCH PREPARATION")
print("=" * 65)

if not INPUT.exists():
    raise FileNotFoundError(
        f"Manifest not found: {INPUT}"
    )

df = pd.read_csv(
    INPUT,
    dtype=str,
    keep_default_na=False,
    encoding="utf-8-sig",
)

required = {"normalized_name", "report_id"}

missing_columns = required - set(df.columns)

if missing_columns:
    raise ValueError(
        f"Missing columns: {sorted(missing_columns)}"
    )

if df.empty:
    raise ValueError("Manifest is empty.")

invalid_names = []

names = set()

for raw_name in df["normalized_name"]:
    raw_name = str(raw_name).strip()

    if not raw_name:
        invalid_names.append(raw_name)
        continue

    normalized = canonicalize_name(raw_name)

    if not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
        normalized,
    ):
        invalid_names.append(raw_name)
        continue

    names.add(normalized)

if invalid_names:
    raise ValueError(
        f"Invalid package names: {invalid_names[:10]}"
    )

names = sorted(names)

total_names = len(names)
total_batches = math.ceil(total_names / BATCH_SIZE)

print("Manifest rows:", len(df))
print("Unique package names:", total_names)
print("Batch size:", BATCH_SIZE)
print("Total batches:", total_batches)


# ============================================================
# 2. GENERATE BATCH FILES
# ============================================================

batch_index = []
tracker_rows = []

for batch_number in range(1, total_batches + 1):

    start = (batch_number - 1) * BATCH_SIZE
    end = start + BATCH_SIZE

    batch_names = names[start:end]

    batch_id = f"batch_{batch_number:03d}"

    csv_file = OUTPUT_DIR / f"{batch_id}_names.csv"
    sql_file = OUTPUT_DIR / f"{batch_id}.sql"

    pd.DataFrame({
        "normalized_name": batch_names
    }).to_csv(
        csv_file,
        index=False,
        encoding="utf-8-sig",
    )

    # BigQuery uses single-quoted SQL string literals.
    # Package names are validated above; escaping is
    # included as an additional precaution.
    sql_names = ",\n    ".join(
        "'" + name.replace("'", "''") + "'"
        for name in batch_names
    )

    # This is an executable BigQuery name-list CTE.
    # It deliberately does not invent a source table.
    # The historical source query must be taken from
    # the user's previously successful BigQuery query.

    sql_text = f"""-- TYPOSQUATSHIELD - {batch_id}
-- Package names: {len(batch_names)}
--
-- IMPORTANT:
-- Replace the historical_source CTE below with the
-- validated historical PyPI query used in your pilot.
-- Do not run this template until that is done.
--
-- Expected source columns:
-- name, version, upload_time, summary,
-- requires_python, filename
--
-- Historical metadata is not a verified malware label.

WITH target_packages AS (
    SELECT package_name
    FROM UNNEST([
    {sql_names}
    ]) AS package_name
),

historical_source AS (
    -- REPLACE THIS SECTION WITH YOUR VERIFIED
    -- HISTORICAL BIGQUERY SOURCE QUERY.
    --
    -- Example required output schema only:
    SELECT
        CAST(NULL AS STRING) AS name,
        CAST(NULL AS STRING) AS version,
        CAST(NULL AS TIMESTAMP) AS upload_time,
        CAST(NULL AS STRING) AS summary,
        CAST(NULL AS STRING) AS requires_python,
        CAST(NULL AS STRING) AS filename
    WHERE FALSE
)

SELECT
    s.name,
    s.version,
    s.upload_time,
    s.summary,
    s.requires_python,
    s.filename
FROM historical_source AS s
JOIN target_packages AS t
    ON REGEXP_REPLACE(
        LOWER(s.name),
        r'[-_.]+',
        '-'
    ) = t.package_name
ORDER BY s.name, s.version, s.upload_time;
"""

    sql_file.write_text(
        sql_text,
        encoding="utf-8",
    )

    batch_index.append({
        "batch_id": batch_id,
        "package_count": len(batch_names),
        "first_package": batch_names[0],
        "last_package": batch_names[-1],
        "names_file": str(csv_file.relative_to(BASE)),
        "sql_file": str(sql_file.relative_to(BASE)),
    })

    tracker_rows.append({
        "batch_id": batch_id,
        "package_count": len(batch_names),
        "status": "not_started",
        "query_completed": False,
        "export_completed": False,
        "export_file": "",
        "returned_rows": "",
        "notes": "",
    })

    print(
        f"[{batch_number}/{total_batches}] "
        f"{batch_id}: {len(batch_names)} packages"
    )


# ============================================================
# 3. SAVE INDEX AND TRACKER
# ============================================================

pd.DataFrame(batch_index).to_csv(
    INDEX_FILE,
    index=False,
    encoding="utf-8-sig",
)

# Preserve progress if the script is rerun.
# New batches are added; existing statuses remain.
new_tracker = pd.DataFrame(tracker_rows)

if TRACKER_FILE.exists():
    old_tracker = pd.read_csv(
        TRACKER_FILE,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )

    if "batch_id" in old_tracker.columns:
        old_by_id = old_tracker.set_index("batch_id")

        for i, row in new_tracker.iterrows():
            batch_id = row["batch_id"]

            if batch_id not in old_by_id.index:
                continue

            old_count = old_by_id.loc[
                batch_id, "package_count"
            ]

            if str(old_count) != str(row["package_count"]):
                raise ValueError(
                    f"Existing tracker mismatch: {batch_id}"
                )

            for column in [
                "status",
                "query_completed",
                "export_completed",
                "export_file",
                "returned_rows",
                "notes",
            ]:
                if column in old_by_id.columns:
                    new_tracker.at[i, column] = (
                        old_by_id.loc[batch_id, column]
                    )

new_tracker.to_csv(
    TRACKER_FILE,
    index=False,
    encoding="utf-8-sig",
)


# ============================================================
# 4. SUMMARY
# ============================================================

summary = [
    "TYPOSQUATSHIELD - BIGQUERY BATCH PREPARATION",
    "=" * 60,
    f"Manifest rows: {len(df)}",
    f"Unique package names: {total_names}",
    f"Batch size: {BATCH_SIZE}",
    f"Total batches: {total_batches}",
    f"Total assigned names: "
    f"{sum(x['package_count'] for x in batch_index)}",
    "",
    "OUTPUTS:",
    str(INDEX_FILE),
    str(TRACKER_FILE),
    "",
    "IMPORTANT:",
    "No BigQuery queries have been executed.",
    "SQL files contain a placeholder historical source.",
    "Use the previously verified BigQuery source query.",
    "No package artifacts have been downloaded.",
    "These are OpenSSF candidates, not verified ML labels.",
]

SUMMARY_FILE.write_text(
    "\n".join(summary),
    encoding="utf-8",
)

print()
print("\n".join(summary))
print()
print("Batch preparation completed.")
