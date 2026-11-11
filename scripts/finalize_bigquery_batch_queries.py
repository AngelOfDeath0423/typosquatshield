
from pathlib import Path
import re

import pandas as pd


# ============================================================
# TYPOSQUATSHIELD - FINALIZE BIGQUERY BATCH QUERIES
# ============================================================

BASE = Path(__file__).resolve().parent.parent

BATCH_DIR = BASE / "data" / "full" / "bigquery_batches"
TRACKER_PATH = BATCH_DIR / "collection_tracker.csv"
REPORT_PATH = (
    BASE / "reports" /
    "bigquery_queries_finalization_summary.txt"
)

SOURCE_TABLE = (
    "bigquery-public-data.pypi.distribution_metadata"
)

REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)


# ============================================================
# 1. LOAD COLLECTION TRACKER
# ============================================================

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
            f"Tracker missing columns: {sorted(missing)}"
        )

    if tracker["batch_id"].duplicated().any():
        raise ValueError("Duplicate batch IDs in tracker.")

    return tracker


# ============================================================
# 2. BUILD COMPLETE BIGQUERY SQL
# ============================================================

def build_query(batch_id, package_names):

    # Safely quote package names for BigQuery SQL.
    sql_names = ",\n        ".join(
        "'" + name.replace("'", "''") + "'"
        for name in package_names
    )

    return f"""-- =====================================================
-- TYPOSQUATSHIELD - {batch_id}
-- Historical PyPI metadata collection
-- Package names: {len(package_names)}
-- Source: {SOURCE_TABLE}
--
-- One output row per normalized package-version pair.
-- No OpenSSF labels are assigned by this query.
-- =====================================================

WITH target_packages AS (
    SELECT package_name
    FROM UNNEST([
        {sql_names}
    ]) AS package_name
),

historical_source AS (
    SELECT
        LOWER(
            REGEXP_REPLACE(name, r'[-_.]+', '-')
        ) AS normalized_name,

        version,

        MIN(upload_time) AS first_upload_time,

        COUNT(*) AS distribution_file_count,

        ARRAY_AGG(
            DISTINCT name IGNORE NULLS
            ORDER BY name
            LIMIT 1
        )[SAFE_OFFSET(0)] AS package_name,

        ARRAY_AGG(
            summary IGNORE NULLS
            ORDER BY upload_time, summary
            LIMIT 1
        )[SAFE_OFFSET(0)] AS summary,

        ARRAY_AGG(
            requires_python IGNORE NULLS
            ORDER BY upload_time, requires_python
            LIMIT 1
        )[SAFE_OFFSET(0)] AS requires_python

    FROM `{SOURCE_TABLE}`

    WHERE LOWER(
        REGEXP_REPLACE(name, r'[-_.]+', '-')
    ) IN (
        SELECT package_name
        FROM target_packages
    )

    GROUP BY
        normalized_name,
        version
)

SELECT
    package_name,
    normalized_name,
    version,
    first_upload_time,
    distribution_file_count,
    summary,
    requires_python

FROM historical_source

ORDER BY
    normalized_name,
    first_upload_time,
    version;
"""


# ============================================================
# 3. VALIDATE GENERATED SQL STRUCTURE
# ============================================================

def validate_sql(query, batch_id, expected_count):

    required_fragments = [
        "WITH target_packages AS (",
        "historical_source AS (",
        "FROM `bigquery-public-data.pypi.distribution_metadata`",
        "GROUP BY",
        "FROM historical_source",
    ]

    for fragment in required_fragments:
        if fragment not in query:
            raise ValueError(
                f"{batch_id}: missing SQL fragment: "
                f"{fragment}"
            )

    # Verify the CTE separator is present.
    if not re.search(
        r"\]\)\s+AS\s+package_name\s*\)\s*,\s*"
        r"historical_source\s+AS\s*\(",
        query,
        flags=re.IGNORECASE,
    ):
        raise ValueError(
            f"{batch_id}: missing CTE separator."
        )

    if "WHERE FALSE" in query.upper():
        raise ValueError(
            f"{batch_id}: placeholder SQL detected."
        )

    if expected_count <= 0:
        raise ValueError(
            f"{batch_id}: no package names."
        )


# ============================================================
# 4. GENERATE REMAINING BATCH QUERIES
# ============================================================

def main():

    print("=" * 65)
    print("TYPOSQUATSHIELD - FINALIZE BIGQUERY QUERIES")
    print("=" * 65)

    tracker = load_tracker()

    print("Tracked batches:", len(tracker))

    generated = []
    skipped = []
    errors = []

    for _, row in tracker.iterrows():

        batch_id = row["batch_id"].strip()

        status = row["status"].strip().lower()

        exported = (
            row["export_completed"].strip().lower()
            == "true"
        )

        # Protect completed exports.
        if status == "exported" or exported:
            skipped.append(batch_id)
            print(
                f"[SKIP] {batch_id}: already exported"
            )
            continue

        names_path = (
            BATCH_DIR / f"{batch_id}_names.csv"
        )

        sql_path = (
            BATCH_DIR / f"{batch_id}.sql"
        )

        try:

            if not names_path.exists():
                raise FileNotFoundError(
                    f"Missing names file: {names_path}"
                )

            names_df = pd.read_csv(
                names_path,
                dtype=str,
                keep_default_na=False,
                encoding="utf-8-sig",
            )

            if "normalized_name" not in names_df.columns:
                raise ValueError(
                    "Missing normalized_name column."
                )

            package_names = (
                names_df["normalized_name"]
                .astype(str)
                .str.strip()
                .tolist()
            )

            expected_count = int(
                row["package_count"]
            )

            if len(package_names) != expected_count:
                raise ValueError(
                    "Package count mismatch: "
                    f"expected {expected_count}, "
                    f"found {len(package_names)}"
                )

            if len(set(package_names)) != len(
                package_names
            ):
                raise ValueError(
                    "Duplicate package names."
                )

            for name in package_names:
                if not re.fullmatch(
                    r"[a-z0-9]+(?:-[a-z0-9]+)*",
                    name,
                ):
                    raise ValueError(
                        f"Invalid normalized name: {name}"
                    )

            query = build_query(
                batch_id,
                package_names,
            )

            validate_sql(
                query,
                batch_id,
                expected_count,
            )

            sql_path.write_text(
                query,
                encoding="utf-8",
            )

            generated.append(batch_id)

            print(
                f"[READY] {batch_id}: "
                f"{len(package_names)} package names"
            )

        except Exception as exc:

            errors.append(
                f"{batch_id}: {exc}"
            )

            print(
                f"[ERROR] {batch_id}: {exc}"
            )

    # ========================================================
    # 5. SAVE REPORT
    # ========================================================

    summary = [
        "TYPOSQUATSHIELD - BIGQUERY QUERY FINALIZATION",
        "=" * 60,
        f"Tracked batches: {len(tracker)}",
        f"Generated SQL files: {len(generated)}",
        f"Skipped exported batches: {len(skipped)}",
        f"Errors: {len(errors)}",
        "",
        "GENERATED:",
        *(generated or ["None"]),
        "",
        "SKIPPED:",
        *(skipped or ["None"]),
        "",
        "ERRORS:",
        *(errors or ["None"]),
        "",
        "IMPORTANT:",
        "Exported batches were not modified.",
        "The collection tracker was not modified.",
        "No BigQuery queries were executed.",
        "Normalized package-version grouping is used.",
        "Historical metadata is not malware ground truth.",
    ]

    REPORT_PATH.write_text(
        "\n".join(summary),
        encoding="utf-8",
    )

    print()
    print("\n".join(summary))
    print()
    print("Saved report:", REPORT_PATH)

    if errors:
        raise SystemExit(
            "Some queries failed validation."
        )

    print()
    print("BigQuery query finalization completed.")


if __name__ == "__main__":
    main()
