
import csv
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data" / "audit" / "malicious_metadata_audit_100.csv"
OUTPUT = BASE / "data" / "audit" / "bigquery_audit_100.sql"

with INPUT.open("r", encoding="utf-8-sig", newline="") as f:
    rows = list(csv.DictReader(f))

names = sorted({
    row["normalized_name"].strip().lower()
    for row in rows
    if row["normalized_name"].strip()
})

if len(names) != 100:
    raise ValueError(f"Expected 100 unique names, found {len(names)}")

values = ",\n    ".join(
    "('" + name.replace("'", "''") + "')"
    for name in names
)

sql = f"""
-- TyposquatShield: Historical metadata coverage audit
-- One result per input package, including packages with no match.

WITH target_packages AS (
  SELECT package_name
  FROM UNNEST([
    {", ".join("'" + n.replace("'", "''") + "'" for n in names)}
  ]) AS package_name
),
historical AS (
  SELECT
    LOWER(
      REGEXP_REPLACE(name, r'[-_.]+', '-')
    ) AS normalized_name,
    COUNT(*) AS distribution_records,
    COUNT(DISTINCT version) AS version_count,
    MIN(upload_time) AS earliest_upload,
    MAX(upload_time) AS latest_upload
  FROM `bigquery-public-data.pypi.distribution_metadata`
  WHERE LOWER(
    REGEXP_REPLACE(name, r'[-_.]+', '-')
  ) IN (SELECT package_name FROM target_packages)
  GROUP BY normalized_name
)
SELECT
  t.package_name,
  COALESCE(h.distribution_records, 0) AS distribution_records,
  COALESCE(h.version_count, 0) AS version_count,
  h.earliest_upload,
  h.latest_upload,
  h.distribution_records IS NOT NULL AS metadata_found
FROM target_packages t
LEFT JOIN historical h
  ON t.package_name = h.normalized_name
ORDER BY t.package_name;
"""

OUTPUT.write_text(sql.strip() + "\n", encoding="utf-8")

print(f"Generated query for {len(names)} packages")
print(f"Saved to: {OUTPUT}")


# ============================================================
# GENERATE HISTORICAL VERSION-LEVEL EXPORT QUERY
# ============================================================

VERSION_OUTPUT = (
    BASE / "data" / "audit" /
    "bigquery_versions_100.sql"
)

package_list = ",\n    ".join(
    "'" + name.replace("'", "''") + "'"
    for name in names
)

version_sql = f"""
-- TyposquatShield: Historical version-level metadata export

WITH target_packages AS (
  SELECT package_name
  FROM UNNEST([
    {package_list}
  ]) AS package_name
)

SELECT
  name AS package_name,
  LOWER(
    REGEXP_REPLACE(name, r'[-_.]+', '-')
  ) AS normalized_name,
  version,
  MIN(upload_time) AS first_upload_time,
  COUNT(*) AS distribution_file_count,
  ARRAY_AGG(
    DISTINCT summary IGNORE NULLS LIMIT 1
  )[SAFE_OFFSET(0)] AS summary,
  ARRAY_AGG(
    DISTINCT requires_python IGNORE NULLS LIMIT 1
  )[SAFE_OFFSET(0)] AS requires_python

FROM `bigquery-public-data.pypi.distribution_metadata`

WHERE LOWER(
  REGEXP_REPLACE(name, r'[-_.]+', '-')
) IN (
  SELECT package_name FROM target_packages
)

GROUP BY
  package_name,
  normalized_name,
  version

ORDER BY
  normalized_name,
  first_upload_time;
"""

VERSION_OUTPUT.write_text(
    version_sql.strip() + "\n",
    encoding="utf-8",
)

print(f"Generated version-level query for {len(names)} packages")
print(f"Saved to: {VERSION_OUTPUT}")
