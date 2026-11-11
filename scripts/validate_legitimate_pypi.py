
import json
from pathlib import Path

import pandas as pd
from packaging.utils import canonicalize_name

BASE = Path(__file__).resolve().parent.parent

DATA = BASE / "data/legitimate/legitimate_pypi_pilot_100.csv"
LOG = BASE / "data/legitimate/legitimate_pypi_pilot_log.csv"
MANIFEST = BASE / "data/labels/openssf_pypi_label_manifest.csv"
REPORT = BASE / "reports/legitimate_pilot_validation.txt"

df = pd.read_csv(DATA, dtype=str, keep_default_na=False)
log = pd.read_csv(LOG, dtype=str, keep_default_na=False)
manifest = pd.read_csv(
    MANIFEST, dtype=str, keep_default_na=False
)

checks = {}

checks["duplicate_names"] = int(
    df["normalized_name"].duplicated().sum()
)

checks["normalization_errors"] = sum(
    canonicalize_name(name) != normalized
    for name, normalized in zip(
        df["package_name"], df["normalized_name"]
    )
)

excluded = set(manifest["normalized_name"])
checks["active_openssf_overlaps"] = len(
    set(df["normalized_name"]) & excluded
)

dates = {}
for col in [
    "first_upload_time",
    "latest_upload_time",
    "collection_timestamp",
]:
    dates[col] = pd.to_datetime(
        df[col],
        format="mixed",
        utc=True,
        errors="coerce",
    )
    checks[f"invalid_{col}"] = int(
        dates[col].isna().sum()
    )

checks["invalid_date_order"] = int((
    (dates["first_upload_time"] > dates["latest_upload_time"])
    | (dates["latest_upload_time"] > dates["collection_timestamp"])
).sum())

for col in [
    "version_count",
    "distribution_file_count",
    "latest_release_file_count",
]:
    values = pd.to_numeric(df[col], errors="coerce")
    checks[f"invalid_{col}"] = int(
        (values.isna() | (values < 0) | (values % 1 != 0)).sum()
    )

for col, expected_type in [
    ("requires_dist", list),
    ("project_urls", dict),
]:
    invalid = 0
    for value in df[col]:
        try:
            if not isinstance(json.loads(value), expected_type):
                invalid += 1
        except (ValueError, TypeError):
            invalid += 1
    checks[f"invalid_{col}_json"] = invalid

checks["unexpected_labels"] = int(
    df["label_status"].ne("presumed_legitimate").sum()
)

checks["unexpected_verified_flags"] = int(
    df["label_verified"].str.lower().ne("false").sum()
)

checks["collection_log_mismatch"] = abs(
    int(log["status"].eq("collected").sum()) - len(df)
)

lines = [
    "TYPOSQUATSHIELD - LEGITIMATE PILOT VALIDATION",
    f"Records: {len(df)}",
    f"Columns: {len(df.columns)}",
    "",
]

for check, count in checks.items():
    lines.append(f"{check}: {count}")

lines.append("")
lines.append("OPTIONAL METADATA MISSING VALUES")

for col in [
    "author", "author_email", "maintainer",
    "maintainer_email", "license", "keywords",
    "home_page", "requires_python",
]:
    lines.append(
        f"{col}: {int(df[col].str.strip().eq('').sum())}"
    )

passed = all(value == 0 for value in checks.values())
lines.append("")
lines.append(
    "STRUCTURAL VALIDATION: "
    + ("PASS" if passed else "REVIEW REQUIRED")
)

lines.append(
    "Note: This does not verify that packages are benign."
)

REPORT.parent.mkdir(parents=True, exist_ok=True)
REPORT.write_text("\n".join(lines), encoding="utf-8")

print("\n".join(lines))
print("\nReport saved to:", REPORT)
