
from pathlib import Path
import pandas as pd
from packaging.utils import canonicalize_name


# ============================================================
# TYPOSQUATSHIELD - PILOT FEATURE AVAILABILITY AUDIT
# ============================================================

BASE = Path(__file__).resolve().parent.parent

INPUT = (
    BASE / "data" / "pilot_ml" /
    "pilot_all_219.csv"
)

OUTPUT = (
    BASE / "data" / "audit" /
    "pilot_feature_availability.csv"
)

RECORD_OUTPUT = (
    BASE / "data" / "audit" /
    "pilot_feature_record_checks.csv"
)

REPORT = (
    BASE / "reports" /
    "pilot_feature_availability_summary.txt"
)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
REPORT.parent.mkdir(parents=True, exist_ok=True)


# ============================================================
# 1. LOAD DATASET
# ============================================================

print("=" * 65)
print("TYPOSQUATSHIELD - PILOT FEATURE AVAILABILITY AUDIT")
print("=" * 65)

if not INPUT.exists():
    raise FileNotFoundError(
        f"Pilot dataset not found: {INPUT}"
    )

df = pd.read_csv(
    INPUT,
    dtype=str,
    keep_default_na=False,
    encoding="utf-8-sig",
)

print("Total records:", len(df))
print(
    "Unique packages:",
    df["normalized_name"].nunique(),
)

if df.duplicated(
    ["normalized_name", "version"]
).any():
    raise ValueError(
        "Duplicate package-version records detected."
    )


# ============================================================
# 2. DEFINE FEATURE CANDIDATES
# ============================================================

# Availability in the CSV is not the same as availability
# at the historical installation time.

FEATURES = {
    "package_name": {
        "category": "name",
        "role": "feature_source",
        "temporal_status": "available_from_package_name",
    },
    "version": {
        "category": "version",
        "role": "feature_source",
        "temporal_status": "available_from_requested_version",
    },
    "summary": {
        "category": "metadata",
        "role": "feature_candidate",
        "temporal_status": "historical_snapshot_not_proven",
    },
    "requires_python": {
        "category": "metadata",
        "role": "feature_candidate",
        "temporal_status": "historical_snapshot_not_proven",
    },
    "distribution_file_count": {
        "category": "release_metadata",
        "role": "feature_candidate",
        "temporal_status": "release_level_verify_definition",
    },
    "first_upload_time": {
        "category": "time",
        "role": "feature_source",
        "temporal_status": "requires_assessment_timestamp",
    },
}

# These fields contain report/label information.
# They must NOT become predictive model inputs.

EXCLUDED_FIELDS = [
    "original_report_status",
    "timeline_status",
    "training_eligibility",
    "ml_label",
    "label_verified",
    "label_source",
    "original_report_ids",
    "explicit_report_ids",
    "range_report_ids",
    "unresolved_report_ids",
    "supporting_report_ids",
    "supporting_report_count",
    "earliest_report_published",
    "latest_report_published",
    "days_before_earliest_report",
]


# ============================================================
# 3. CALCULATE FEATURE AVAILABILITY
# ============================================================

def is_present(value):
    text = str(value).strip()

    return text.lower() not in {
        "",
        "nan",
        "nat",
        "null",
        "none",
    }


audit_rows = []
record_checks = df[
    ["normalized_name", "version", "training_eligibility"]
].copy()

for feature, details in FEATURES.items():

    if feature not in df.columns:
        audit_rows.append({
            "feature": feature,
            "category": details["category"],
            "role": details["role"],
            "temporal_status": details["temporal_status"],
            "available_count": 0,
            "missing_count": len(df),
            "availability_percent": 0.0,
            "column_exists": False,
        })

        record_checks[f"{feature}_present"] = False
        continue

    present = df[feature].map(is_present)

    available_count = int(present.sum())
    missing_count = len(df) - available_count

    availability_percent = round(
        100 * available_count / len(df),
        2,
    ) if len(df) else 0.0

    audit_rows.append({
        "feature": feature,
        "category": details["category"],
        "role": details["role"],
        "temporal_status": details["temporal_status"],
        "available_count": available_count,
        "missing_count": missing_count,
        "availability_percent": availability_percent,
        "column_exists": True,
    })

    record_checks[f"{feature}_present"] = (
        present.values
    )


# ============================================================
# 4. CHECK SIMPLE DERIVED FEATURES
# ============================================================

# These features can be computed from the package name
# without downloading or executing package artifacts.

record_checks["name_length"] = (
    df["normalized_name"].astype(str).str.len()
)

record_checks["hyphen_count"] = (
    df["normalized_name"].astype(str)
    .str.count("-")
)

record_checks["digit_count"] = (
    df["normalized_name"].astype(str)
    .str.count(r"\d")
)

record_checks["name_has_digits"] = (
    record_checks["digit_count"] > 0
)

record_checks["summary_length"] = (
    df["summary"].astype(str).str.len()
    if "summary" in df.columns
    else 0
)

# Note: missing summaries become zero length.
# A missing-summary indicator should also be retained.


# ============================================================
# 5. SAVE CSV OUTPUTS
# ============================================================

audit_df = pd.DataFrame(audit_rows)

audit_df.to_csv(
    OUTPUT,
    index=False,
    encoding="utf-8-sig",
)

record_checks.to_csv(
    RECORD_OUTPUT,
    index=False,
    encoding="utf-8-sig",
)


# ============================================================
# 6. GENERATE SUMMARY REPORT
# ============================================================

summary = [
    "TYPOSQUATSHIELD - PILOT FEATURE AVAILABILITY",
    "=" * 60,
    f"Total records: {len(df)}",
    f"Unique packages: "
    f"{df['normalized_name'].nunique()}",
    "",
    "FEATURE AVAILABILITY:",
]

for _, row in audit_df.iterrows():
    summary.append(
        f"{row['feature']}: "
        f"{row['available_count']}/{len(df)} "
        f"({row['availability_percent']}%)"
    )

summary.extend([
    "",
    "EXCLUDED FROM PREDICTIVE FEATURES:",
    ", ".join(EXCLUDED_FIELDS),
    "",
    "IMPORTANT:",
    "A field being present does not prove it was available",
    "at the time a user would have installed the package.",
    "Name-based features are available before installation.",
    "Historical metadata fields need temporal verification.",
    "OpenSSF evidence fields must not be ML inputs.",
    "This audit does not train or evaluate a classifier.",
])

REPORT.write_text(
    "\n".join(summary),
    encoding="utf-8",
)

print()
print("\n".join(summary))
print()
print("Saved feature audit:", OUTPUT)
print("Saved record checks:", RECORD_OUTPUT)
print("Saved report:", REPORT)
print()
print("Feature availability audit completed.")
