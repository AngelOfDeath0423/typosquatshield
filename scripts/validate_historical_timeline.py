
from pathlib import Path
import pandas as pd


# ============================================================
# TYPOSQUATSHIELD - HISTORICAL TIMELINE VALIDATION
# ============================================================

BASE = Path(__file__).resolve().parent.parent

HISTORICAL = (
    BASE / "data" / "audit" /
    "openssf_version_evaluation_100.csv"
)

ORIGINAL_AUDIT = (
    BASE / "data" / "audit" /
    "openssf_original_report_audit_100.csv"
)

OPENSSF = (
    BASE / "data" / "labels" /
    "openssf_pypi_labels_raw.csv"
)

OUTPUT = (
    BASE / "data" / "audit" /
    "historical_timeline_validation_100.csv"
)

REPORT = (
    BASE / "reports" /
    "historical_timeline_validation_summary.txt"
)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
REPORT.parent.mkdir(parents=True, exist_ok=True)


# ============================================================
# 1. HELPER FUNCTIONS
# ============================================================

def parse_date(value):
    text = str(value).strip()

    if text.lower() in ("", "nan", "nat", "null", "none"):
        return pd.NaT

    # BigQuery timestamps commonly end in " UTC".
    if text.endswith(" UTC"):
        text = text[:-4] + "+00:00"

    return pd.to_datetime(
        text,
        utc=True,
        errors="coerce",
    )


def report_ids_from_cell(value):
    if not str(value).strip():
        return set()

    return {
        item.strip()
        for item in str(value).split(";")
        if item.strip()
    }


def find_column(frame, candidates):
    for column in candidates:
        if column in frame.columns:
            return column

    raise ValueError(
        f"Could not find any of these columns: {candidates}"
    )


def load_csv(path):
    if not path.exists():
        raise FileNotFoundError(
            f"Required file not found: {path}"
        )

    return pd.read_csv(
        path,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )


# ============================================================
# 2. LOAD DATASETS
# ============================================================

print("=" * 65)
print("TYPOSQUATSHIELD - HISTORICAL TIMELINE VALIDATION")
print("=" * 65)

historical = load_csv(HISTORICAL)
audit = load_csv(ORIGINAL_AUDIT)
openssf = load_csv(OPENSSF)

print("Historical records:", len(historical))
print("Original audit records:", len(audit))
print("Raw OpenSSF rows:", len(openssf))


# ============================================================
# 3. VALIDATE REQUIRED COLUMNS
# ============================================================

required_historical = {
    "package_name",
    "normalized_name",
    "version",
    "evidence_status",
}

required_audit = {
    "normalized_name",
    "version",
    "original_report_status",
    "explicit_report_ids",
    "range_report_ids",
}

required_openssf = {
    "report_id",
    "published",
}

for title, frame, required in [
    ("Historical", historical, required_historical),
    ("Original audit", audit, required_audit),
    ("OpenSSF", openssf, required_openssf),
]:
    missing = required - set(frame.columns)

    if missing:
        raise ValueError(
            f"{title} dataset is missing columns: {missing}"
        )

upload_column = find_column(
    historical,
    ["first_upload_time", "upload_time"],
)


# ============================================================
# 4. BUILD OPENSSF REPORT PUBLICATION LOOKUP
# ============================================================

# A report ID can appear in multiple CSV rows.
# It must have one consistent publication date.

report_dates = {}

for report_id, group in openssf.groupby("report_id"):
    parsed_dates = set()

    for value in group["published"]:
        date = parse_date(value)

        if pd.notna(date):
            parsed_dates.add(date)

    if len(parsed_dates) == 1:
        report_dates[report_id] = next(
            iter(parsed_dates)
        )
    else:
        report_dates[report_id] = pd.NaT

print("OpenSSF report IDs:", len(report_dates))


# ============================================================
# 5. MERGE HISTORICAL RECORDS WITH ORIGINAL AUDIT
# ============================================================

keys = [
    "normalized_name",
    "version",
]

# Check for duplicate package-version combinations.
for title, frame in [
    ("Historical", historical),
    ("Original audit", audit),
]:
    duplicate_count = int(
        frame.duplicated(keys).sum()
    )

    if duplicate_count:
        raise ValueError(
            f"{title} has {duplicate_count} duplicate "
            "package-version combinations."
        )


audit_columns = [
    "normalized_name",
    "version",
    "original_report_status",
    "explicit_report_ids",
    "range_report_ids",
]

# IMPORTANT FIX:
# Both CSV files may contain explicit_report_ids or
# range_report_ids. Remove overlapping columns from
# the historical dataframe before merging.

overlapping_columns = [
    column
    for column in audit_columns
    if column not in keys
    and column in historical.columns
]

historical_for_merge = historical.drop(
    columns=overlapping_columns
)

merged = historical_for_merge.merge(
    audit[audit_columns],
    on=keys,
    how="left",
    validate="one_to_one",
    indicator=True,
)

# Ensure every historical row matched an original audit row.
unmatched_count = int(
    (merged["_merge"] != "both").sum()
)

if unmatched_count:
    raise ValueError(
        f"{unmatched_count} historical records have "
        "no matching original audit record."
    )

# Check that the previous classifications agree with
# the original JSON audit classifications.
status_mismatches = int(
    (
        merged["evidence_status"]
        != merged["original_report_status"]
    ).sum()
)

if status_mismatches:
    raise ValueError(
        f"{status_mismatches} evidence classifications "
        "disagree with the original OpenSSF audit."
    )

print("Merged records:", len(merged))
print("Evidence status disagreements:", status_mismatches)


# ============================================================
# 6. VALIDATE HISTORICAL TIMELINES
# ============================================================

results = []

for _, row in merged.iterrows():
    package_name = row["package_name"]
    normalized_name = row["normalized_name"]
    version = row["version"]
    evidence_status = row["evidence_status"]

    upload_date = parse_date(
        row[upload_column]
    )

    # Only consider reports that actually support
    # the affected-version classification.

    if evidence_status == "explicit_version_match":
        supporting_ids = report_ids_from_cell(
            row["explicit_report_ids"]
        )

    elif evidence_status == "range_affected_candidate":
        supporting_ids = report_ids_from_cell(
            row["range_report_ids"]
        )

    else:
        supporting_ids = set()

    valid_dates = []
    missing_date_ids = []

    for report_id in sorted(supporting_ids):
        report_date = report_dates.get(
            report_id,
            pd.NaT,
        )

        if pd.isna(report_date):
            missing_date_ids.append(report_id)
        else:
            valid_dates.append(report_date)

    earliest_report = (
        min(valid_dates)
        if valid_dates
        else pd.NaT
    )

    latest_report = (
        max(valid_dates)
        if valid_dates
        else pd.NaT
    )

    # Determine timeline classification.

    if pd.isna(upload_date):
        timeline_status = "invalid_upload_date"

    elif not supporting_ids:
        timeline_status = (
            "no_version_level_report_evidence"
        )

    elif missing_date_ids or not valid_dates:
        timeline_status = "missing_report_date"

    elif all(
        upload_date < date
        for date in valid_dates
    ):
        timeline_status = (
            "uploaded_before_all_reports"
        )

    elif all(
        upload_date == date
        for date in valid_dates
    ):
        timeline_status = (
            "same_timestamp_as_reports"
        )

    elif all(
        upload_date > date
        for date in valid_dates
    ):
        timeline_status = (
            "uploaded_after_all_reports"
        )

    else:
        timeline_status = "mixed_report_timeline"

    days_before_report = ""

    if (
        pd.notna(upload_date)
        and pd.notna(earliest_report)
    ):
        days_before_report = round(
            (
                earliest_report - upload_date
            ).total_seconds() / 86400,
            2,
        )

    results.append({
        "package_name": package_name,
        "normalized_name": normalized_name,
        "version": version,
        "evidence_status": evidence_status,
        "first_upload_time": (
            upload_date.isoformat()
            if pd.notna(upload_date)
            else ""
        ),
        "supporting_report_ids": ";".join(
            sorted(supporting_ids)
        ),
        "supporting_report_count": len(
            supporting_ids
        ),
        "earliest_report_published": (
            earliest_report.isoformat()
            if pd.notna(earliest_report)
            else ""
        ),
        "latest_report_published": (
            latest_report.isoformat()
            if pd.notna(latest_report)
            else ""
        ),
        "days_before_earliest_report": (
            days_before_report
        ),
        "timeline_status": timeline_status,
        "missing_date_report_ids": ";".join(
            missing_date_ids
        ),
        "label_verified": False,
    })


# ============================================================
# 7. SAVE VALIDATION CSV
# ============================================================

result_df = pd.DataFrame(results)

result_df.to_csv(
    OUTPUT,
    index=False,
    encoding="utf-8-sig",
)

status_counts = (
    result_df["timeline_status"].value_counts()
)


# ============================================================
# 8. GENERATE SUMMARY REPORT
# ============================================================

statuses = [
    "uploaded_before_all_reports",
    "uploaded_after_all_reports",
    "same_timestamp_as_reports",
    "mixed_report_timeline",
    "missing_report_date",
    "invalid_upload_date",
    "no_version_level_report_evidence",
]

summary = [
    "TYPOSQUATSHIELD - HISTORICAL TIMELINE VALIDATION",
    "=" * 60,
    f"Historical records: {len(result_df)}",
    f"Unique packages: "
    f"{result_df['normalized_name'].nunique()}",
    "",
    "TIMELINE STATUS COUNTS:",
]

for status in statuses:
    summary.append(
        f"{status}: {int(status_counts.get(status, 0))}"
    )

summary.extend([
    "",
    "INTERPRETATION:",
    "Only supporting OpenSSF reports are used.",
    "Unmatched versions are not assigned benign labels.",
    "Upload before publication is not malware proof.",
    "Upload after publication requires investigation.",
    "Historical feature availability needs further review.",
    "No labels are automatically marked verified.",
])

REPORT.write_text(
    "\n".join(summary),
    encoding="utf-8",
)

print()
print("\n".join(summary))
print()
print("Saved CSV:", OUTPUT)
print("Saved report:", REPORT)
print()
print("Timeline validation completed.")
