
from pathlib import Path
import pandas as pd
from packaging.utils import canonicalize_name

# ============================================================
# TYPOSQUATSHIELD - BUILD PILOT ML DATASET
# ============================================================

BASE = Path(__file__).resolve().parent.parent

HISTORICAL = (
    BASE / "data" / "audit" /
    "bigquery_versions_100.csv"
)

EVIDENCE = (
    BASE / "data" / "audit" /
    "openssf_original_report_audit_100.csv"
)

TIMELINE = (
    BASE / "data" / "audit" /
    "historical_timeline_validation_100.csv"
)

OUTPUT_DIR = BASE / "data" / "pilot_ml"
REPORT_DIR = BASE / "reports"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

ALL_OUTPUT = OUTPUT_DIR / "pilot_all_219.csv"
CANDIDATE_OUTPUT = (
    OUTPUT_DIR / "pilot_affected_candidates.csv"
)
REVIEW_OUTPUT = (
    OUTPUT_DIR / "pilot_requires_review.csv"
)
SUMMARY_OUTPUT = (
    REPORT_DIR / "pilot_ml_dataset_summary.txt"
)


# ============================================================
# 1. LOAD CSV FILES
# ============================================================

def load_csv(path):
    if not path.exists():
        raise FileNotFoundError(
            f"Missing required file: {path}"
        )

    return pd.read_csv(
        path,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )


def check_columns(frame, required, title):
    missing = set(required) - set(frame.columns)

    if missing:
        raise ValueError(
            f"{title} missing columns: {sorted(missing)}"
        )


def normalize_version(value):
    # Preserve the original version string.
    # Avoid collapsing potentially meaningful versions.
    return str(value).strip()


def add_keys(frame):
    frame = frame.copy()

    frame["normalized_name"] = (
        frame["package_name"]
        .astype(str)
        .map(canonicalize_name)
    )

    frame["version"] = (
        frame["version"]
        .map(normalize_version)
    )

    return frame


print("=" * 65)
print("TYPOSQUATSHIELD - PILOT ML DATASET BUILDER")
print("=" * 65)

historical = load_csv(HISTORICAL)
evidence = load_csv(EVIDENCE)
timeline = load_csv(TIMELINE)

check_columns(
    historical,
    [
        "package_name",
        "version",
        "first_upload_time",
    ],
    "Historical metadata",
)

check_columns(
    evidence,
    [
        "package_name",
        "version",
        "original_report_status",
        "original_report_ids",
        "explicit_report_ids",
        "range_report_ids",
    ],
    "Original OpenSSF audit",
)

check_columns(
    timeline,
    [
        "package_name",
        "version",
        "timeline_status",
        "supporting_report_ids",
        "earliest_report_published",
    ],
    "Timeline validation",
)

historical = add_keys(historical)
evidence = add_keys(evidence)
timeline = add_keys(timeline)

keys = ["normalized_name", "version"]

for title, frame in [
    ("Historical", historical),
    ("Evidence", evidence),
    ("Timeline", timeline),
]:
    duplicates = int(frame.duplicated(keys).sum())

    if duplicates:
        raise ValueError(
            f"{title} contains {duplicates} duplicate "
            "package-version records."
        )

print("Historical rows:", len(historical))
print("Evidence rows:", len(evidence))
print("Timeline rows:", len(timeline))


# ============================================================
# 2. PREPARE EVIDENCE AND TIMELINE COLUMNS
# ============================================================

evidence_subset = evidence[
    [
        "normalized_name",
        "version",
        "original_report_status",
        "original_report_ids",
        "explicit_report_ids",
        "range_report_ids",
        "unresolved_report_ids",
    ]
].copy()

timeline_subset = timeline[
    [
        "normalized_name",
        "version",
        "timeline_status",
        "supporting_report_ids",
        "supporting_report_count",
        "earliest_report_published",
        "latest_report_published",
        "days_before_earliest_report",
    ]
].copy()


# ============================================================
# 3. MERGE DATASETS
# ============================================================

merged = historical.merge(
    evidence_subset,
    on=keys,
    how="left",
    validate="one_to_one",
    indicator="evidence_merge",
)

if (merged["evidence_merge"] != "both").any():
    raise ValueError(
        "Some historical records are missing "
        "original OpenSSF evidence."
    )

merged = merged.drop(columns=["evidence_merge"])

merged = merged.merge(
    timeline_subset,
    on=keys,
    how="left",
    validate="one_to_one",
    indicator="timeline_merge",
)

if (merged["timeline_merge"] != "both").any():
    raise ValueError(
        "Some historical records are missing "
        "timeline validation."
    )

merged = merged.drop(columns=["timeline_merge"])


# ============================================================
# 4. DETERMINE TRAINING ELIGIBILITY
# ============================================================

def determine_eligibility(row):
    evidence_status = row["original_report_status"]
    timeline_status = row["timeline_status"]

    if evidence_status in (
        "explicit_version_match",
        "range_affected_candidate",
    ):
        if timeline_status == "uploaded_before_all_reports":
            return "candidate_for_review"

        if timeline_status in (
            "uploaded_after_all_reports",
            "same_timestamp_as_reports",
            "mixed_report_timeline",
        ):
            return "temporal_review_required"

        return "evidence_review_required"

    return "insufficient_version_evidence"


merged["training_eligibility"] = merged.apply(
    determine_eligibility,
    axis=1,
)

# IMPORTANT:
# These are NOT final binary malware labels.
merged["label_verified"] = False
merged["ml_label"] = ""
merged["label_source"] = "OpenSSF malicious-packages"
merged["metadata_source"] = "PyPI BigQuery historical export"


# ============================================================
# 5. ARRANGE FINAL COLUMNS
# ============================================================

preferred_columns = [
    "package_name",
    "normalized_name",
    "version",
    "first_upload_time",
    "summary",
    "requires_python",
    "distribution_file_count",
    "original_report_status",
    "timeline_status",
    "training_eligibility",
    "ml_label",
    "label_verified",
    "label_source",
    "metadata_source",
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

remaining_columns = [
    column
    for column in merged.columns
    if column not in preferred_columns
]

final_columns = [
    column
    for column in preferred_columns
    if column in merged.columns
] + remaining_columns

final_df = merged[final_columns].copy()


# ============================================================
# 6. SAVE DATASETS
# ============================================================

final_df.to_csv(
    ALL_OUTPUT,
    index=False,
    encoding="utf-8-sig",
)

candidates = final_df[
    final_df["training_eligibility"]
    == "candidate_for_review"
].copy()

candidates.to_csv(
    CANDIDATE_OUTPUT,
    index=False,
    encoding="utf-8-sig",
)

review = final_df[
    final_df["training_eligibility"]
    != "candidate_for_review"
].copy()

review.to_csv(
    REVIEW_OUTPUT,
    index=False,
    encoding="utf-8-sig",
)


# ============================================================
# 7. VALIDATE AND SUMMARIZE
# ============================================================

if len(final_df) != len(historical):
    raise ValueError(
        "Row count changed during merging."
    )

if final_df.duplicated(keys).any():
    raise ValueError(
        "Duplicate package-version keys in final dataset."
    )

counts = (
    final_df["training_eligibility"]
    .value_counts()
)

evidence_counts = (
    final_df["original_report_status"]
    .value_counts()
)

summary_lines = [
    "TYPOSQUATSHIELD - PILOT ML DATASET",
    "=" * 60,
    f"Total records: {len(final_df)}",
    f"Unique packages: "
    f"{final_df['normalized_name'].nunique()}",
    f"Duplicate package-version pairs: "
    f"{int(final_df.duplicated(keys).sum())}",
    "",
    "TRAINING ELIGIBILITY:",
]

for status in [
    "candidate_for_review",
    "temporal_review_required",
    "evidence_review_required",
    "insufficient_version_evidence",
]:
    summary_lines.append(
        f"{status}: {int(counts.get(status, 0))}"
    )

summary_lines.extend([
    "",
    "OPENSSF EVIDENCE:",
])

for status in [
    "explicit_version_match",
    "range_affected_candidate",
    "range_unresolved",
    "no_confirmed_affected_version",
]:
    summary_lines.append(
        f"{status}: {int(evidence_counts.get(status, 0))}"
    )

summary_lines.extend([
    "",
    "IMPORTANT:",
    "This is a pilot dataset, not a finalized ML training set.",
    "Candidate records still require label-quality review.",
    "Unmatched versions are not assumed benign.",
    "Post-publication versions require temporal review.",
    "Report IDs and publication dates are audit fields,",
    "not predictive ML features.",
    "No binary labels have been assigned.",
])

SUMMARY_OUTPUT.write_text(
    "\n".join(summary_lines),
    encoding="utf-8",
)

print()
print("\n".join(summary_lines))
print()
print("Saved complete dataset:", ALL_OUTPUT)
print("Saved candidates:", CANDIDATE_OUTPUT)
print("Saved review records:", REVIEW_OUTPUT)
print("Saved summary:", SUMMARY_OUTPUT)
print()
print("Pilot dataset build completed.")
