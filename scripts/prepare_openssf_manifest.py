
import pandas as pd
from pathlib import Path
from packaging.utils import canonicalize_name

# ============================================================
# 1. PROJECT PATHS
# ============================================================

# Script location:
# fyp-building-phase/scripts/prepare_openssf_manifest.py
#
# Main project folder:
# fyp-building-phase/

BASE = Path(__file__).resolve().parent.parent

# Input CSV
INPUT = (
    BASE
    / "data"
    / "labels"
    / "openssf_pypi_labels_reviewed.csv"
)

# Output CSV
OUTPUT = (
    BASE
    / "data"
    / "labels"
    / "openssf_pypi_label_manifest.csv"
)

# ============================================================
# 2. CHECK INPUT FILE
# ============================================================

print("=" * 60)
print("TYPOSQUATSHIELD - OPENSSF PYPI LABEL MANIFEST")
print("=" * 60)

print(f"\nProject directory: {BASE}")
print(f"Input file: {INPUT}")
print(f"Input file exists: {INPUT.exists()}")

if not INPUT.is_file():
    raise FileNotFoundError(
        f"Cannot find the reviewed OpenSSF CSV:\n{INPUT}"
    )

# ============================================================
# 3. LOAD REVIEWED DATASET
# ============================================================

df = pd.read_csv(
    INPUT,
    dtype=str,
    keep_default_na=False,
    encoding="utf-8-sig"
)

print(f"\nInput records: {len(df):,}")

required_columns = [
    "package_name",
    "report_id",
    "label_status",
    "published",
]

missing_columns = [
    col for col in required_columns
    if col not in df.columns
]

if missing_columns:
    raise ValueError(
        f"Missing required columns: {missing_columns}"
    )

# ============================================================
# 4. NORMALIZE PYPI PACKAGE NAMES
# ============================================================

# PEP 503 normalization:
# - Lowercase names
# - Treat runs of '.', '_' and '-' equivalently

df["normalized_name"] = (
    df["package_name"]
    .str.strip()
    .map(canonicalize_name)
)

# Remove rows with blank package names, if any
df = df[
    df["normalized_name"].str.strip() != ""
].copy()

print(
    "Unique normalized package names:",
    f"{df['normalized_name'].nunique():,}"
)

# ============================================================
# 5. DETERMINE PACKAGE-LEVEL REVIEW STATUS
# ============================================================

# If any report requires review, the entire package
# is flagged for review in this package-level manifest.
#
# These statuses are provisional and must not be treated
# as confirmed machine-learning ground-truth labels.

def overall_status(statuses):
    values = set(statuses)

    if "excluded_withdrawn" in values:
        return "excluded_withdrawn"

    if "needs_review" in values:
        return "needs_review"

    if values == {"candidate_malicious"}:
        return "candidate_malicious"

    return "needs_review"


# ============================================================
# 6. BUILD PACKAGE-LEVEL MANIFEST
# ============================================================

manifest = (
    df.groupby("normalized_name", as_index=False)
    .agg(
        package_name=("package_name", "first"),

        report_ids=(
            "report_id",
            lambda values: ";".join(
                sorted(set(v for v in values if v.strip()))
            )
        ),

        report_count=("report_id", "nunique"),

        label_status=("label_status", overall_status),

        first_report_date=("published", "min"),

        last_report_date=("published", "max"),
    )
)

# Record the source of the labels
manifest["label_source"] = "OpenSSF malicious-packages"

# These are review statuses, not verified binary labels.
manifest["label_verified"] = False

# Arrange columns in a clear order
manifest = manifest[
    [
        "package_name",
        "normalized_name",
        "report_ids",
        "report_count",
        "first_report_date",
        "last_report_date",
        "label_source",
        "label_status",
        "label_verified",
    ]
]

# ============================================================
# 7. SAVE THE MANIFEST
# ============================================================

OUTPUT.parent.mkdir(
    parents=True,
    exist_ok=True
)

manifest.to_csv(
    OUTPUT,
    index=False,
    encoding="utf-8-sig"
)

# ============================================================
# 8. VALIDATE THE OUTPUT
# ============================================================

print("\n" + "=" * 60)
print("MANIFEST VALIDATION")
print("=" * 60)

print(f"\nInput records: {len(df):,}")
print(f"Manifest packages: {len(manifest):,}")

duplicate_count = manifest[
    "normalized_name"
].duplicated().sum()

print(f"Duplicate normalized names: {duplicate_count}")

print("\n--- Review status breakdown ---")
print(
    manifest["label_status"].value_counts().to_string()
)

print("\n--- Missing values ---")
for column in [
    "package_name",
    "normalized_name",
    "report_ids",
]:
    missing = manifest[column].eq("").sum()
    print(f"{column}: {missing}")

print("\n--- Sample manifest records ---")
print(
    manifest[
        [
            "package_name",
            "report_count",
            "label_status",
        ]
    ].head(10).to_string(index=False)
)

print("\n" + "=" * 60)
print("MANIFEST PREPARATION COMPLETED")
print("=" * 60)

print(f"\nSaved to:\n{OUTPUT}")
