
from pathlib import Path
from collections import Counter
from math import log2
import re

import pandas as pd
from packaging.utils import canonicalize_name
from rapidfuzz.distance import (
    Levenshtein,
    DamerauLevenshtein,
)
from rapidfuzz import fuzz


# ============================================================
# TYPOSQUATSHIELD - PILOT FEATURE ENGINEERING
# ============================================================

BASE = Path(__file__).resolve().parent.parent

PILOT = BASE / "data" / "pilot_ml" / "pilot_all_219.csv"

LEGITIMATE = (
    BASE / "data" / "legitimate" /
    "legitimate_pypi_pilot_100.csv"
)

OUTPUT_DIR = BASE / "data" / "features"
REPORT_DIR = BASE / "reports"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT = OUTPUT_DIR / "pilot_features_219.csv"
SUMMARY = REPORT_DIR / "pilot_feature_engineering_summary.txt"


# ============================================================
# 1. HELPERS
# ============================================================

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


def missing(value):
    return str(value).strip().lower() in {
        "", "nan", "nat", "null", "none"
    }


def entropy(value):
    if not value:
        return 0.0

    counts = Counter(value)
    total = len(value)

    return round(
        -sum(
            (count / total) * log2(count / total)
            for count in counts.values()
        ),
        5,
    )


def name_features(name):
    name = canonicalize_name(name)

    return {
        "name_length": len(name),
        "digit_count": sum(c.isdigit() for c in name),
        "hyphen_count": name.count("-"),
        "has_digits": int(any(c.isdigit() for c in name)),
        "name_entropy": entropy(name),
        "name_token_count": len(
            [part for part in name.split("-") if part]
        ),
    }


def similarity_features(name, references):
    name = canonicalize_name(name)

    if not references:
        return {
            "max_name_similarity": None,
            "min_edit_distance": None,
            "damerau_distance": None,
            "closest_reference_name": "",
            "is_exact_reference_match": 0,
            "potential_typosquat": 0,
        }

    # Compare against every reference name.
    # Pilot size is small, so this is inexpensive.
    candidates = []

    for reference in references:
        similarity = fuzz.ratio(name, reference)
        edit_distance = Levenshtein.distance(
            name, reference
        )
        damerau_distance = DamerauLevenshtein.distance(
            name, reference
        )

        candidates.append((
            similarity,
            edit_distance,
            damerau_distance,
            reference,
        ))

    # Highest similarity first; then shortest edit distance.
    candidates.sort(
        key=lambda item: (
            -item[0],
            item[1],
            item[2],
            item[3],
        )
    )

    best = candidates[0]

    exact_match = int(name == best[3])

    # Experimental threshold only.
    potential_typosquat = int(
        exact_match == 0
        and best[1] <= 2
        and best[0] >= 75
    )

    return {
        "max_name_similarity": round(best[0], 3),
        "min_edit_distance": best[1],
        "damerau_distance": best[2],
        "closest_reference_name": best[3],
        "is_exact_reference_match": exact_match,
        "potential_typosquat": potential_typosquat,
    }


# ============================================================
# 2. LOAD INPUTS
# ============================================================

print("=" * 65)
print("TYPOSQUATSHIELD - PILOT FEATURE ENGINEERING")
print("=" * 65)

pilot = load_csv(PILOT)
legitimate = load_csv(LEGITIMATE)

required_pilot = {
    "package_name",
    "normalized_name",
    "version",
    "summary",
    "requires_python",
    "training_eligibility",
}

required_legitimate = {"package_name"}

for title, frame, required in [
    ("Pilot", pilot, required_pilot),
    ("Legitimate reference", legitimate, required_legitimate),
]:
    missing_columns = required - set(frame.columns)

    if missing_columns:
        raise ValueError(
            f"{title} missing columns: {sorted(missing_columns)}"
        )

if pilot.duplicated(
    ["normalized_name", "version"]
).any():
    raise ValueError(
        "Duplicate package-version records in pilot."
    )

references = sorted({
    canonicalize_name(name)
    for name in legitimate["package_name"]
    if not missing(name)
})

print("Pilot records:", len(pilot))
print("Unique pilot packages:", pilot["normalized_name"].nunique())
print("Reference package names:", len(references))


# ============================================================
# 3. ENGINEER FEATURES
# ============================================================

feature_rows = []

for _, row in pilot.iterrows():
    name = row["normalized_name"]

    features = {
        "package_name": row["package_name"],
        "normalized_name": name,
        "version": row["version"],
        "training_eligibility": row["training_eligibility"],
    }

    features.update(name_features(name))
    features.update(similarity_features(name, references))

    summary = row["summary"]
    requires_python = row["requires_python"]

    features["summary_missing"] = int(missing(summary))
    features["summary_length"] = (
        0 if missing(summary) else len(summary)
    )

    features["requires_python_missing"] = int(
        missing(requires_python)
    )

    # Preserve source timing for later leakage review.
    features["first_upload_time"] = row.get(
        "first_upload_time", ""
    )

    # The similarity reference is a current pilot list,
    # not a historical time-filtered reference set.
    features["similarity_reference_status"] = (
        "experimental_not_time_validated"
    )

    feature_rows.append(features)


# ============================================================
# 4. SAVE FEATURES
# ============================================================

feature_df = pd.DataFrame(feature_rows)

feature_df.to_csv(
    OUTPUT,
    index=False,
    encoding="utf-8-sig",
)

# ============================================================
# 5. VALIDATION
# ============================================================

if len(feature_df) != len(pilot):
    raise ValueError(
        "Feature engineering changed the row count."
    )

if feature_df.duplicated(
    ["normalized_name", "version"]
).any():
    raise ValueError(
        "Duplicate package-version records after engineering."
    )

feature_columns = [
    "name_length",
    "digit_count",
    "hyphen_count",
    "has_digits",
    "name_entropy",
    "name_token_count",
    "max_name_similarity",
    "min_edit_distance",
    "damerau_distance",
    "is_exact_reference_match",
    "potential_typosquat",
    "summary_missing",
    "summary_length",
    "requires_python_missing",
]

null_counts = (
    feature_df[feature_columns]
    .isna()
    .sum()
)

summary_lines = [
    "TYPOSQUATSHIELD - PILOT FEATURE ENGINEERING",
    "=" * 60,
    f"Total records: {len(feature_df)}",
    f"Unique packages: "
    f"{feature_df['normalized_name'].nunique()}",
    f"Reference names: {len(references)}",
    f"Duplicate package-version pairs: "
    f"{int(feature_df.duplicated(['normalized_name', 'version']).sum())}",
    "",
    "FEATURE NULL COUNTS:",
]

for feature, count in null_counts.items():
    summary_lines.append(
        f"{feature}: {int(count)}"
    )

summary_lines.extend([
    "",
    "IMPORTANT:",
    "Features are for pilot pipeline testing only.",
    "Similarity reference list is not historically validated.",
    "Similarity thresholds are experimental.",
    "No malware labels are assigned.",
    "No model training is performed.",
    "OpenSSF evidence fields are excluded from features.",
])

SUMMARY.write_text(
    "\n".join(summary_lines),
    encoding="utf-8",
)

print()
print("\n".join(summary_lines))
print()
print("Saved features:", OUTPUT)
print("Saved report:", SUMMARY)
print()
print("Pilot feature engineering completed.")
