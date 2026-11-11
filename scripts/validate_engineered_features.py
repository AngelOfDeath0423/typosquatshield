
from pathlib import Path
from collections import Counter
from math import log2
import re

import pandas as pd
from packaging.utils import canonicalize_name
from rapidfuzz import fuzz
from rapidfuzz.distance import Levenshtein, DamerauLevenshtein


# ============================================================
# TYPOSQUATSHIELD - ENGINEERED FEATURE VALIDATION
# ============================================================

BASE = Path(__file__).resolve().parent.parent

FEATURES = BASE / "data" / "features" / "pilot_features_219.csv"
PILOT = BASE / "data" / "pilot_ml" / "pilot_all_219.csv"
LEGITIMATE = (
    BASE / "data" / "legitimate" /
    "legitimate_pypi_pilot_100.csv"
)

OUTPUT = (
    BASE / "data" / "audit" /
    "engineered_feature_validation.csv"
)

REPORT = (
    BASE / "reports" /
    "engineered_feature_validation_summary.txt"
)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
REPORT.parent.mkdir(parents=True, exist_ok=True)


# ============================================================
# 1. HELPERS
# ============================================================

def load_csv(path):
    if not path.exists():
        raise FileNotFoundError(
            f"Required file missing: {path}"
        )

    return pd.read_csv(
        path,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )


def is_missing(value):
    return str(value).strip().lower() in {
        "", "nan", "nat", "null", "none"
    }


def calculate_entropy(text):
    if not text:
        return 0.0

    counts = Counter(text)
    total = len(text)

    return round(
        -sum(
            (count / total) * log2(count / total)
            for count in counts.values()
        ),
        5,
    )


def as_float(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def as_int(value):
    try:
        number = float(value)
        if not number.is_integer():
            return None
        return int(number)
    except (ValueError, TypeError):
        return None


def expected_similarity(name, references):
    candidates = []

    for reference in references:
        candidates.append((
            fuzz.ratio(name, reference),
            Levenshtein.distance(name, reference),
            DamerauLevenshtein.distance(name, reference),
            reference,
        ))

    candidates.sort(
        key=lambda item: (
            -item[0],
            item[1],
            item[2],
            item[3],
        )
    )

    similarity, edit, damerau, closest = candidates[0]

    return {
        "max_name_similarity": round(similarity, 3),
        "min_edit_distance": edit,
        "damerau_distance": damerau,
        "closest_reference_name": closest,
        "is_exact_reference_match": int(name == closest),
        "potential_typosquat": int(
            name != closest
            and edit <= 2
            and similarity >= 75
        ),
    }


# ============================================================
# 2. LOAD DATASETS
# ============================================================

print("=" * 65)
print("TYPOSQUATSHIELD - FEATURE VALIDATION")
print("=" * 65)

features = load_csv(FEATURES)
pilot = load_csv(PILOT)
legitimate = load_csv(LEGITIMATE)

keys = ["normalized_name", "version"]

required_features = {
    *keys,
    "name_length",
    "digit_count",
    "hyphen_count",
    "has_digits",
    "name_entropy",
    "name_token_count",
    "max_name_similarity",
    "min_edit_distance",
    "damerau_distance",
    "closest_reference_name",
    "is_exact_reference_match",
    "potential_typosquat",
    "summary_missing",
    "summary_length",
    "requires_python_missing",
}

required_pilot = {
    *keys,
    "summary",
    "requires_python",
}

required_legitimate = {"package_name"}

for title, frame, required in [
    ("Features", features, required_features),
    ("Pilot", pilot, required_pilot),
    ("Legitimate", legitimate, required_legitimate),
]:
    missing_columns = required - set(frame.columns)
    if missing_columns:
        raise ValueError(
            f"{title} missing columns: {sorted(missing_columns)}"
        )

for title, frame in [
    ("Features", features),
    ("Pilot", pilot),
]:
    if frame.duplicated(keys).any():
        raise ValueError(
            f"{title} has duplicate package-version keys."
        )

if len(features) != len(pilot):
    raise ValueError(
        "Feature and pilot row counts do not match."
    )

references = sorted({
    canonicalize_name(name)
    for name in legitimate["package_name"]
    if not is_missing(name)
})

if not references:
    raise ValueError("Reference package list is empty.")

print("Feature records:", len(features))
print("Pilot records:", len(pilot))
print("Reference names:", len(references))


# ============================================================
# 3. MATCH FEATURE ROWS TO SOURCE RECORDS
# ============================================================

merged = features.merge(
    pilot[
        keys + ["summary", "requires_python"]
    ],
    on=keys,
    how="left",
    validate="one_to_one",
    indicator=True,
)

unmatched = int((merged["_merge"] != "both").sum())

if unmatched:
    raise ValueError(
        f"{unmatched} feature rows have no matching source row."
    )


# ============================================================
# 4. RECOMPUTE AND VALIDATE FEATURES
# ============================================================

results = []

for _, row in merged.iterrows():
    name = canonicalize_name(row["normalized_name"])

    expected = {
        "name_length": len(name),
        "digit_count": sum(c.isdigit() for c in name),
        "hyphen_count": name.count("-"),
        "has_digits": int(any(c.isdigit() for c in name)),
        "name_entropy": calculate_entropy(name),
        "name_token_count": len([
            token for token in name.split("-") if token
        ]),
        "summary_missing": int(
            is_missing(row["summary"])
        ),
        "summary_length": (
            0 if is_missing(row["summary"])
            else len(row["summary"])
        ),
        "requires_python_missing": int(
            is_missing(row["requires_python"])
        ),
    }

    expected.update(
        expected_similarity(name, references)
    )

    mismatches = []

    for column, expected_value in expected.items():
        actual_value = row[column]

        if isinstance(expected_value, float):
            actual_number = as_float(actual_value)

            if (
                actual_number is None
                or abs(actual_number - expected_value) > 0.001
            ):
                mismatches.append(column)

        elif isinstance(expected_value, int):
            if as_int(actual_value) != expected_value:
                mismatches.append(column)

        else:
            if str(actual_value) != str(expected_value):
                mismatches.append(column)

    results.append({
        "normalized_name": row["normalized_name"],
        "version": row["version"],
        "validation_pass": len(mismatches) == 0,
        "mismatch_count": len(mismatches),
        "mismatched_features": ";".join(mismatches),
    })


# ============================================================
# 5. INDEPENDENT KNOWN-EXAMPLE TESTS
# ============================================================

# These tests check expected mathematical behavior.
# They do not require 'requests' to be in the pilot
# legitimate reference list.

known_tests = {
    "levenshtein_requests_typo": (
        Levenshtein.distance(
            "requests", "reqeusts"
        ) == 2
    ),
    "damerau_requests_typo": (
        DamerauLevenshtein.distance(
            "requests", "reqeusts"
        ) == 1
    ),
    "exact_similarity": (
        fuzz.ratio("requests", "requests") == 100
    ),
    "nonnegative_distance": (
        Levenshtein.distance(
            "requests", "reqeusts"
        ) >= 0
    ),
    "normalized_package_name": (
        canonicalize_name("My_Package.Name")
        == "my-package-name"
    ),
}

# ============================================================
# 6. SAVE VALIDATION RESULTS
# ============================================================

validation_df = pd.DataFrame(results)

validation_df.to_csv(
    OUTPUT,
    index=False,
    encoding="utf-8-sig",
)

failed_rows = int(
    (~validation_df["validation_pass"]).sum()
)

known_failed = [
    name
    for name, passed in known_tests.items()
    if not passed
]

overall_pass = (
    failed_rows == 0
    and len(known_failed) == 0
)

summary = [
    "TYPOSQUATSHIELD - FEATURE VALIDATION",
    "=" * 60,
    f"Feature records: {len(features)}",
    f"Source records: {len(pilot)}",
    f"Reference names: {len(references)}",
    f"Failed feature rows: {failed_rows}",
    "",
    "KNOWN EXAMPLE TESTS:",
]

for name, passed in known_tests.items():
    summary.append(
        f"{name}: {'PASS' if passed else 'FAIL'}"
    )

summary.extend([
    "",
    f"OVERALL VALIDATION: "
    f"{'PASS' if overall_pass else 'FAIL'}",
    "",
    "IMPORTANT:",
    "This verifies consistency with feature definitions.",
    "It does not validate the reference list historically.",
    "It does not establish predictive effectiveness.",
    "No malicious or benign labels are assigned.",
])

REPORT.write_text(
    "\n".join(summary),
    encoding="utf-8",
)

print()
print("\n".join(summary))
print()
print("Saved validation CSV:", OUTPUT)
print("Saved summary:", REPORT)

if not overall_pass:
    raise SystemExit(
        "Feature validation failed. Review the CSV."
    )

print()
print("Feature validation completed successfully.")
