
from pathlib import Path
import re

import numpy as np
import pandas as pd
from packaging.version import Version, InvalidVersion

BASE = Path(__file__).resolve().parent.parent

INPUT = (
    BASE / "data/features/version_aware_reputation_features.csv"
)

OUTPUT = (
    BASE / "data/features/version_aware_metadata_reputation.csv"
)

REPORT = (
    BASE / "reports/version_aware_metadata_feature_report.txt"
)

METADATA_FEATURES = [
    "name_length",
    "name_separator_count",
    "name_digit_count",
    "version_is_prerelease",
    "summary_length",
    "summary_word_count",
    "summary_missing",
    "requires_python_missing",
]

REPUTATION_FEATURES = [
    "prior_release_count",
    "has_prior_history",
    "observed_package_age_days",
    "days_since_previous_release",
    "prior_release_span_days",
]


def is_missing(value):
    if pd.isna(value):
        return True

    return not str(value).strip()


def is_prerelease(value):
    if is_missing(value):
        return 0

    try:
        return int(Version(str(value)).is_prerelease)
    except InvalidVersion:
        return 0


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - VERSION-AWARE METADATA FEATURES")
    print("=" * 65)

    df = pd.read_csv(
        INPUT,
        dtype={
            "normalized_name": str,
            "version": str,
        },
    )

    required = [
        "normalized_name",
        "version",
        "first_upload_time",
        "candidate_group",
        "matched_pair_id",
        "summary",
        "requires_python",
    ] + REPUTATION_FEATURES

    missing = sorted(set(required) - set(df.columns))

    if missing:
        raise ValueError(f"Missing columns: {missing}")

    if len(df) != 4410:
        raise ValueError(
            f"Expected 4410 records, found {len(df)}"
        )

    if df["normalized_name"].duplicated().any():
        raise ValueError("Duplicate package names.")

    if df["matched_pair_id"].nunique() != 2205:
        raise ValueError("Unexpected matched-pair count.")

    names = df["normalized_name"].fillna("").astype(str)

    summaries = df["summary"].fillna("").astype(str)
    summaries = summaries.str.strip()

    df["name_length"] = names.str.len()

    df["name_separator_count"] = names.str.count(r"[-_.]")

    df["name_digit_count"] = names.str.count(r"\d")

    df["version_is_prerelease"] = (
        df["version"].apply(is_prerelease)
    )

    df["summary_length"] = summaries.str.len()

    df["summary_word_count"] = summaries.apply(
        lambda text: len(text.split()) if text else 0
    )

    df["summary_missing"] = (
        df["summary"].apply(is_missing).astype(int)
    )

    df["requires_python_missing"] = (
        df["requires_python"]
        .apply(is_missing)
        .astype(int)
    )

    for feature in METADATA_FEATURES:
        values = pd.to_numeric(df[feature], errors="coerce")

        if values.isna().any():
            raise ValueError(
                f"Invalid metadata values in {feature}"
            )

        if (values < 0).any():
            raise ValueError(
                f"Negative metadata values in {feature}"
            )

    # Verify that reputation features are preserved.
    for feature in REPUTATION_FEATURES:
        if feature not in df.columns:
            raise ValueError(
                f"Missing reputation feature: {feature}"
            )

    if df[REPUTATION_FEATURES[:2]].isna().any().any():
        raise ValueError(
            "Missing prior-count/history indicators."
        )

    summary = (
        df.groupby("candidate_group")[METADATA_FEATURES]
        .mean()
        .round(4)
    )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    df.to_csv(OUTPUT, index=False)

    lines = [
        "TYPOSQUATSHIELD - VERSION-AWARE METADATA REPORT",
        "=" * 65,
        f"Input records: {len(df)}",
        f"Output records: {len(df)}",
        f"Unique packages: {df['normalized_name'].nunique()}",
        f"Matched pairs: {df['matched_pair_id'].nunique()}",
        f"Metadata features: {len(METADATA_FEATURES)}",
        f"Reputation features preserved: "
        f"{len(REPUTATION_FEATURES)}",
        "",
        "METADATA FEATURE MEANS BY GROUP",
        summary.to_string(),
        "",
        "FEATURE LIST",
        *METADATA_FEATURES,
        "",
        "VALIDATION",
        "Package uniqueness: PASS",
        "Matched-pair count: PASS",
        "Metadata feature validity: PASS",
        "Reputation feature preservation: PASS",
        "",
        "LIMITATIONS",
        "Candidate groups remain provisional.",
        "Metadata availability at assessment time",
        "has not been independently verified.",
        "Invalid version strings are assigned",
        "version_is_prerelease=0 and need separate review.",
        "No ML training performed.",
    ]

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print("\n".join(lines))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Version-aware metadata features completed.")


if __name__ == "__main__":
    main()
