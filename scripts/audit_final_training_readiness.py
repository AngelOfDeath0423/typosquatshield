
from pathlib import Path
import numpy as np
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

DATA = BASE / "data/features/version_aware_combined_features.csv"
EVIDENCE = BASE / "data/full/training_label_eligibility_audit.csv"
SPLITS = BASE / "reports/version_aware_ml/split_membership.csv"

OUTPUT = BASE / "reports/final_training_readiness_audit.csv"
REPORT = BASE / "reports/final_training_readiness_report.txt"

KEY = ["normalized_name", "version"]

GROUPS = {
    "openssf_exact_version_candidate",
    "presumed_legitimate",
}

EXPECTED = 4410
EXPECTED_PAIRS = 2205

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

SIMILARITY_FEATURES = [
    "typo_min_edit_distance",
    "typo_max_similarity",
    "typo_potential_match",
    "typo_close_match_count",
    "typo_reference_length",
]

HISTORY_FEATURES = [
    "prior_release_count",
    "has_prior_history",
    "observed_package_age_days",
]

FEATURES = (
    METADATA_FEATURES
    + SIMILARITY_FEATURES
    + HISTORY_FEATURES
)


def parse_utc(series):
    return pd.to_datetime(
        series,
        errors="coerce",
        utc=True,
    )


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - FINAL TRAINING READINESS AUDIT")
    print("=" * 65)

    df = pd.read_csv(DATA, dtype={"version": str})
    evidence = pd.read_csv(
        EVIDENCE,
        dtype={"version": str},
    )
    splits = pd.read_csv(
        SPLITS,
        dtype={"version": str},
    )

    if len(df) != EXPECTED:
        raise ValueError(
            f"Expected {EXPECTED} records, found {len(df)}"
        )

    if df["normalized_name"].nunique() != EXPECTED:
        raise ValueError("Duplicate package names detected.")

    if df["matched_pair_id"].nunique() != EXPECTED_PAIRS:
        raise ValueError("Unexpected matched-pair count.")

    if set(df["candidate_group"]) != GROUPS:
        raise ValueError("Unexpected candidate groups.")

    missing_features = [
        col for col in FEATURES
        if col not in df.columns
    ]

    if missing_features:
        raise ValueError(
            f"Missing features: {missing_features}"
        )

    if df[KEY].isna().any().any():
        raise ValueError("Missing package/version identifiers.")

    if df.duplicated(KEY).any():
        raise ValueError("Duplicate package-version records.")

    # Verify matched pairs.
    pair_sizes = df.groupby("matched_pair_id").size()
    pair_groups = (
        df.groupby("matched_pair_id")["candidate_group"]
        .nunique()
    )

    if not pair_sizes.eq(2).all():
        raise ValueError("Invalid matched-pair sizes.")

    if not pair_groups.eq(2).all():
        raise ValueError("Invalid matched-pair composition.")

    # Parse provisional assessment timestamps.
    df["assessment_time"] = parse_utc(
        df["first_upload_time"]
    )

    invalid_assessment_times = int(
        df["assessment_time"].isna().sum()
    )

    # Validate historical reputation feature consistency.
    df["prior_release_count"] = pd.to_numeric(
        df["prior_release_count"],
        errors="coerce",
    )

    df["has_prior_history"] = pd.to_numeric(
        df["has_prior_history"],
        errors="coerce",
    )

    df["observed_package_age_days"] = pd.to_numeric(
        df["observed_package_age_days"],
        errors="coerce",
    )

    history_inconsistent = (
        (df["prior_release_count"] > 0)
        != (df["has_prior_history"] == 1)
    )

    history_inconsistent_count = int(
        history_inconsistent.sum()
    )

    negative_age_count = int(
        (df["observed_package_age_days"] < 0).sum()
    )

    age_missing_with_history = int(
        (
            (df["has_prior_history"] == 1)
            & df["observed_package_age_days"].isna()
        ).sum()
    )

    age_present_without_history = int(
        (
            (df["has_prior_history"] == 0)
            & df["observed_package_age_days"].notna()
        ).sum()
    )

    # Verify OpenSSF evidence at the exact package/version level.
    required_evidence = [
        "normalized_name",
        "version",
        "training_evidence_status",
        "exact_version_match",
    ]

    missing_evidence_cols = [
        col for col in required_evidence
        if col not in evidence.columns
    ]

    if missing_evidence_cols:
        raise ValueError(
            f"Missing evidence columns: {missing_evidence_cols}"
        )

    # Evidence records should be unique by package/version.
    if evidence.duplicated(KEY).any():
        raise ValueError(
            "Duplicate package-version evidence records. "
            "Review evidence aggregation before joining."
        )

    evidence_subset = evidence[
        KEY + [
            "training_evidence_status",
            "exact_version_match",
        ]
    ].copy()

    df = df.merge(
        evidence_subset,
        on=KEY,
        how="left",
        validate="one_to_one",
        suffixes=("", "_audit"),
    )

    positive = (
        df["candidate_group"]
        == "openssf_exact_version_candidate"
    )

    negative = (
        df["candidate_group"]
        == "presumed_legitimate"
    )

    status_column = (
        "training_evidence_status_audit"
        if "training_evidence_status_audit" in df.columns
        else "training_evidence_status"
    )

    match_column = (
        "exact_version_match_audit"
        if "exact_version_match_audit" in df.columns
        else "exact_version_match"
    )

    positive_status = df.loc[
        positive, status_column
    ]

    positive_evidence_missing = int(
        positive_status.isna().sum()
    )

    positive_status_counts = (
        positive_status.value_counts(dropna=False)
    )

    # Boolean values may be stored as strings in CSV.
    exact_match = (
        df[match_column]
        .astype("string")
        .str.lower()
        .eq("true")
        .fillna(False)
    )

    positive_not_exact = int(
        (positive & ~exact_match).sum()
    )

    positive_not_candidate_review = int(
        (
            positive
            & (
                df[status_column]
                != "candidate_training_review"
            )
        ).sum()
    )

    # Negative records are intentionally not assigned
    # verified benign status.
    negative_with_openssf_evidence = int(
        (
            negative
            & df[status_column].notna()
        ).sum()
    )

    # Verify train/test split membership.
    split_key = KEY + ["matched_pair_id"]

    if splits.duplicated(split_key).any():
        raise ValueError("Duplicate split records.")

    df = df.merge(
        splits[split_key + ["split"]],
        on=split_key,
        how="left",
        validate="one_to_one",
        suffixes=("", "_audit"),
    )

    split_column = (
        "split_audit"
        if "split_audit" in df.columns
        else "split"
    )

    missing_split = int(
        df[split_column].isna().sum()
    )

    split_leakage = int(
        (
            df.groupby("matched_pair_id")[split_column]
            .nunique()
            > 1
        ).sum()
    )

    # Check numerical feature availability.
    numeric_feature_missing = (
        df[FEATURES]
        .isna()
        .sum()
        .sort_values(ascending=False)
    )

    # Flag suspicious ages, not necessarily invalid ones.
    age_under_hour = int(
        (
            df["observed_package_age_days"].notna()
            & (
                df["observed_package_age_days"]
                < 1 / 24
            )
        ).sum()
    )

    age_over_year = int(
        (
            df["observed_package_age_days"] > 365
        ).sum()
    )

    checks = {
        "invalid_assessment_timestamps":
            invalid_assessment_times,
        "history_indicator_inconsistencies":
            history_inconsistent_count,
        "negative_observed_ages":
            negative_age_count,
        "age_missing_with_prior_history":
            age_missing_with_history,
        "age_present_without_prior_history":
            age_present_without_history,
        "positive_evidence_missing":
            positive_evidence_missing,
        "positive_not_exact_version":
            positive_not_exact,
        "positive_not_candidate_review":
            positive_not_candidate_review,
        "negative_with_openssf_evidence":
            negative_with_openssf_evidence,
        "missing_split_membership":
            missing_split,
        "matched_pair_split_leakage":
            split_leakage,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    df.to_csv(OUTPUT, index=False)

    lines = [
        "TYPOSQUATSHIELD - FINAL TRAINING READINESS REPORT",
        "=" * 65,
        f"Records: {len(df)}",
        f"Unique packages: {df['normalized_name'].nunique()}",
        f"Matched pairs: {df['matched_pair_id'].nunique()}",
        f"Candidate features: {len(FEATURES)}",
        "",
        "EVIDENCE STATUS FOR OPEnSSF CANDIDATES",
        positive_status_counts.to_string(),
        "",
        "READINESS CHECKS",
    ]

    for name, count in checks.items():
        lines.append(f"{name}: {count}")

    lines += [
        "",
        "NUMERIC FEATURE MISSINGNESS",
        numeric_feature_missing.to_string(),
        "",
        "AGE RELIABILITY FLAGS",
        f"Observed age under 1 hour: {age_under_hour}",
        f"Observed age over 365 days: {age_over_year}",
        "",
        "ASSESSMENT",
        "This audit checks internal dataset consistency.",
        "It does not verify original publication timestamps.",
        "It does not independently verify metadata provenance.",
        "It does not verify historical similarity references.",
        "It does not establish verified malware labels.",
        "It does not establish verified benign labels.",
        "It does not approve final model evaluation.",
    ]

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print("\n".join(lines))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)

    if any(count > 0 for count in checks.values()):
        print(
            "[REVIEW REQUIRED] Some readiness checks "
            "need investigation."
        )
    else:
        print(
            "[SUCCESS] Internal readiness checks passed."
        )


if __name__ == "__main__":
    main()
