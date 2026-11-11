
from pathlib import Path
import pandas as pd

from typosquatting_similarity import load_reference_names
from engineer_typosquatting_features import calculate_features, FEATURES

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/features/version_aware_metadata_reputation.csv"
OUTPUT = BASE / "data/features/version_aware_combined_features.csv"
REPORT = BASE / "reports/version_aware_similarity_report.txt"

EXPECTED_RECORDS = 4410
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

REPUTATION_FEATURES = [
    "prior_release_count",
    "has_prior_history",
    "observed_package_age_days",
    "days_since_previous_release",
    "prior_release_span_days",
]


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - VERSION-AWARE SIMILARITY FEATURES")
    print("=" * 65)

    # Load the version-aware metadata and reputation dataset.
    df = pd.read_csv(
        INPUT,
        dtype={
            "normalized_name": str,
            "version": str,
        },
    )

    # Check required columns.
    required_columns = [
        "normalized_name",
        "version",
        "first_upload_time",
        "candidate_group",
        "matched_pair_id",
    ] + METADATA_FEATURES + REPUTATION_FEATURES

    missing_columns = [
        column for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    # Validate the existing dataset.
    if len(df) != EXPECTED_RECORDS:
        raise ValueError(
            f"Expected {EXPECTED_RECORDS} records, "
            f"found {len(df)}"
        )

    if df["normalized_name"].isna().any():
        raise ValueError("Missing package names.")

    if df["normalized_name"].duplicated().any():
        raise ValueError("Duplicate package names.")

    if df["matched_pair_id"].nunique() != EXPECTED_PAIRS:
        raise ValueError("Unexpected matched-pair count.")

    pair_counts = df.groupby("matched_pair_id").size()

    if not pair_counts.eq(2).all():
        raise ValueError(
            "Each matched pair must contain exactly 2 records."
        )

    group_counts = df.groupby("candidate_group").size()

    expected_groups = {
        "openssf_exact_version_candidate": EXPECTED_PAIRS,
        "presumed_legitimate": EXPECTED_PAIRS,
    }

    if group_counts.to_dict() != expected_groups:
        raise ValueError(
            f"Unexpected candidate-group counts: "
            f"{group_counts.to_dict()}"
        )

    pair_group_counts = (
        df.groupby("matched_pair_id")["candidate_group"]
        .nunique()
    )

    if not pair_group_counts.eq(2).all():
        raise ValueError(
            "Each matched pair must contain both candidate groups."
        )

    # Avoid duplicate similarity columns.
    existing_features = [
        feature for feature in FEATURES
        if feature in df.columns
    ]

    if existing_features:
        raise ValueError(
            f"Similarity features already exist: {existing_features}"
        )

    # Load the original curated reference package list.
    references = load_reference_names()

    if not references:
        raise ValueError("Reference package list is empty.")

    print(f"Input records: {len(df)}")
    print(f"Unique packages: {df['normalized_name'].nunique()}")
    print(f"Matched pairs: {df['matched_pair_id'].nunique()}")
    print(f"Reference packages loaded: {len(references)}")
    print()
    print("Calculating typosquatting similarity features...")

    # Use the SAME feature engineering logic as the
    # previously tested typosquatting feature script.
    feature_records = []

    for index, package_name in enumerate(
        df["normalized_name"], start=1
    ):
        features = calculate_features(
            package_name,
            references,
        )

        feature_records.append(features)

        if index % 1000 == 0:
            print(f"Processed {index}/{len(df)} packages")

    # Convert engineered features into a DataFrame.
    feature_df = pd.DataFrame(feature_records)

    # Validate generated similarity features.
    missing_features = [
        feature for feature in FEATURES
        if feature not in feature_df.columns
    ]

    if missing_features:
        raise ValueError(
            f"Missing similarity features: {missing_features}"
        )

    if feature_df[FEATURES].isna().any().any():
        raise ValueError(
            "Missing values in similarity features."
        )

    # Combine by row position.
    result = pd.concat(
        [
            df.reset_index(drop=True),
            feature_df[FEATURES].reset_index(drop=True),
        ],
        axis=1,
    )

    # Validate final output.
    if len(result) != EXPECTED_RECORDS:
        raise ValueError("Output record count changed.")

    if result["normalized_name"].duplicated().any():
        raise ValueError("Duplicate packages in output.")

    if result["matched_pair_id"].nunique() != EXPECTED_PAIRS:
        raise ValueError("Matched-pair count changed.")

    all_features = (
        METADATA_FEATURES
        + REPUTATION_FEATURES
        + FEATURES
    )

    if len(all_features) != 18:
        raise ValueError("Unexpected engineered feature count.")

    # Missing values are expected in age/interval features
    # when no earlier historical release was observed.
    nonnullable_features = METADATA_FEATURES + FEATURES + [
        "prior_release_count",
        "has_prior_history",
    ]

    if result[nonnullable_features].isna().any().any():
        raise ValueError(
            "Unexpected missing values in required features."
        )

    # Summarize typosquatting features by candidate group.
    similarity_summary = (
        result.groupby("candidate_group")[FEATURES]
        .mean()
        .round(4)
    )

    typo_counts = (
        result.groupby("candidate_group")[
            "typo_potential_match"
        ]
        .agg(["sum", "count"])
    )

    # Create output directories.
    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Save combined dataset.
    result.to_csv(
        OUTPUT,
        index=False,
    )

    # Generate report.
    lines = [
        "TYPOSQUATSHIELD - VERSION-AWARE SIMILARITY REPORT",
        "=" * 65,
        f"Input records: {len(df)}",
        f"Output records: {len(result)}",
        f"Unique packages: {result['normalized_name'].nunique()}",
        f"Matched pairs: {result['matched_pair_id'].nunique()}",
        f"Reference packages: {len(references)}",
        "",
        "ENGINEERED FEATURE COUNTS",
        f"Metadata features: {len(METADATA_FEATURES)}",
        f"Reputation features: {len(REPUTATION_FEATURES)}",
        f"Similarity features: {len(FEATURES)}",
        f"Total engineered features: {len(all_features)}",
        "",
        "SIMILARITY FEATURE MEANS BY GROUP",
        similarity_summary.to_string(),
        "",
        "POTENTIAL TYPO MATCHES BY GROUP",
        typo_counts.to_string(),
        "",
        "VALIDATION",
        "Input record count: PASS",
        "Package uniqueness: PASS",
        "Matched-pair count: PASS",
        "Both groups represented in every pair: PASS",
        "Similarity feature completeness: PASS",
        "Metadata/reputation columns preserved: PASS",
        "",
        "LIMITATIONS",
        "Reference list contains curated package names only.",
        "Historical reference availability is not verified.",
        "Similarity does not establish maliciousness.",
        "Candidate-group labels remain provisional.",
        "Historical metadata timing requires further review.",
        "No ML training performed.",
    ]

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print()
    print("\n".join(lines))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Version-aware similarity completed.")


if __name__ == "__main__":
    main()
