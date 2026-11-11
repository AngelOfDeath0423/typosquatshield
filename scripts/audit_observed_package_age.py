
from pathlib import Path
import numpy as np
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/features/version_aware_combined_features.csv"

OUTPUT = BASE / "reports/age_feature_reliability_audit.csv"
REPORT = BASE / "reports/age_feature_reliability_report.txt"

GROUPS = [
    "openssf_exact_version_candidate",
    "presumed_legitimate",
]

AGE_COLUMN = "observed_package_age_days"

AGE_BUCKETS = [
    "missing",
    "under_1_hour",
    "1_to_24_hours",
    "1_to_7_days",
    "7_to_30_days",
    "30_to_365_days",
    "over_365_days",
]


def categorize_age(value):
    if pd.isna(value):
        return "missing"

    if value < 0:
        return "invalid_negative"

    if value < 1 / 24:
        return "under_1_hour"

    if value < 1:
        return "1_to_24_hours"

    if value < 7:
        return "1_to_7_days"

    if value < 30:
        return "7_to_30_days"

    if value <= 365:
        return "30_to_365_days"

    return "over_365_days"


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - OBSERVED PACKAGE AGE AUDIT")
    print("=" * 65)

    df = pd.read_csv(
        INPUT,
        dtype={"version": str},
    )

    required = [
        "normalized_name",
        "candidate_group",
        "matched_pair_id",
        "history_bucket",
        "has_prior_history",
        "prior_release_count",
        AGE_COLUMN,
        "days_since_previous_release",
        "prior_release_span_days",
    ]

    missing_columns = [
        col for col in required
        if col not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing columns: {missing_columns}"
        )

    if len(df) != 4410:
        raise ValueError(
            f"Expected 4410 records, found {len(df)}"
        )

    if df["normalized_name"].nunique() != 4410:
        raise ValueError("Package uniqueness check failed.")

    if df["matched_pair_id"].nunique() != 2205:
        raise ValueError("Matched-pair check failed.")

    if set(df["candidate_group"]) != set(GROUPS):
        raise ValueError("Unexpected candidate groups.")

    df[AGE_COLUMN] = pd.to_numeric(
        df[AGE_COLUMN],
        errors="raise",
    )

    df["has_prior_history"] = pd.to_numeric(
        df["has_prior_history"],
        errors="raise",
    )

    df["prior_release_count"] = pd.to_numeric(
        df["prior_release_count"],
        errors="raise",
    )

    if np.isinf(
        df[AGE_COLUMN].to_numpy(dtype=float)
    ).any():
        raise ValueError("Infinite age values detected.")

    if (df[AGE_COLUMN].dropna() < 0).any():
        raise ValueError("Negative age values detected.")

    if not df["has_prior_history"].isin([0, 1]).all():
        raise ValueError("Invalid history indicators.")

    # Check missingness consistency.
    no_history = df["has_prior_history"] == 0
    with_history = df["has_prior_history"] == 1

    missing_without_history = int(
        df.loc[no_history, AGE_COLUMN].isna().sum()
    )

    present_without_history = int(
        df.loc[no_history, AGE_COLUMN].notna().sum()
    )

    missing_with_history = int(
        df.loc[with_history, AGE_COLUMN].isna().sum()
    )

    present_with_history = int(
        df.loc[with_history, AGE_COLUMN].notna().sum()
    )

    df["age_bucket"] = df[AGE_COLUMN].apply(
        categorize_age
    )

    bucket_table = pd.crosstab(
        df["age_bucket"],
        df["candidate_group"],
    ).reindex(AGE_BUCKETS, fill_value=0)

    available = df[df[AGE_COLUMN].notna()].copy()

    statistics = (
        available.groupby("candidate_group")[AGE_COLUMN]
        .agg(["count", "mean", "median", "std", "min", "max"])
        .round(4)
    )

    quantiles = (
        available.groupby("candidate_group")[AGE_COLUMN]
        .quantile([0.25, 0.50, 0.75, 0.95, 0.99])
        .unstack()
        .round(4)
    )

    # Near-zero ages are particularly important.
    short_age = (
        available.assign(
            under_hour=available[AGE_COLUMN] < 1 / 24,
            under_day=available[AGE_COLUMN] < 1,
            over_year=available[AGE_COLUMN] > 365,
        )
        .groupby("candidate_group")
        .agg(
            records=(AGE_COLUMN, "size"),
            under_hour=("under_hour", "sum"),
            under_day=("under_day", "sum"),
            over_year=("over_year", "sum"),
        )
    )

    # Inspect matched pairs with the greatest age differences.
    pair_ages = df.pivot(
        index="matched_pair_id",
        columns="candidate_group",
        values=AGE_COLUMN,
    )

    both_available = pair_ages.dropna().copy()

    if len(both_available):
        both_available["absolute_age_difference_days"] = (
            both_available[GROUPS[0]]
            - both_available[GROUPS[1]]
        ).abs()

        largest_differences = (
            both_available.sort_values(
                "absolute_age_difference_days",
                ascending=False,
            )
            .head(20)
        )
    else:
        largest_differences = pd.DataFrame()

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    df.to_csv(OUTPUT, index=False)

    lines = [
        "TYPOSQUATSHIELD - OBSERVED PACKAGE AGE RELIABILITY",
        "=" * 65,
        f"Total records: {len(df)}",
        f"Packages with prior history: {with_history.sum()}",
        f"Packages without prior history: {no_history.sum()}",
        "",
        "AGE AVAILABILITY",
        f"Missing age without prior history: "
        f"{missing_without_history}",
        f"Present age without prior history: "
        f"{present_without_history}",
        f"Missing age with prior history: "
        f"{missing_with_history}",
        f"Present age with prior history: "
        f"{present_with_history}",
        "",
        "AGE BUCKET DISTRIBUTION",
        bucket_table.to_string(),
        "",
        "AGE STATISTICS BY GROUP",
        statistics.to_string(),
        "",
        "AGE QUANTILES BY GROUP",
        quantiles.to_string(),
        "",
        "SHORT AND LONG OBSERVED AGES",
        short_age.to_string(),
        "",
        "MATCHED PAIRS WITH LARGEST AGE DIFFERENCES",
        largest_differences.to_string(),
        "",
        "LIMITATIONS",
        "Age is measured from first observed historical record.",
        "It is not verified original package publication age.",
        "Historical timestamps may reflect collection artifacts.",
        "Missing ages may reflect incomplete source history.",
        "Candidate groups are provisional.",
        "No malware-detection conclusion can be drawn.",
        "No model training was performed.",
    ]

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print("\n".join(lines))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Age-feature reliability audit completed.")


if __name__ == "__main__":
    main()
