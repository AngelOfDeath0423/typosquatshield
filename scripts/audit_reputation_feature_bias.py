
from pathlib import Path
import numpy as np
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/features/version_aware_reputation_features.csv"
OUTPUT = BASE / "reports/reputation_feature_bias_audit.txt"

FEATURES = [
    "prior_release_count",
    "observed_package_age_days",
    "days_since_previous_release",
    "prior_release_span_days",
]


def main():
    df = pd.read_csv(INPUT)

    if len(df) != 4410:
        raise ValueError("Unexpected record count.")

    if df["normalized_name"].duplicated().any():
        raise ValueError("Duplicate package names.")

    for feature in FEATURES:
        values = df[feature].dropna()

        if not np.isfinite(values).all():
            raise ValueError(f"Non-finite values: {feature}")

        if (values < 0).any():
            raise ValueError(f"Negative values: {feature}")

    prior = df[df["has_prior_history"] == 1].copy()

    if prior[FEATURES].isna().any().any():
        raise ValueError("Missing values among prior-history records.")

    lines = [
        "TYPOSQUATSHIELD - REPUTATION FEATURE BIAS AUDIT",
        "=" * 65,
        f"Total packages: {len(df)}",
        f"Packages with prior history: {len(prior)}",
        "",
        "PRIOR HISTORY BY GROUP AND BUCKET",
        pd.crosstab(
            df["history_bucket"],
            df["candidate_group"],
        ).to_string(),
        "",
    ]

    for feature in FEATURES:
        lines.append(f"FEATURE: {feature}")

        # Age and interval features are only meaningful
        # for packages with prior observed history.
        subset = (
            df if feature == "prior_release_count"
            else prior
        )

        stats = subset.groupby("candidate_group")[
            feature
        ].agg([
            "count",
            "mean",
            "median",
            "std",
            "min",
            "max",
        ])

        quantiles = subset.groupby("candidate_group")[
            feature
        ].quantile([0.25, 0.75, 0.95, 0.99]).unstack()

        lines.extend([
            stats.round(3).to_string(),
            "",
            "QUANTILES (25%, 75%, 95%, 99%)",
            quantiles.round(3).to_string(),
            "",
        ])

    prior["previous_within_hour"] = (
        prior["days_since_previous_release"] < 1 / 24
    )

    prior["previous_within_day"] = (
        prior["days_since_previous_release"] < 1
    )

    short_intervals = prior.groupby("candidate_group").agg(
        packages=("normalized_name", "count"),
        within_hour=("previous_within_hour", "sum"),
        within_day=("previous_within_day", "sum"),
    )

    lines.extend([
        "SHORT RELEASE INTERVALS",
        short_intervals.to_string(),
        "",
        "LIMITATIONS",
        "These are observed version-record timestamps.",
        "Short intervals may reflect release automation,",
        "historical aggregation, or collection artifacts.",
        "The groups have provisional labels.",
        "No causal security conclusions are established.",
        "No model training was performed.",
    ])

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print("\n".join(lines))
    print()
    print("Saved:", OUTPUT)
    print("[SUCCESS] Reputation bias audit completed.")


if __name__ == "__main__":
    main()
