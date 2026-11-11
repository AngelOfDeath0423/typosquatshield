
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/features/year_matched_features.csv"
REPORT = BASE / "reports/year_matched_feature_audit.txt"
OUTPUT = BASE / "data/features/year_matched_feature_statistics.csv"

FEATURES = [
    "name_length",
    "name_separator_count",
    "name_digit_count",
    "version_is_prerelease",
    "summary_length",
    "summary_word_count",
    "summary_missing",
    "requires_python_missing",
    "requires_python_specified",
]


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - FEATURE QUALITY AUDIT")
    print("=" * 65)

    df = pd.read_csv(INPUT)

    if len(df) != 4510:
        raise ValueError("Unexpected dataset size.")

    if df["normalized_name"].duplicated().any():
        raise ValueError("Duplicate package names detected.")

    if df[FEATURES].isna().any().any():
        raise ValueError("Missing numeric feature values.")

    grouped = df.groupby("candidate_group")[FEATURES]

    statistics = grouped.agg(
        ["mean", "median", "std", "min", "max"]
    )

    statistics.to_csv(OUTPUT)

    report = [
        "TYPOSQUATSHIELD - FEATURE QUALITY AUDIT",
        "=" * 65,
        f"Records: {len(df)}",
        f"Unique packages: {df['normalized_name'].nunique()}",
        f"Features: {len(FEATURES)}",
        "",
        "FEATURE MEANS BY CANDIDATE GROUP:",
        grouped.mean().round(3).to_string(),
        "",
        "FEATURE MEDIANS BY CANDIDATE GROUP:",
        grouped.median().to_string(),
        "",
        "MISSING METADATA RATES:",
    ]

    for group, subset in df.groupby("candidate_group"):
        report.extend([
            f"{group}:",
            f"  Missing summary: "
            f"{subset['summary_missing'].mean():.2%}",
            f"  Missing requires_python: "
            f"{subset['requires_python_missing'].mean():.2%}",
        ])

    report.extend([
        "",
        "REDUNDANCY CHECK:",
        "requires_python_specified is the inverse of",
        "requires_python_missing; retain only one for modeling.",
        "",
        "LIMITATIONS:",
        "Differences between groups may reflect selection bias.",
        "OpenSSF candidates are not verified malware labels.",
        "Presumed legitimate packages are not verified benign.",
        "Feature quality alone does not validate model accuracy.",
    ])

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    REPORT.write_text(
        "\n".join(report),
        encoding="utf-8",
    )

    print("\n".join(report))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Feature audit completed.")


if __name__ == "__main__":
    main()
