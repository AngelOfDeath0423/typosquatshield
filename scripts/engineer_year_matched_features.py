
from pathlib import Path
import pandas as pd
from packaging.version import Version, InvalidVersion

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/full/year_matched_ml_candidates.csv"
OUTPUT = BASE / "data/features/year_matched_features.csv"
REPORT = BASE / "reports/year_matched_feature_report.txt"

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


def is_prerelease(version):
    try:
        return int(Version(version).is_prerelease)
    except InvalidVersion:
        return 0


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - HISTORICAL FEATURE ENGINEERING")
    print("=" * 65)

    df = pd.read_csv(
        INPUT,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )

    required = [
        "normalized_name",
        "version",
        "summary",
        "requires_python",
        "candidate_group",
        "first_upload_time",
    ]

    missing = set(required) - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    if df["normalized_name"].duplicated().any():
        raise ValueError("Duplicate package names found.")

    if len(df) != 4510:
        raise ValueError(
            f"Expected 4510 records, found {len(df)}"
        )

    names = df["normalized_name"].str.strip()
    summaries = df["summary"].str.strip()
    python_requirements = df["requires_python"].str.strip()

    features = df[
        [
            "normalized_name",
            "version",
            "first_upload_time",
            "candidate_group",
        ]
    ].copy()

    # Preserve evidence provenance without assigning verified labels.
    for column in ["evidence_status", "ml_label", "label_verified"]:
        if column in df.columns:
            features[column] = df[column]

    features["name_length"] = names.str.len()
    features["name_separator_count"] = names.str.count("-")
    features["name_digit_count"] = names.str.count(r"\d")

    features["version_is_prerelease"] = (
        df["version"].apply(is_prerelease)
    )

    features["summary_length"] = summaries.str.len()
    features["summary_word_count"] = summaries.apply(
        lambda text: len(text.split())
    )
    features["summary_missing"] = (
        summaries.eq("").astype(int)
    )

    features["requires_python_missing"] = (
        python_requirements.eq("").astype(int)
    )
    features["requires_python_specified"] = (
        python_requirements.ne("").astype(int)
    )

    if features[FEATURES].isna().any().any():
        raise ValueError("Missing engineered feature values.")

    if not all(
        pd.api.types.is_numeric_dtype(features[col])
        for col in FEATURES
    ):
        raise ValueError("Non-numeric feature detected.")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    features.to_csv(
        OUTPUT,
        index=False,
        encoding="utf-8-sig",
    )

    report_lines = [
        "TYPOSQUATSHIELD - FEATURE ENGINEERING REPORT",
        "=" * 65,
        f"Input records: {len(df)}",
        f"Output records: {len(features)}",
        f"Unique packages: {features['normalized_name'].nunique()}",
        f"Engineered features: {len(FEATURES)}",
        "",
        "FEATURE LIST:",
        *FEATURES,
        "",
        "GROUP COUNTS:",
        features["candidate_group"].value_counts().to_string(),
        "",
        "LIMITATIONS:",
        "No final binary labels assigned.",
        "Candidate-group membership is provisional evidence.",
        "Historical metadata is not verified malware ground truth.",
        "Upload year is retained for auditing, not as an ML feature.",
        "Features are preliminary and do not yet include",
        "typosquatting similarity, reputation, or static analysis.",
        "Some metadata may reflect distribution-level aggregation.",
        "Assessment-time availability requires further validation.",
    ]

    REPORT.write_text(
        "\n".join(report_lines),
        encoding="utf-8",
    )

    print("\n".join(report_lines))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Feature engineering completed.")


if __name__ == "__main__":
    main()
