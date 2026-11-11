
from pathlib import Path
import json
import pandas as pd

from backend.services.feature_service import (
    EXPECTED_FEATURES,
)
from scripts.model_inference import TyposquatShieldModel
from scripts.test_age_feature_sensitivity import DATA

BASE = Path(__file__).resolve().parent.parent

REPORT = (
    BASE / "reports" /
    "live_feature_compatibility_report.txt"
)

MODEL_METADATA = (
    BASE / "models" /
    "typosquatshield_model_metadata.json"
)

# Use the exact dataset used for model training.
TRAINING_DATA = Path(DATA)

FEATURES_TO_AUDIT = [
    "summary_length",
    "summary_word_count",
    "summary_missing",
    "requires_python_missing",
    "typo_min_edit_distance",
    "typo_max_similarity",
    "typo_potential_match",
    "typo_close_match_count",
    "typo_reference_length",
    "prior_release_count",
    "has_prior_history",
    "observed_package_age_days",
]


def load_training_data():
    if not TRAINING_DATA.exists():
        raise FileNotFoundError(
            f"Training dataset not found: {TRAINING_DATA}"
        )

    df = pd.read_csv(
        TRAINING_DATA,
        dtype={"version": str},
    )

    missing = [
        feature
        for feature in FEATURES_TO_AUDIT
        if feature not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing training features: {missing}"
        )

    return df


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - LIVE FEATURE COMPATIBILITY AUDIT")
    print("=" * 65)

    model_metadata = json.loads(
        MODEL_METADATA.read_text(
            encoding="utf-8"
        )
    )

    predictor = TyposquatShieldModel()

    model_features = model_metadata["features"]

    if model_features != predictor.features:
        raise ValueError(
            "Model feature metadata mismatch."
        )

    if model_features != EXPECTED_FEATURES:
        raise ValueError(
            "Live feature ordering differs from "
            "the exported model."
        )

    print("Model:", model_metadata["experiment"])
    print("Expected features:", len(model_features))

    df = load_training_data()

    print("Training feature table:", TRAINING_DATA)
    print("Training records:", len(df))

    if len(df) != 4410:
        raise ValueError(
            f"Unexpected training dataset size: {len(df)}"
        )

    report = [
        "TYPOSQUATSHIELD - LIVE FEATURE COMPATIBILITY AUDIT",
        "=" * 65,
        f"Model: {model_metadata['experiment']}",
        f"Expected features: {len(model_features)}",
        f"Training source: {TRAINING_DATA}",
        f"Training records: {len(df)}",
        "",
        "MODEL FEATURE ALIGNMENT",
        "Model metadata and inference feature order: PASS",
        "Model metadata and live feature order: PASS",
        "",
        "CANDIDATE GROUP DISTRIBUTION",
        df["candidate_group"].value_counts().to_string(),
        "",
        "HISTORICAL FEATURE DISTRIBUTIONS",
    ]

    for feature in FEATURES_TO_AUDIT:
        values = pd.to_numeric(
            df[feature],
            errors="coerce",
        )

        report.extend([
            "",
            f"Feature: {feature}",
            f"Missing: {int(values.isna().sum())}",
            f"Mean: {values.mean():.4f}",
            f"Median: {values.median():.4f}",
            f"Minimum: {values.min()}",
            f"Maximum: {values.max()}",
        ])

    report.extend([
        "",
        "COMPATIBILITY CHECKLIST",
        "",
        "1. Confirm identical name normalization.",
        "2. Confirm summary handling and whitespace rules.",
        "3. Confirm requires_python missing-value conventions.",
        "4. Confirm similarity reference list and exact-match handling.",
        "5. Confirm similarity defaults when no close match exists.",
        "6. Confirm historical and live release counting units.",
        "7. Confirm age cutoff and assessment timestamp semantics.",
        "8. Confirm missing-value imputation and indicator behavior.",
        "",
        "IMPORTANT LIMITATIONS",
        "Historical and live PyPI data may have different coverage.",
        "Descriptive statistics do not prove feature equivalence.",
        "Candidate-group labels are provisional.",
        "No verified malware-risk calibration is established.",
        "No model retraining or export performed.",
    ])

    REPORT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT.write_text(
        "\n".join(report),
        encoding="utf-8",
    )

    print()
    print("MODEL FEATURE ALIGNMENT: PASS")
    print("TRAINING DATASET VALIDATION: PASS")
    print()
    print("Saved:", REPORT)
    print("[SUCCESS] Compatibility audit report generated.")


if __name__ == "__main__":
    main()
