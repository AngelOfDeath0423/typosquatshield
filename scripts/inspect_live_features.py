
from pathlib import Path
import asyncio
import json

import pandas as pd

from backend.services.pypi_service import fetch_pypi_metadata
from backend.services.feature_service import prepare_live_features
from scripts.typosquatting_similarity import (
    analyze_package,
    load_reference_names,
)

BASE = Path(__file__).resolve().parent.parent

TRAINING_FILE = (
    BASE / "data/features/version_aware_combined_features.csv"
)

REPORT_FILE = (
    BASE / "reports/live_feature_inspection_report.txt"
)

PACKAGES = ["requests", "numpy", "pandas"]

FEATURES = [
    "name_length",
    "name_separator_count",
    "name_digit_count",
    "version_is_prerelease",
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


async def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - LIVE FEATURE INSPECTION")
    print("=" * 65)

    if not TRAINING_FILE.exists():
        raise FileNotFoundError(TRAINING_FILE)

    training = pd.read_csv(TRAINING_FILE)

    missing_columns = [
        feature for feature in FEATURES
        if feature not in training.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing training columns: {missing_columns}"
        )

    references = load_reference_names()

    report = [
        "TYPOSQUATSHIELD - LIVE FEATURE INSPECTION",
        "=" * 65,
        f"Training records: {len(training)}",
        f"Reference packages: {len(references)}",
        "",
    ]

    for package_name in PACKAGES:
        print(f"\nInspecting: {package_name}")

        metadata = await fetch_pypi_metadata(package_name)

        typo_result = analyze_package(
            package_name,
            references,
        )

        live = prepare_live_features(
            metadata,
            typo_result=typo_result,
        )

        values = live["features"]

        if list(values) != FEATURES:
            raise ValueError(
                "Live feature order differs from expected order."
            )

        report.extend([
            "",
            "=" * 65,
            f"PACKAGE: {package_name}",
            f"Version: {metadata.get('version')}",
            f"Feature status: {live['feature_status']}",
            f"Missing features: {live['missing_features']}",
            "",
            f"{'Feature':35} {'Live':>14} {'Train median':>14}",
            "-" * 65,
        ])

        for feature in FEATURES:
            historical = pd.to_numeric(
                training[feature],
                errors="coerce",
            )

            live_value = values[feature]
            median = historical.median()

            live_text = (
                "MISSING"
                if live_value is None
                else str(round(live_value, 4))
                if isinstance(live_value, float)
                else str(live_value)
            )

            line = (
                f"{feature:35} "
                f"{live_text:>14} "
                f"{median:>14.4f}"
            )

            report.append(line)

        report.extend([
            "",
            "SIMILARITY RESULT",
            json.dumps(typo_result, indent=2),
            "",
            "REPUTATION RESULT",
            json.dumps(
                live.get("reputation_features", {}),
                indent=2,
                default=str,
            ),
        ])

    report.extend([
        "",
        "INTERPRETATION NOTES",
        "Training medians are descriptive, not expected values.",
        "Live metadata may differ from historical metadata.",
        "Current PyPI release history may be incomplete.",
        "The training labels are provisional candidate groups.",
        "No malware probability or final risk level is inferred.",
        "This script does not retrain or modify the model.",
    ])

    REPORT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT_FILE.write_text(
        "\n".join(report),
        encoding="utf-8",
    )

    print("\n".join(report))

    print("\nSaved:", REPORT_FILE)
    print("[SUCCESS] Live feature inspection completed.")


if __name__ == "__main__":
    asyncio.run(main())
