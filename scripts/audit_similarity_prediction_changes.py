
from pathlib import Path
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/features/year_matched_with_typo_features.csv"
OUTPUT = BASE / "reports/preliminary_ml/similarity_prediction_changes.csv"

BASELINE = [
    "name_length",
    "name_separator_count",
    "name_digit_count",
    "version_is_prerelease",
    "summary_length",
    "summary_word_count",
    "summary_missing",
    "requires_python_missing",
]

SIMILARITY = [
    "typo_min_edit_distance",
    "typo_max_similarity",
    "typo_potential_match",
    "typo_close_match_count",
    "typo_reference_length",
]


def main():
    df = pd.read_csv(INPUT)

    if df["normalized_name"].duplicated().any():
        raise ValueError("Duplicate package names.")

    y = (
        df["candidate_group"]
        == "openssf_exact_version_candidate"
    ).astype(int)

    train_idx, test_idx = train_test_split(
        df.index.to_numpy(),
        test_size=0.25,
        stratify=y,
        random_state=42,
    )

    predictions = {}

    for name, features in {
        "baseline": BASELINE,
        "with_similarity": BASELINE + SIMILARITY,
    }.items():
        model = RandomForestClassifier(
            n_estimators=200,
            min_samples_leaf=5,
            random_state=42,
            n_jobs=-1,
        )

        model.fit(
            df.loc[train_idx, features],
            y.loc[train_idx],
        )

        predictions[name] = model.predict(
            df.loc[test_idx, features]
        )

    results = df.loc[
        test_idx,
        [
            "normalized_name",
            "candidate_group",
            "typo_potential_match",
            "typo_min_edit_distance",
            "typo_max_similarity",
        ],
    ].copy()

    results["actual_group"] = y.loc[test_idx].to_numpy()
    results["baseline_prediction"] = predictions["baseline"]
    results["similarity_prediction"] = predictions[
        "with_similarity"
    ]

    results["prediction_changed"] = (
        results["baseline_prediction"]
        != results["similarity_prediction"]
    )

    changed = results[
        results["prediction_changed"]
    ].copy()

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    changed.to_csv(OUTPUT, index=False)

    print("=" * 65)
    print("TYPOSQUATSHIELD - PREDICTION CHANGE AUDIT")
    print("=" * 65)

    print("Test records:", len(results))
    print("Changed predictions:", len(changed))

    print(
        "Changed predictions with close typo match:",
        int(changed["typo_potential_match"].sum()),
    )

    print("\nCHANGES BY ACTUAL GROUP")
    print(
        changed.groupby(
            ["candidate_group",
             "baseline_prediction",
             "similarity_prediction"]
        ).size().to_string()
    )

    print("\nFIRST 25 CHANGED PREDICTIONS")
    print(
        changed[
            [
                "normalized_name",
                "candidate_group",
                "typo_potential_match",
                "baseline_prediction",
                "similarity_prediction",
            ]
        ].head(25).to_string(index=False)
    )

    print("\nSaved:", OUTPUT)
    print("[SUCCESS] Prediction change audit completed.")


if __name__ == "__main__":
    main()
