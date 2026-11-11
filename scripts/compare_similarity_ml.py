
from pathlib import Path
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

BASE = Path(__file__).resolve().parent.parent

INPUT = (
    BASE / "data/features/year_matched_with_typo_features.csv"
)

OUTPUT = (
    BASE / "reports/preliminary_ml/similarity_comparison.csv"
)

BASELINE_FEATURES = [
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

SEED = 42


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - SIMILARITY ML COMPARISON")
    print("=" * 65)

    df = pd.read_csv(INPUT)

    if df["normalized_name"].duplicated().any():
        raise ValueError("Duplicate package names detected.")

    all_features = BASELINE_FEATURES + SIMILARITY_FEATURES

    if df[all_features].isna().any().any():
        raise ValueError("Missing feature values.")

    y = (
        df["candidate_group"]
        == "openssf_exact_version_candidate"
    ).astype(int)

    train_idx, test_idx = train_test_split(
        df.index.to_numpy(),
        test_size=0.25,
        stratify=y,
        random_state=SEED,
    )

    experiments = {
        "baseline_metadata": BASELINE_FEATURES,
        "metadata_plus_similarity": all_features,
    }

    results = []

    for experiment, features in experiments.items():
        X_train = df.loc[train_idx, features]
        X_test = df.loc[test_idx, features]

        y_train = y.loc[train_idx]
        y_test = y.loc[test_idx]

        model = RandomForestClassifier(
            n_estimators=200,
            min_samples_leaf=5,
            random_state=SEED,
            n_jobs=-1,
        )

        model.fit(X_train, y_train)
        predictions = model.predict(X_test)

        tn, fp, fn, tp = confusion_matrix(
            y_test,
            predictions,
            labels=[0, 1],
        ).ravel()

        results.append({
            "experiment": experiment,
            "features": len(features),
            "accuracy": accuracy_score(
                y_test, predictions
            ),
            "precision": precision_score(
                y_test, predictions, zero_division=0
            ),
            "recall": recall_score(
                y_test, predictions, zero_division=0
            ),
            "f1": f1_score(
                y_test, predictions, zero_division=0
            ),
            "false_positives": int(fp),
            "false_negatives": int(fn),
        })

    result_df = pd.DataFrame(results)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    result_df.to_csv(OUTPUT, index=False)

    print()
    print(result_df.to_string(index=False))
    print()
    print("Saved:", OUTPUT)
    print("[SUCCESS] Similarity comparison completed.")
    print(
        "NOTE: Candidate-group classification only; "
        "not verified malware detection."
    )


if __name__ == "__main__":
    main()
