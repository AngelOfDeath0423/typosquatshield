
from pathlib import Path
import json

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/features/year_matched_features.csv"
OUTPUT_DIR = BASE / "reports/preliminary_ml"

FULL_FEATURES = [
    "name_length",
    "name_separator_count",
    "name_digit_count",
    "version_is_prerelease",
    "summary_length",
    "summary_word_count",
    "summary_missing",
    "requires_python_missing",
]

REDUCED_FEATURES = [
    "name_length",
    "name_separator_count",
    "name_digit_count",
    "summary_length",
    "summary_word_count",
]

SEED = 42


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - PRELIMINARY ML BASELINES")
    print("=" * 65)

    df = pd.read_csv(INPUT)

    if df["normalized_name"].duplicated().any():
        raise ValueError("Duplicate package names detected.")

    expected_groups = {
        "openssf_exact_version_candidate",
        "presumed_legitimate",
    }

    if set(df["candidate_group"]) != expected_groups:
        raise ValueError("Unexpected candidate groups.")

    all_features = sorted(set(FULL_FEATURES + REDUCED_FEATURES))

    if df[all_features].isna().any().any():
        raise ValueError("Missing feature values.")

    # Exploratory target: candidate source membership only.
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
        "full": FULL_FEATURES,
        "reduced": REDUCED_FEATURES,
    }

    results = []

    for experiment_name, columns in experiments.items():
        X_train = df.loc[train_idx, columns]
        X_test = df.loc[test_idx, columns]

        y_train = y.loc[train_idx]
        y_test = y.loc[test_idx]

        models = {
            "logistic_regression": make_pipeline(
                StandardScaler(),
                LogisticRegression(
                    max_iter=2000,
                    random_state=SEED,
                ),
            ),
            "random_forest": RandomForestClassifier(
                n_estimators=200,
                min_samples_leaf=5,
                random_state=SEED,
                n_jobs=-1,
            ),
        }

        for model_name, model in models.items():
            model.fit(X_train, y_train)
            predictions = model.predict(X_test)

            tn, fp, fn, tp = confusion_matrix(
                y_test,
                predictions,
                labels=[0, 1],
            ).ravel()

            result = {
                "experiment": experiment_name,
                "model": model_name,
                "feature_count": len(columns),
                "train_records": len(train_idx),
                "test_records": len(test_idx),
                "accuracy": accuracy_score(y_test, predictions),
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
                "true_positives": int(tp),
                "true_negatives": int(tn),
            }

            results.append(result)

            print()
            print(f"Experiment: {experiment_name}")
            print(f"Model: {model_name}")
            print(f"Accuracy: {result['accuracy']:.4f}")
            print(f"Precision: {result['precision']:.4f}")
            print(f"Recall: {result['recall']:.4f}")
            print(f"F1: {result['f1']:.4f}")
            print(f"FP: {fp} | FN: {fn} | TP: {tp} | TN: {tn}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    results_df = pd.DataFrame(results)
    results_path = OUTPUT_DIR / "baseline_comparison.csv"

    results_df.to_csv(results_path, index=False)

    metadata = {
        "target": "candidate_group_membership",
        "verified_malware_detection": False,
        "seed": SEED,
        "train_records": len(train_idx),
        "test_records": len(test_idx),
        "experiments": experiments,
        "limitations": [
            "Candidate-group labels are provisional.",
            "Negative candidates are not verified benign.",
            "Sampling and metadata selection biases remain.",
            "The split is random, not a future-time holdout.",
            "Results are not operational malware detection metrics.",
        ],
    }

    metadata_path = OUTPUT_DIR / "experiment_metadata.json"

    metadata_path.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    print()
    print("=" * 65)
    print("BASELINE COMPARISON")
    print("=" * 65)
    print(results_df.to_string(index=False))
    print()
    print("Saved:", results_path)
    print("Saved:", metadata_path)
    print("[SUCCESS] Preliminary experiments completed.")


if __name__ == "__main__":
    main()
