
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/features/version_aware_combined_features.csv"
OUTPUT_DIR = BASE / "reports/version_aware_ml"

RANDOM_STATE = 42

METADATA = [
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

HISTORY = [
    "prior_release_count",
    "has_prior_history",
]

TIMING = [
    "observed_package_age_days",
    "days_since_previous_release",
    "prior_release_span_days",
]

EXPERIMENTS = {
    "A_metadata_similarity": METADATA + SIMILARITY,
    "B_plus_history": METADATA + SIMILARITY + HISTORY,
    "C_full_reputation": METADATA + SIMILARITY + HISTORY + TIMING,
}

LOG_FEATURES = set([
    "prior_release_count",
    "observed_package_age_days",
    "days_since_previous_release",
    "prior_release_span_days",
])

LABEL_MAP = {
    "presumed_legitimate": 0,
    "openssf_exact_version_candidate": 1,
}


def prepare_features(df, columns):
    X = df[columns].copy()

    for column in columns:
        X[column] = pd.to_numeric(
            X[column],
            errors="raise",
        )

        values = X[column].to_numpy(dtype=float)

        if np.isinf(values).any():
            raise ValueError(
                f"Infinite values in {column}"
            )

        if column in LOG_FEATURES:
            if (X[column].dropna() < 0).any():
                raise ValueError(
                    f"Negative values in {column}"
                )

            X[column] = np.log1p(X[column])

    return X


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - VERSION-AWARE ML EXPERIMENTS")
    print("=" * 65)

    df = pd.read_csv(INPUT)

    if len(df) != 4410:
        raise ValueError("Unexpected record count.")

    if df["normalized_name"].nunique() != 4410:
        raise ValueError("Duplicate package names.")

    if df["matched_pair_id"].nunique() != 2205:
        raise ValueError("Unexpected matched-pair count.")

    if df["candidate_group"].isna().any():
        raise ValueError("Missing candidate groups.")

    if not df["candidate_group"].isin(LABEL_MAP).all():
        raise ValueError("Unexpected candidate-group values.")

    pair_sizes = df.groupby("matched_pair_id").size()

    if not pair_sizes.eq(2).all():
        raise ValueError("Invalid matched-pair sizes.")

    pair_groups = (
        df.groupby("matched_pair_id")["candidate_group"]
        .nunique()
    )

    if not pair_groups.eq(2).all():
        raise ValueError("Invalid pair-group composition.")

    all_features = set(
        feature
        for columns in EXPERIMENTS.values()
        for feature in columns
    )

    missing = sorted(all_features - set(df.columns))

    if missing:
        raise ValueError(f"Missing features: {missing}")

    # Split matched pairs, not individual records.
    pair_ids = sorted(df["matched_pair_id"].unique())

    train_pairs, test_pairs = train_test_split(
        pair_ids,
        test_size=0.25,
        random_state=RANDOM_STATE,
        shuffle=True,
    )

    train_mask = df["matched_pair_id"].isin(train_pairs)
    test_mask = df["matched_pair_id"].isin(test_pairs)

    train_df = df.loc[train_mask].copy()
    test_df = df.loc[test_mask].copy()

    if set(train_df["normalized_name"]) & set(
        test_df["normalized_name"]
    ):
        raise ValueError("Package overlap between splits.")

    if set(train_pairs) & set(test_pairs):
        raise ValueError("Matched-pair leakage.")

    y_train = train_df["candidate_group"].map(
        LABEL_MAP
    ).astype(int)

    y_test = test_df["candidate_group"].map(
        LABEL_MAP
    ).astype(int)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Save split membership for reproducibility.
    split_info = df[
        [
            "normalized_name",
            "version",
            "matched_pair_id",
            "candidate_group",
        ]
    ].copy()

    split_info["split"] = np.where(
        train_mask,
        "train",
        "test",
    )

    split_info.to_csv(
        OUTPUT_DIR / "split_membership.csv",
        index=False,
    )

    print(f"Training records: {len(train_df)}")
    print(f"Testing records: {len(test_df)}")
    print(f"Training pairs: {len(train_pairs)}")
    print(f"Testing pairs: {len(test_pairs)}")
    print()

    results = []
    predictions = []

    for experiment, features in EXPERIMENTS.items():
        X_train = prepare_features(train_df, features)
        X_test = prepare_features(test_df, features)

        # The imputer is fitted only on training data.
        model = Pipeline([
            (
                "imputer",
                SimpleImputer(
                    strategy="median",
                    add_indicator=True,
                ),
            ),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=300,
                    random_state=RANDOM_STATE,
                    n_jobs=-1,
                    class_weight="balanced",
                    min_samples_leaf=2,
                ),
            ),
        ])

        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)

        tn, fp, fn, tp = confusion_matrix(
            y_test,
            y_pred,
            labels=[0, 1],
        ).ravel()

        result = {
            "experiment": experiment,
            "feature_count": len(features),
            "train_records": len(train_df),
            "test_records": len(test_df),
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(
                y_test, y_pred, zero_division=0
            ),
            "recall": recall_score(
                y_test, y_pred, zero_division=0
            ),
            "f1": f1_score(
                y_test, y_pred, zero_division=0
            ),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
            "true_negatives": int(tn),
        }

        results.append(result)

        prediction_df = test_df[
            [
                "normalized_name",
                "version",
                "matched_pair_id",
                "candidate_group",
            ]
        ].copy()

        prediction_df["experiment"] = experiment
        prediction_df["true_group_code"] = y_test.to_numpy()
        prediction_df["predicted_group_code"] = y_pred

        predictions.append(prediction_df)

        print("-" * 65)
        print(f"Experiment: {experiment}")
        print(f"Features: {len(features)}")
        print(f"Accuracy: {result['accuracy']:.4f}")
        print(f"Precision: {result['precision']:.4f}")
        print(f"Recall: {result['recall']:.4f}")
        print(f"F1: {result['f1']:.4f}")
        print(f"FP: {fp} | FN: {fn} | TP: {tp} | TN: {tn}")
        print()

    comparison = pd.DataFrame(results)

    comparison.to_csv(
        OUTPUT_DIR / "experiment_comparison.csv",
        index=False,
    )

    pd.concat(
        predictions,
        ignore_index=True,
    ).to_csv(
        OUTPUT_DIR / "test_predictions.csv",
        index=False,
    )

    print("=" * 65)
    print("EXPERIMENT COMPARISON")
    print("=" * 65)
    print(comparison.round(4).to_string(index=False))

    print()
    print("Saved:", OUTPUT_DIR / "experiment_comparison.csv")
    print("Saved:", OUTPUT_DIR / "test_predictions.csv")
    print("Saved:", OUTPUT_DIR / "split_membership.csv")

    print()
    print("LIMITATIONS:")
    print("Candidate groups are provisional, not verified labels.")
    print("Results are not malware-detection performance.")
    print("Historical availability remains unverified.")
    print("Timing features may reflect collection artifacts.")
    print("No independent external validation performed.")

    print()
    print("[SUCCESS] Version-aware ML experiments completed.")


if __name__ == "__main__":
    main()
