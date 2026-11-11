
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
from sklearn.pipeline import Pipeline

BASE = Path(__file__).resolve().parent.parent

DATA = BASE / "data/features/version_aware_combined_features.csv"
SPLITS = BASE / "reports/version_aware_ml/split_membership.csv"
OUT = BASE / "reports/version_aware_ml"

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

BASE_FEATURES = METADATA + SIMILARITY

HISTORY = [
    "prior_release_count",
    "has_prior_history",
]

AGE = "observed_package_age_days"
INTERVAL = "days_since_previous_release"
SPAN = "prior_release_span_days"

EXPERIMENTS = {
    "A_baseline": BASE_FEATURES,
    "B_history": BASE_FEATURES + HISTORY,
    "D_plus_age": BASE_FEATURES + HISTORY + [AGE],
    "E_plus_interval": BASE_FEATURES + HISTORY + [INTERVAL],
    "F_plus_span": BASE_FEATURES + HISTORY + [SPAN],
    "C_full": BASE_FEATURES + HISTORY + [AGE, INTERVAL, SPAN],
}

LOG_FEATURES = {
    "prior_release_count",
    AGE,
    INTERVAL,
    SPAN,
}

LABELS = {
    "presumed_legitimate": 0,
    "openssf_exact_version_candidate": 1,
}

KEY = ["normalized_name", "version", "matched_pair_id"]


def prepare(df, columns):
    X = df[columns].copy()

    for col in columns:
        X[col] = pd.to_numeric(X[col], errors="raise")

        if np.isinf(X[col].to_numpy(dtype=float)).any():
            raise ValueError(f"Infinite values in {col}")

        if col in LOG_FEATURES:
            if (X[col].dropna() < 0).any():
                raise ValueError(f"Negative values in {col}")
            X[col] = np.log1p(X[col])

    return X


def metrics(y, pred):
    tn, fp, fn, tp = confusion_matrix(
        y, pred, labels=[0, 1]
    ).ravel()

    return {
        "accuracy": accuracy_score(y, pred),
        "precision": precision_score(
            y, pred, zero_division=0
        ),
        "recall": recall_score(
            y, pred, zero_division=0
        ),
        "f1": f1_score(y, pred, zero_division=0),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "tn": int(tn),
    }


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - REPUTATION FEATURE ABLATION")
    print("=" * 65)

    df = pd.read_csv(DATA, dtype={"version": str})
    splits = pd.read_csv(SPLITS, dtype={"version": str})

    if len(df) != 4410 or len(splits) != 4410:
        raise ValueError("Unexpected dataset size.")

    if df.duplicated(KEY).any() or splits.duplicated(KEY).any():
        raise ValueError("Duplicate package/version/pair keys.")

    if set(splits["split"]) != {"train", "test"}:
        raise ValueError("Invalid split labels.")

    if not df["candidate_group"].isin(LABELS).all():
        raise ValueError("Unexpected candidate group.")

    df = df.merge(
        splits[KEY + ["split"]],
        on=KEY,
        how="left",
        validate="one_to_one",
    )

    if df["split"].isna().any():
        raise ValueError("Missing split assignments.")

    pair_splits = df.groupby("matched_pair_id")["split"].nunique()

    if not pair_splits.eq(1).all():
        raise ValueError("Matched-pair split leakage.")

    train = df[df["split"] == "train"].copy()
    test = df[df["split"] == "test"].copy()

    if len(train) != 3306 or len(test) != 1104:
        raise ValueError("Unexpected train/test sizes.")

    y_train = train["candidate_group"].map(LABELS).astype(int)
    y_test = test["candidate_group"].map(LABELS).astype(int)

    results = []
    subgroup_results = []
    predictions = []

    for name, columns in EXPERIMENTS.items():
        X_train = prepare(train, columns)
        X_test = prepare(test, columns)

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
                    random_state=42,
                    n_jobs=-1,
                    class_weight="balanced",
                    min_samples_leaf=2,
                ),
            ),
        ])

        model.fit(X_train, y_train)
        pred = model.predict(X_test)

        overall = metrics(y_test, pred)

        results.append({
            "experiment": name,
            "feature_count": len(columns),
            **overall,
        })

        prediction_df = test[KEY + [
            "candidate_group",
            "has_prior_history",
        ]].copy()

        prediction_df["experiment"] = name
        prediction_df["actual"] = y_test.to_numpy()
        prediction_df["predicted"] = pred

        predictions.append(prediction_df)

        for history_value in [0, 1]:
            mask = (
                test["has_prior_history"].to_numpy()
                == history_value
            )

            submetrics = metrics(
                y_test.to_numpy()[mask],
                pred[mask],
            )

            subgroup_results.append({
                "experiment": name,
                "has_prior_history": history_value,
                "records": int(mask.sum()),
                **submetrics,
            })

        print(
            f"{name:18s} "
            f"F1={overall['f1']:.4f} "
            f"Accuracy={overall['accuracy']:.4f} "
            f"FP={overall['fp']} "
            f"FN={overall['fn']}"
        )

    OUT.mkdir(parents=True, exist_ok=True)

    comparison = pd.DataFrame(results)
    subgroup = pd.DataFrame(subgroup_results)

    comparison.to_csv(
        OUT / "reputation_ablation_comparison.csv",
        index=False,
    )

    subgroup.to_csv(
        OUT / "reputation_ablation_subgroups.csv",
        index=False,
    )

    pd.concat(
        predictions,
        ignore_index=True,
    ).to_csv(
        OUT / "reputation_ablation_predictions.csv",
        index=False,
    )

    print()
    print("OVERALL COMPARISON")
    print(comparison.round(4).to_string(index=False))

    print()
    print("PERFORMANCE BY PRIOR-HISTORY AVAILABILITY")
    print(
        subgroup[
            [
                "experiment",
                "has_prior_history",
                "records",
                "accuracy",
                "f1",
                "fp",
                "fn",
            ]
        ].round(4).to_string(index=False)
    )

    print()
    print("Saved reports in:", OUT)
    print("[SUCCESS] Reputation ablation completed.")
    print(
        "NOTE: Provisional candidate-group classification only."
    )


if __name__ == "__main__":
    main()
