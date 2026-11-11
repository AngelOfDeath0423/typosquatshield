
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

KEY = ["normalized_name", "version", "matched_pair_id"]
AGE = "observed_package_age_days"

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

BASE_FEATURES = METADATA + SIMILARITY + HISTORY

LABELS = {
    "presumed_legitimate": 0,
    "openssf_exact_version_candidate": 1,
}

EXPERIMENTS = [
    "B_no_age",
    "D_original_age",
    "D1_capped_age",
    "D2_short_age_missing",
    "D3_age_categories",
]

LOG_FEATURES = {"prior_release_count", AGE}


def prepare(df, columns):
    X = df[columns].copy()

    for col in columns:
        X[col] = pd.to_numeric(X[col], errors="raise")

        values = X[col].to_numpy(dtype=float)

        if np.isinf(values).any():
            raise ValueError(f"Infinite values in {col}")

        if col in LOG_FEATURES:
            if (X[col].dropna() < 0).any():
                raise ValueError(f"Negative values in {col}")

            X[col] = np.log1p(X[col])

    return X


def age_category(series):
    # Missing ages remain missing.
    # Categories are ordinal, not verified risk levels.
    result = pd.Series(np.nan, index=series.index)

    valid = series.notna()

    bins = [
        -np.inf,
        1 / 24,
        1,
        7,
        30,
        365,
        np.inf,
    ]

    result.loc[valid] = pd.cut(
        series.loc[valid],
        bins=bins,
        labels=False,
        right=False,
    ).astype(float).to_numpy()

    return result


def evaluate(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(
        y_true, y_pred, labels=[0, 1]
    ).ravel()

    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(
            y_true, y_pred, zero_division=0
        ),
        "recall": recall_score(
            y_true, y_pred, zero_division=0
        ),
        "f1": f1_score(
            y_true, y_pred, zero_division=0
        ),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "tn": int(tn),
    }


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - AGE FEATURE SENSITIVITY")
    print("=" * 65)

    df = pd.read_csv(DATA, dtype={"version": str})
    splits = pd.read_csv(SPLITS, dtype={"version": str})

    if len(df) != 4410 or len(splits) != 4410:
        raise ValueError("Unexpected dataset size.")

    if df.duplicated(KEY).any():
        raise ValueError("Duplicate dataset keys.")

    if splits.duplicated(KEY).any():
        raise ValueError("Duplicate split keys.")

    required = (
        KEY + ["candidate_group", AGE]
        + BASE_FEATURES
    )

    missing = set(required) - set(df.columns)

    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    if not df["candidate_group"].isin(LABELS).all():
        raise ValueError("Unexpected candidate group.")

    if not splits["split"].isin(["train", "test"]).all():
        raise ValueError("Invalid split assignment.")

    df = df.merge(
        splits[KEY + ["split"]],
        on=KEY,
        how="left",
        validate="one_to_one",
    )

    if df["split"].isna().any():
        raise ValueError("Missing split assignments.")

    if not df.groupby("matched_pair_id")["split"].nunique().eq(1).all():
        raise ValueError("Matched-pair split leakage.")

    train = df[df["split"] == "train"].copy()
    test = df[df["split"] == "test"].copy()

    if len(train) != 3306 or len(test) != 1104:
        raise ValueError("Unexpected split sizes.")

    y_train = train["candidate_group"].map(LABELS).astype(int)
    y_test = test["candidate_group"].map(LABELS).astype(int)

    # The cap is determined from training data only.
    training_age = pd.to_numeric(
        train[AGE], errors="raise"
    )

    cap = training_age.dropna().quantile(0.95)

    if not np.isfinite(cap) or cap <= 0:
        raise ValueError("Invalid training-derived age cap.")

    print(f"Training records: {len(train)}")
    print(f"Testing records: {len(test)}")
    print(f"Training age 95th percentile: {cap:.4f} days")
    print()

    results = []
    subgroup_results = []
    prediction_records = []

    for experiment in EXPERIMENTS:
        train_copy = train.copy()
        test_copy = test.copy()

        if experiment == "B_no_age":
            columns = BASE_FEATURES.copy()

        elif experiment == "D_original_age":
            columns = BASE_FEATURES + [AGE]

        elif experiment == "D1_capped_age":
            for frame in [train_copy, test_copy]:
                frame[AGE] = frame[AGE].clip(upper=cap)

            columns = BASE_FEATURES + [AGE]

        elif experiment == "D2_short_age_missing":
            for frame in [train_copy, test_copy]:
                frame.loc[
                    frame[AGE].notna()
                    & (frame[AGE] < 1 / 24),
                    AGE,
                ] = np.nan

            columns = BASE_FEATURES + [AGE]

        elif experiment == "D3_age_categories":
            for frame in [train_copy, test_copy]:
                frame["age_category"] = age_category(
                    pd.to_numeric(frame[AGE], errors="raise")
                )

            columns = BASE_FEATURES + ["age_category"]

        X_train = prepare(train_copy, columns)
        X_test = prepare(test_copy, columns)

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
        predictions = model.predict(X_test)

        overall = evaluate(y_test, predictions)

        results.append({
            "experiment": experiment,
            "feature_count": len(columns),
            **overall,
        })

        pred_df = test_copy[
            KEY + ["candidate_group", "has_prior_history"]
        ].copy()

        pred_df["experiment"] = experiment
        pred_df["actual"] = y_test.to_numpy()
        pred_df["predicted"] = predictions

        prediction_records.append(pred_df)

        for history_value in [0, 1]:
            mask = (
                test_copy["has_prior_history"].to_numpy()
                == history_value
            )

            subgroup_metrics = evaluate(
                y_test.to_numpy()[mask],
                predictions[mask],
            )

            subgroup_results.append({
                "experiment": experiment,
                "has_prior_history": history_value,
                "records": int(mask.sum()),
                **subgroup_metrics,
            })

        print(
            f"{experiment:22s} "
            f"F1={overall['f1']:.4f} "
            f"Accuracy={overall['accuracy']:.4f} "
            f"FP={overall['fp']} "
            f"FN={overall['fn']}"
        )

    OUT.mkdir(parents=True, exist_ok=True)

    comparison = pd.DataFrame(results)
    subgroup = pd.DataFrame(subgroup_results)

    comparison.to_csv(
        OUT / "age_sensitivity_comparison.csv",
        index=False,
    )

    subgroup.to_csv(
        OUT / "age_sensitivity_subgroups.csv",
        index=False,
    )

    pd.concat(
        prediction_records,
        ignore_index=True,
    ).to_csv(
        OUT / "age_sensitivity_predictions.csv",
        index=False,
    )

    print()
    print("OVERALL COMPARISON")
    print(comparison.round(4).to_string(index=False))

    print()
    print("PERFORMANCE BY PRIOR HISTORY")
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
    print("LIMITATIONS")
    print("Candidate-group labels remain provisional.")
    print("Age is based on first observed historical records.")
    print("Age categories are descriptive, not risk thresholds.")
    print("Missing-value treatment may itself affect predictions.")
    print("Repeated test-set comparisons are exploratory.")
    print("No verified malware-detection claims are supported.")

    print()
    print("Saved reports in:", OUT)
    print("[SUCCESS] Age sensitivity experiment completed.")


if __name__ == "__main__":
    main()
