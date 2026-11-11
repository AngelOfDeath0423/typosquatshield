
from pathlib import Path
import numpy as np
import pandas as pd

from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

from test_age_feature_sensitivity import (
    DATA,
    SPLITS,
    KEY,
    AGE,
    BASE_FEATURES,
    LABELS,
    prepare,
)

BASE = Path(__file__).resolve().parent.parent
REPORT = BASE / "reports/summary_feature_ablation_report.txt"

SUMMARY_FEATURES = [
    "summary_length",
    "summary_word_count",
    "summary_missing",
]

EXPERIMENTS = {
    "D2_baseline_16": [],
    "D2_without_summary_13": SUMMARY_FEATURES,
    "D2_without_summary_and_python_12": (
        SUMMARY_FEATURES + ["requires_python_missing"]
    ),
}


def evaluate(y_true, predictions):
    tn, fp, fn, tp = confusion_matrix(
        y_true,
        predictions,
        labels=[0, 1],
    ).ravel()

    return {
        "accuracy": accuracy_score(y_true, predictions),
        "precision": precision_score(
            y_true, predictions, zero_division=0
        ),
        "recall": recall_score(
            y_true, predictions, zero_division=0
        ),
        "f1": f1_score(
            y_true, predictions, zero_division=0
        ),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "tn": int(tn),
    }


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - SUMMARY FEATURE ABLATION")
    print("=" * 65)

    df = pd.read_csv(DATA, dtype={"version": str})
    splits = pd.read_csv(SPLITS, dtype={"version": str})

    if len(df) != 4410 or len(splits) != 4410:
        raise ValueError("Unexpected dataset size.")

    if df.duplicated(KEY).any():
        raise ValueError("Duplicate dataset keys.")

    if splits.duplicated(KEY).any():
        raise ValueError("Duplicate split keys.")

    df = df.merge(
        splits[KEY + ["split"]],
        on=KEY,
        how="left",
        validate="one_to_one",
    )

    if df["split"].isna().any():
        raise ValueError("Missing split assignments.")

    if not df.groupby("matched_pair_id")[
        "split"
    ].nunique().eq(1).all():
        raise ValueError("Matched-pair split leakage.")

    train = df[df["split"] == "train"].copy()
    test = df[df["split"] == "test"].copy()

    if len(train) != 3306 or len(test) != 1104:
        raise ValueError("Unexpected split sizes.")

    y_train = train["candidate_group"].map(
        LABELS
    ).astype(int)

    y_test = test["candidate_group"].map(
        LABELS
    ).astype(int)

    # Reproduce D2 age treatment.
    for frame in (train, test):
        ages = pd.to_numeric(
            frame[AGE],
            errors="raise",
        )

        frame[AGE] = ages.mask(
            ages < (1.0 / 24.0)
        )

    all_features = BASE_FEATURES + [AGE]

    if len(all_features) != 16:
        raise ValueError(
            f"Expected 16 features, got {len(all_features)}."
        )

    results = []

    for experiment, removed in EXPERIMENTS.items():
        features = [
            feature
            for feature in all_features
            if feature not in removed
        ]

        X_train = prepare(train.copy(), features)
        X_test = prepare(test.copy(), features)

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

        metrics = evaluate(y_test, predictions)

        results.append({
            "experiment": experiment,
            "features": len(features),
            **metrics,
        })

        print()
        print("Experiment:", experiment)
        print("Features:", len(features))
        print(f"Accuracy: {metrics['accuracy']:.4f}")
        print(f"Precision: {metrics['precision']:.4f}")
        print(f"Recall: {metrics['recall']:.4f}")
        print(f"F1: {metrics['f1']:.4f}")
        print(
            f"FP: {metrics['fp']} | "
            f"FN: {metrics['fn']} | "
            f"TP: {metrics['tp']} | "
            f"TN: {metrics['tn']}"
        )

    results_df = pd.DataFrame(results)

    baseline_f1 = results_df.iloc[0]["f1"]

    results_df["f1_change_from_baseline"] = (
        results_df["f1"] - baseline_f1
    )

    REPORT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_lines = [
        "TYPOSQUATSHIELD - SUMMARY FEATURE ABLATION",
        "=" * 65,
        "Training records: 3306",
        "Testing records: 1104",
        "Matched-pair split: preserved",
        "Model: RandomForestClassifier",
        "Age treatment: D2_short_age_missing",
        "",
        results_df.to_string(index=False),
        "",
        "LIMITATIONS",
        "Candidate-group labels are provisional.",
        "Results do not establish malware-detection accuracy.",
        "Ablation does not prove or disprove data leakage.",
        "Live PyPI features may differ from historical features.",
        "No independent external validation performed.",
        "Existing exported model is not modified.",
    ]

    REPORT.write_text(
        "\n".join(report_lines),
        encoding="utf-8",
    )

    print()
    print("=" * 65)
    print("ABLATION COMPARISON")
    print("=" * 65)

    print(results_df.to_string(index=False))

    print()
    print("Saved:", REPORT)
    print("[SUCCESS] Summary feature ablation completed.")


if __name__ == "__main__":
    main()
