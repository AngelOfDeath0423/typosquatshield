
from pathlib import Path
import json
import joblib
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

MODEL_DIR = BASE / "models"
REPORT_DIR = BASE / "reports" / "model_export"

MODEL_PATH = MODEL_DIR / "typosquatshield_baseline.joblib"
METADATA_PATH = MODEL_DIR / "typosquatshield_model_metadata.json"
REPORT_PATH = REPORT_DIR / "model_export_report.txt"

EXPERIMENT = "D2_short_age_missing"

# The original sensitivity script applies log1p to
# prior_release_count and observed_package_age_days.
# Reuse its prepare() function rather than duplicating it.

def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - MODEL TRAINING AND EXPORT")
    print("=" * 65)

    df = pd.read_csv(DATA, dtype={"version": str})
    splits = pd.read_csv(SPLITS, dtype={"version": str})

    if len(df) != 4410 or len(splits) != 4410:
        raise ValueError("Unexpected dataset or split size.")

    if df.duplicated(KEY).any():
        raise ValueError("Duplicate dataset keys.")

    if splits.duplicated(KEY).any():
        raise ValueError("Duplicate split keys.")

    split_columns = KEY + ["split"]

    df = df.merge(
        splits[split_columns],
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
        raise ValueError("Unexpected train/test sizes.")

    y_train = (
        train["candidate_group"]
        .map(LABELS)
        .astype(int)
    )

    y_test = (
        test["candidate_group"]
        .map(LABELS)
        .astype(int)
    )

    # D2: represent observed ages below one hour as missing.
    # This is a diagnostic treatment, not a security threshold.
    train_copy = train.copy()
    test_copy = test.copy()

    for frame in (train_copy, test_copy):
        ages = pd.to_numeric(
            frame[AGE],
            errors="raise",
        )

        frame[AGE] = ages.mask(
            ages < (1.0 / 24.0)
        )

    features = BASE_FEATURES + [AGE]

    X_train = prepare(train_copy, features)
    X_test = prepare(test_copy, features)

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

    print(f"Training records: {len(train)}")
    print(f"Testing records: {len(test)}")
    print(f"Features: {len(features)}")
    print(f"Experiment: {EXPERIMENT}")

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    tn, fp, fn, tp = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1],
    ).ravel()

    metrics = {
        "accuracy": float(
            accuracy_score(y_test, predictions)
        ),
        "precision": float(
            precision_score(
                y_test, predictions, zero_division=0
            )
        ),
        "recall": float(
            recall_score(
                y_test, predictions, zero_division=0
            )
        ),
        "f1": float(
            f1_score(
                y_test, predictions, zero_division=0
            )
        ),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
        "true_negatives": int(tn),
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # Save preprocessing and model together.
    # The age masking and prepare() transformation
    # remain explicit external inference requirements.
    joblib.dump(model, MODEL_PATH)

    reloaded = joblib.load(MODEL_PATH)

    reload_predictions = reloaded.predict(X_test)

    if not np.array_equal(
        predictions,
        reload_predictions,
    ):
        raise ValueError(
            "Reloaded model predictions do not match."
        )

    metadata = {
        "system": "TyposquatShield",
        "experiment": EXPERIMENT,
        "model_type": "RandomForestClassifier",
        "features": features,
        "label_mapping": LABELS,
        "training_records": len(train),
        "testing_records": len(test),
        "preprocessing": {
            "age_under_one_hour": "set_to_missing",
            "age_threshold_days": 1.0 / 24.0,
            "log1p_features": [
                "prior_release_count",
                AGE,
            ],
            "imputation": "median",
            "missing_indicators": True,
        },
        "metrics": metrics,
        "limitations": [
            "Candidate-group labels are provisional.",
            "This model is not a verified malware detector.",
            "Historical data availability is incomplete.",
            "Observed package age is not verified creation age.",
            "The current model does not use static features.",
            "External validation has not been performed.",
        ],
    }

    METADATA_PATH.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    lines = [
        "TYPOSQUATSHIELD - MODEL EXPORT REPORT",
        "=" * 65,
        f"Experiment: {EXPERIMENT}",
        f"Training records: {len(train)}",
        f"Testing records: {len(test)}",
        f"Feature count: {len(features)}",
        "",
        "TEST PERFORMANCE",
        f"Accuracy: {metrics['accuracy']:.4f}",
        f"Precision: {metrics['precision']:.4f}",
        f"Recall: {metrics['recall']:.4f}",
        f"F1: {metrics['f1']:.4f}",
        f"FP: {fp} | FN: {fn} | TP: {tp} | TN: {tn}",
        "",
        "VALIDATION",
        "Matched-pair split: PASS",
        "Model reload consistency: PASS",
        "",
        "LIMITATIONS",
        *metadata["limitations"],
    ]

    REPORT_PATH.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print()
    print("\n".join(lines))
    print()
    print("Saved:", MODEL_PATH)
    print("Saved:", METADATA_PATH)
    print("Saved:", REPORT_PATH)
    print("[SUCCESS] Model training and export completed.")


if __name__ == "__main__":
    main()
