
from pathlib import Path

import numpy as np
import pandas as pd

from model_inference import TyposquatShieldModel
from test_age_feature_sensitivity import (
    DATA,
    SPLITS,
    KEY,
    LABELS,
)

BASE = Path(__file__).resolve().parent.parent

REPORT = (
    BASE / "reports/model_export/"
    "inference_validation_report.txt"
)


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - INFERENCE VALIDATION")
    print("=" * 65)

    predictor = TyposquatShieldModel()

    df = pd.read_csv(DATA, dtype={"version": str})
    splits = pd.read_csv(SPLITS, dtype={"version": str})

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

    test = df[df["split"] == "test"].copy()

    if len(test) != 1104:
        raise ValueError(
            f"Expected 1104 test records, got {len(test)}"
        )

    y_true = (
        test["candidate_group"]
        .map(LABELS)
        .astype(int)
        .to_numpy()
    )

    predictions = []

    for index, (_, row) in enumerate(test.iterrows(), 1):
        feature_values = {
            feature: (
                None
                if pd.isna(row[feature])
                else row[feature]
            )
            for feature in predictor.features
        }

        result = predictor.predict(feature_values)

        prediction = int(
            result["predicted_candidate_group"]
            == "openssf_exact_version_candidate"
        )

        predictions.append(prediction)

        if index % 200 == 0:
            print(
                f"Validated {index}/{len(test)} records"
            )

    y_pred = np.asarray(predictions)

    from sklearn.metrics import (
        accuracy_score,
        precision_score,
        recall_score,
        f1_score,
        confusion_matrix,
    )

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
    ).ravel()

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(
        y_true, y_pred, zero_division=0
    )
    recall = recall_score(
        y_true, y_pred, zero_division=0
    )
    f1 = f1_score(
        y_true, y_pred, zero_division=0
    )

    # Expected results from the exported D2 experiment.
    expected = {
        "fp": 123,
        "fn": 129,
        "tp": 423,
        "tn": 429,
    }

    actual = {
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "tn": int(tn),
    }

    passed = actual == expected

    lines = [
        "TYPOSQUATSHIELD - INFERENCE VALIDATION REPORT",
        "=" * 65,
        f"Test records: {len(test)}",
        f"Accuracy: {accuracy:.4f}",
        f"Precision: {precision:.4f}",
        f"Recall: {recall:.4f}",
        f"F1: {f1:.4f}",
        f"FP: {fp} | FN: {fn} | TP: {tp} | TN: {tn}",
        "",
        "VALIDATION",
        "Expected confusion matrix: "
        + str(expected),
        "Actual confusion matrix: "
        + str(actual),
        "Inference reproduction: "
        + ("PASS" if passed else "FAIL"),
        "",
        "LIMITATIONS",
        "Labels represent provisional candidate groups.",
        "This does not establish malware-detection accuracy.",
        "Historical features may not be available live.",
        "No independent external validation performed.",
    ]

    REPORT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print()
    print("\n".join(lines))
    print()
    print("Saved:", REPORT)

    if not passed:
        raise SystemExit(
            "[FAIL] Inference predictions differ "
            "from the exported experiment."
        )

    print("[SUCCESS] Inference validation passed.")


if __name__ == "__main__":
    main()
