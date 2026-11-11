
from pathlib import Path
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/features/year_matched_features.csv"
OUT = BASE / "reports/preliminary_ml"

FEATURES = [
    "name_length",
    "name_separator_count",
    "name_digit_count",
    "version_is_prerelease",
    "summary_length",
    "summary_word_count",
    "summary_missing",
    "requires_python_missing",
]

SEED = 42


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - PRELIMINARY MODEL ANALYSIS")
    print("=" * 65)

    df = pd.read_csv(INPUT)

    if df["normalized_name"].duplicated().any():
        raise ValueError("Duplicate package names detected.")

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

    X_train = df.loc[train_idx, FEATURES]
    X_test = df.loc[test_idx, FEATURES]

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

    print("\nCLASSIFICATION REPORT")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "presumed_legitimate",
                "openssf_candidate",
            ],
            zero_division=0,
        )
    )

    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))

    # Permutation importance on held-out test data.
    importance = permutation_importance(
        model,
        X_test,
        y_test,
        scoring="f1",
        n_repeats=10,
        random_state=SEED,
        n_jobs=-1,
    )

    importance_df = pd.DataFrame({
        "feature": FEATURES,
        "importance_mean": importance.importances_mean,
        "importance_std": importance.importances_std,
    }).sort_values(
        "importance_mean",
        ascending=False,
    )

    print("\nPERMUTATION FEATURE IMPORTANCE")
    print(importance_df.to_string(index=False))

    # Evaluate performance by historical upload year.
    dates = pd.to_datetime(
        df.loc[test_idx, "first_upload_time"],
        format="mixed",
        utc=True,
        errors="coerce",
    )

    if dates.isna().any():
        raise ValueError("Invalid test-set timestamps.")

    test_results = pd.DataFrame({
        "normalized_name": df.loc[
            test_idx, "normalized_name"
        ].to_numpy(),
        "upload_year": dates.dt.year.to_numpy(),
        "actual_candidate_group": y_test.to_numpy(),
        "predicted_candidate_group": predictions,
    })

    test_results["correct"] = (
        test_results["actual_candidate_group"]
        == test_results["predicted_candidate_group"]
    )

    year_results = (
        test_results.groupby("upload_year")
        .agg(
            records=("correct", "size"),
            accuracy=("correct", "mean"),
        )
        .reset_index()
    )

    print("\nPERFORMANCE BY UPLOAD YEAR")
    print(year_results.to_string(index=False))

    OUT.mkdir(parents=True, exist_ok=True)

    importance_df.to_csv(
        OUT / "feature_importance.csv",
        index=False,
    )

    test_results.to_csv(
        OUT / "test_predictions.csv",
        index=False,
    )

    year_results.to_csv(
        OUT / "performance_by_year.csv",
        index=False,
    )

    print("\n[SUCCESS] Model analysis completed.")
    print("Saved reports in:", OUT)
    print(
        "NOTE: Results measure provisional candidate-group "
        "classification, not verified malware detection."
    )


if __name__ == "__main__":
    main()
