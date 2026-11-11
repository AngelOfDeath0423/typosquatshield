
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

PREDICTIONS = BASE / "reports/version_aware_ml/test_predictions.csv"
FEATURES = BASE / "data/features/version_aware_combined_features.csv"

OUTPUT = BASE / "reports/version_aware_ml/prediction_changes.csv"
REPORT = BASE / "reports/version_aware_ml/prediction_change_audit.txt"

EXPERIMENTS = [
    "A_metadata_similarity",
    "B_plus_history",
    "C_full_reputation",
]


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - PREDICTION CHANGE AUDIT")
    print("=" * 65)

    predictions = pd.read_csv(
        PREDICTIONS,
        dtype={"version": str},
    )

    features = pd.read_csv(
        FEATURES,
        dtype={"version": str},
    )

    key = ["normalized_name", "version", "matched_pair_id"]

    if predictions.duplicated(key + ["experiment"]).any():
        raise ValueError("Duplicate experiment predictions.")

    if set(predictions["experiment"]) != set(EXPERIMENTS):
        raise ValueError("Unexpected experiment names.")

    wide = predictions.pivot(
        index=key,
        columns="experiment",
        values="predicted_group_code",
    ).reset_index()

    if len(wide) != 1104:
        raise ValueError("Unexpected test record count.")

    if wide[EXPERIMENTS].isna().any().any():
        raise ValueError("Missing predictions.")

    actual = predictions[
        predictions["experiment"] == EXPERIMENTS[0]
    ][key + ["candidate_group", "true_group_code"]]

    wide = wide.merge(
        actual,
        on=key,
        validate="one_to_one",
    )

    extra = [
        "prior_release_count",
        "has_prior_history",
        "observed_package_age_days",
        "days_since_previous_release",
        "prior_release_span_days",
        "history_bucket",
        "first_upload_time",
    ]

    wide = wide.merge(
        features[key + extra],
        on=key,
        validate="one_to_one",
    )

    for experiment in EXPERIMENTS:
        wide[experiment + "_correct"] = (
            wide[experiment] == wide["true_group_code"]
        )

    a = EXPERIMENTS[0]
    b = EXPERIMENTS[1]
    c = EXPERIMENTS[2]

    wide["A_to_C_changed"] = wide[a] != wide[c]
    wide["B_to_C_changed"] = wide[b] != wide[c]

    wide["A_to_C_outcome"] = "unchanged"

    wide.loc[
        wide["A_to_C_changed"]
        & wide[c + "_correct"],
        "A_to_C_outcome",
    ] = "corrected"

    wide.loc[
        wide["A_to_C_changed"]
        & ~wide[c + "_correct"],
        "A_to_C_outcome",
    ] = "became_incorrect"

    summary = pd.crosstab(
        wide["candidate_group"],
        wide["A_to_C_outcome"],
    )

    history_summary = pd.crosstab(
        wide["history_bucket"],
        wide["A_to_C_outcome"],
    )

    changes = wide[wide["A_to_C_changed"]].copy()

    corrected = (
        changes["A_to_C_outcome"] == "corrected"
    ).sum()

    worsened = (
        changes["A_to_C_outcome"] == "became_incorrect"
    ).sum()

    lines = [
        "TYPOSQUATSHIELD - PREDICTION CHANGE AUDIT",
        "=" * 65,
        f"Test records: {len(wide)}",
        f"A to C changed predictions: {len(changes)}",
        f"B to C changed predictions: "
        f"{wide['B_to_C_changed'].sum()}",
        f"A to C corrected predictions: {corrected}",
        f"A to C newly incorrect predictions: {worsened}",
        "",
        "CHANGES BY CANDIDATE GROUP",
        summary.to_string(),
        "",
        "CHANGES BY HISTORY BUCKET",
        history_summary.to_string(),
        "",
        "FIRST 25 CHANGED PREDICTIONS",
        changes[
            [
                "normalized_name",
                "candidate_group",
                "history_bucket",
                "prior_release_count",
                "A_to_C_outcome",
                a,
                c,
            ]
        ].head(25).to_string(index=False),
        "",
        "LIMITATIONS",
        "Results describe provisional candidate groups.",
        "Changes do not establish malware detection.",
        "Timing and historical-source bias remain possible.",
        "No new model training was performed.",
    ]

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    wide.to_csv(OUTPUT, index=False)

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print("\n".join(lines))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Prediction change audit completed.")


if __name__ == "__main__":
    main()
