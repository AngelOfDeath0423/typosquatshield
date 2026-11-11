
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data" / "full"
REPORTS = BASE / "reports"
REPORTS.mkdir(parents=True, exist_ok=True)

KEY = ["normalized_name", "version"]

history_path = DATA / "historical_openssf_evidence_matched.csv"
range_path = DATA / "openssf_version_range_validation.csv"
temporal_path = DATA / "openssf_temporal_evidence_audit.csv"

output_path = DATA / "training_label_eligibility_audit.csv"
review_path = DATA / "training_evidence_review_queue.csv"
report_path = REPORTS / "training_label_eligibility_report.txt"


def load_csv(path):
    if not path.exists():
        raise FileNotFoundError(path)

    return pd.read_csv(
        path,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )


def validate_unique(df, label):
    duplicates = df.duplicated(KEY).sum()
    if duplicates:
        raise ValueError(
            f"{label} contains {duplicates} duplicate keys."
        )


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - TRAINING LABEL ELIGIBILITY AUDIT")
    print("=" * 65)

    history = load_csv(history_path)
    ranges = load_csv(range_path)
    temporal = load_csv(temporal_path)

    validate_unique(history, "Historical evidence")
    validate_unique(ranges, "Range validation")
    validate_unique(temporal, "Temporal audit")

    print("Historical records:", len(history))
    print("Range validation records:", len(ranges))
    print("Temporal audit records:", len(temporal))

    if len(history) != len(ranges):
        raise ValueError(
            "Historical and range record counts differ."
        )

    # Preserve one historical record per package-version.
    range_fields = ranges[
        KEY + [
            "exact_version_match",
            "range_match",
            "range_has_candidate_report",
            "ambiguous_range_evaluation",
            "evidence_category",
        ]
    ].rename(columns={
        "evidence_category": "range_evidence_category",
    })

    result = history.merge(
        range_fields,
        on=KEY,
        how="left",
        validate="one_to_one",
        indicator=True,
    )

    if not result["_merge"].eq("both").all():
        raise ValueError("Missing range-validation matches.")

    result.drop(columns=["_merge"], inplace=True)

    # Temporal audit has report-level records. Aggregate safely.
    temporal["is_candidate"] = (
        temporal["label_status"].eq("candidate_malicious")
    )

    temporal["is_review"] = (
        temporal["label_status"].eq("needs_review")
    )

    temporal["is_consistent_candidate"] = (
        temporal["evidence_review_category"]
        .eq("candidate_temporally_consistent")
    )

    temporal["is_after_report"] = (
        temporal["evidence_review_category"]
        .eq("uploaded_after_report_review")
    )

    summary = (
        temporal.groupby(KEY, as_index=False)
        .agg(
            report_count=("report_id", "nunique"),
            candidate_report_count=("is_candidate", "sum"),
            needs_review_report_count=("is_review", "sum"),
            consistent_candidate_count=(
                "is_consistent_candidate", "sum"
            ),
            after_report_count=("is_after_report", "sum"),
        )
    )

    result = result.merge(
        summary,
        on=KEY,
        how="left",
        validate="one_to_one",
    )

    count_columns = [
        "report_count",
        "candidate_report_count",
        "needs_review_report_count",
        "consistent_candidate_count",
        "after_report_count",
    ]

    for column in count_columns:
        result[column] = (
            pd.to_numeric(result[column], errors="coerce")
            .fillna(0)
            .astype(int)
        )

    # Conservative evidence eligibility categories.
    result["training_evidence_status"] = "unlabeled"

    # Name-only evidence cannot establish maliciousness.
    result.loc[
        result["range_evidence_category"].eq(
            "range_supported_evidence"
        ),
        "training_evidence_status",
    ] = "range_evidence_review"

    # Exact evidence with no consistent candidate requires review.
    result.loc[
        (result["report_count"] > 0)
        & (result["consistent_candidate_count"] == 0),
        "training_evidence_status",
    ] = "exact_evidence_review"

    # Temporally consistent candidate reports form a preliminary pool.
    result.loc[
        (result["consistent_candidate_count"] > 0)
        & (result["needs_review_report_count"] == 0)
        & (result["after_report_count"] == 0),
        "training_evidence_status",
    ] = "candidate_training_review"

    # Mixed report evidence must be reviewed.
    result.loc[
        (result["needs_review_report_count"] > 0)
        | (result["after_report_count"] > 0),
        "training_evidence_status",
    ] = "conflicting_or_temporal_review"

    # Preserve uncertainty. Do not assign final labels.
    result["ml_label"] = "unassigned"

    result.to_csv(
        output_path,
        index=False,
        encoding="utf-8-sig",
    )

    review = result[
        result["training_evidence_status"].ne("unlabeled")
    ].copy()

    review.to_csv(
        review_path,
        index=False,
        encoding="utf-8-sig",
    )

    counts = result[
        "training_evidence_status"
    ].value_counts()

    report = [
        "TYPOSQUATSHIELD - TRAINING LABEL ELIGIBILITY",
        "=" * 60,
        f"Historical records: {len(result)}",
        "",
        "EVIDENCE CATEGORIES:",
        *(f"{key}: {value}" for key, value in counts.items()),
        "",
        f"Evidence review queue: {len(review)}",
        "",
        "LIMITATIONS:",
        "Candidate training records are not verified malware.",
        "Range-only records require further source review.",
        "Name-only records are not benign labels.",
        "No final ML labels assigned.",
        "Feature-time leakage must be checked before training.",
    ]

    report_path.write_text(
        "\n".join(report),
        encoding="utf-8",
    )

    print()
    print("\n".join(report))
    print()
    print("Saved:", output_path)
    print("Saved:", review_path)
    print("Saved:", report_path)
    print()
    print("[SUCCESS] Training-label eligibility audit completed.")


if __name__ == "__main__":
    main()
