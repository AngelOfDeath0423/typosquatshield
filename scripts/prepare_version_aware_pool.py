
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

CANDIDATES = BASE / "data/full/year_matched_ml_candidates.csv"
EVIDENCE = BASE / "data/full/training_label_eligibility_audit.csv"

HISTORY_FILES = [
    BASE / "data/full/historical_metadata_consolidated.csv",
    BASE / "data/legitimate/legitimate_historical_consolidated.csv",
]

OUT = BASE / "data/full/version_aware_assessment_pool.csv"
REPORT = BASE / "reports/version_aware_pool_report.txt"

KEY = ["normalized_name", "version", "first_upload_time"]


def prepare(df):
    df = df.copy()
    df["normalized_name"] = (
        df["normalized_name"].astype("string")
        .str.strip().str.lower()
    )
    df["version"] = df["version"].astype("string").str.strip()
    df["first_upload_time"] = pd.to_datetime(
        df["first_upload_time"],
        format="mixed",
        utc=True,
        errors="coerce",
    )

    if df[KEY].isna().any().any():
        raise ValueError("Missing or invalid package keys.")

    return df


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - VERSION-AWARE ASSESSMENT POOL")
    print("=" * 65)

    candidates = prepare(pd.read_csv(CANDIDATES))
    evidence = prepare(pd.read_csv(EVIDENCE))

    history = prepare(pd.concat(
        [pd.read_csv(path) for path in HISTORY_FILES],
        ignore_index=True,
    ))

    if candidates["normalized_name"].duplicated().any():
        raise ValueError("Duplicate selected package names.")

    if history.duplicated(KEY).any():
        raise ValueError("Duplicate historical version keys.")

    if evidence.duplicated(KEY).any():
        raise ValueError("Duplicate evidence version keys.")

    positive_group = "openssf_exact_version_candidate"
    negative_group = "presumed_legitimate"

    positives = set(
        candidates.loc[
            candidates["candidate_group"] == positive_group,
            "normalized_name",
        ]
    )

    negatives = set(
        candidates.loc[
            candidates["candidate_group"] == negative_group,
            "normalized_name",
        ]
    )

    if positives & negatives:
        raise ValueError("Candidate groups overlap.")

    selected_names = positives | negatives

    history = history[
        history["normalized_name"].isin(selected_names)
    ].copy()

    # Count records with strictly earlier timestamps.
    # Equal-timestamp records are not counted.
    history = history.sort_values(
        ["normalized_name", "first_upload_time", "version"]
    ).reset_index(drop=True)

    history["prior_version_records"] = (
        history.groupby("normalized_name")["first_upload_time"]
        .rank(method="min")
        .astype(int) - 1
    )

    history["assessment_year"] = (
        history["first_upload_time"].dt.year
    )

    history["history_bucket"] = pd.cut(
        history["prior_version_records"],
        bins=[-1, 0, 2, 10, float("inf")],
        labels=["0", "1-2", "3-10", "11+"],
    )

    eligible = evidence.loc[
        evidence["training_evidence_status"]
        == "candidate_training_review",
        KEY
    ].drop_duplicates()

    positive_pool = history[
        history["normalized_name"].isin(positives)
    ].merge(
        eligible.assign(exact_evidence_candidate=True),
        on=KEY,
        how="inner",
        validate="one_to_one",
    )

    negative_pool = history[
        history["normalized_name"].isin(negatives)
    ].copy()

    negative_pool["exact_evidence_candidate"] = False

    positive_pool["candidate_group"] = positive_group
    negative_pool["candidate_group"] = negative_group

    pool = pd.concat(
        [positive_pool, negative_pool],
        ignore_index=True,
    )

    pool["label_verified"] = False
    pool["ml_label"] = "unassigned"

    # This is a diagnostic pool, not a final training set.
    pool["assessment_selection_status"] = (
        "diagnostic_pool_only"
    )

    pool = pool.sort_values(
        ["candidate_group", "normalized_name", "first_upload_time"]
    ).reset_index(drop=True)

    summary = pool.groupby(
        "candidate_group"
    ).agg(
        version_records=("version", "size"),
        unique_packages=("normalized_name", "nunique"),
        with_prior_history=(
            "prior_version_records",
            lambda x: int((x > 0).sum()),
        ),
    )

    strata = (
        pool.groupby(
            ["candidate_group", "assessment_year", "history_bucket"],
            observed=True,
        )["normalized_name"]
        .nunique()
        .rename("unique_packages")
        .reset_index()
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    pool.to_csv(OUT, index=False)

    lines = [
        "TYPOSQUATSHIELD - VERSION-AWARE POOL REPORT",
        "=" * 65,
        f"Total version records: {len(pool)}",
        f"Unique packages: {pool['normalized_name'].nunique()}",
        "",
        "GROUP SUMMARY",
        summary.to_string(),
        "",
        "YEAR AND PRIOR-HISTORY STRATA",
        strata.to_string(index=False),
        "",
        "LIMITATIONS",
        "This is a diagnostic pool, not a final ML dataset.",
        "No verified malicious or benign labels are assigned.",
        "OpenSSF versions require exact candidate-review evidence.",
        "Positive names are restricted to the existing matched cohort.",
        "Negative versions are presumed legitimate only.",
        "Prior history uses strictly earlier observed upload times.",
        "No assessment versions have been selected yet.",
        "Year/history matching and temporal validation remain.",
    ]

    REPORT.write_text("\n".join(lines), encoding="utf-8")

    print("\n".join(lines))
    print()
    print("Saved:", OUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Version-aware pool prepared.")


if __name__ == "__main__":
    main()
