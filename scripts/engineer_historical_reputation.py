
from pathlib import Path
import numpy as np
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/full/version_aware_matched_candidates.csv"

HISTORY_FILES = [
    BASE / "data/full/historical_metadata_consolidated.csv",
    BASE / "data/legitimate/legitimate_historical_consolidated.csv",
]

OUTPUT = BASE / "data/features/version_aware_reputation_features.csv"
REPORT = BASE / "reports/historical_reputation_feature_report.txt"

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
        errors="raise",
    )
    return df


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - HISTORICAL REPUTATION FEATURES")
    print("=" * 65)

    candidates = prepare(pd.read_csv(
        INPUT, dtype={"version": str}
    ))

    history = prepare(pd.concat(
        [
            pd.read_csv(path, dtype={"version": str})
            for path in HISTORY_FILES
        ],
        ignore_index=True,
    ))

    if candidates["normalized_name"].duplicated().any():
        raise ValueError("Duplicate candidate packages.")

    if history.duplicated(KEY).any():
        raise ValueError("Duplicate historical records.")

    if len(candidates) != 4410:
        raise ValueError("Unexpected candidate count.")

    selected_names = set(candidates["normalized_name"])

    history = history[
        history["normalized_name"].isin(selected_names)
    ].copy()

    history = history.sort_values(
        ["normalized_name", "first_upload_time", "version"]
    )

    grouped = {
        name: group["first_upload_time"].to_numpy(
            dtype="datetime64[ns]"
        )
        for name, group in history.groupby("normalized_name")
    }

    records = []

    for row in candidates.itertuples(index=False):
        name = row.normalized_name
        cutoff = np.datetime64(
            row.first_upload_time.tz_convert("UTC").tz_localize(None),
            "ns",
        )

        times = grouped[name]

        # Strictly earlier releases only.
        prior_count = int(np.searchsorted(
            times, cutoff, side="left"
        ))

        if prior_count:
            first = pd.Timestamp(times[0])
            previous = pd.Timestamp(times[prior_count - 1])
            assessment = pd.Timestamp(cutoff)

            age = (assessment - first).total_seconds() / 86400
            since_previous = (
                assessment - previous
            ).total_seconds() / 86400
            span = (previous - first).total_seconds() / 86400
        else:
            age = np.nan
            since_previous = np.nan
            span = np.nan

        records.append({
            "normalized_name": name,
            "prior_release_count": prior_count,
            "has_prior_history": int(prior_count > 0),
            "observed_package_age_days": age,
            "days_since_previous_release": since_previous,
            "prior_release_span_days": span,
        })

    features = pd.DataFrame(records)

    result = candidates.merge(
        features,
        on="normalized_name",
        how="left",
        validate="one_to_one",
    )

    # Verify against the previously calculated counts.
    mismatches = (
        result["prior_release_count"]
        != result["prior_version_records"]
    )

    if mismatches.any():
        raise ValueError(
            f"Prior history count mismatch: {mismatches.sum()}"
        )

    if (result["prior_release_count"] < 0).any():
        raise ValueError("Negative prior release count.")

    if (
        result.loc[
            result["has_prior_history"] == 1,
            [
                "observed_package_age_days",
                "days_since_previous_release",
                "prior_release_span_days",
            ],
        ].isna().any().any()
    ):
        raise ValueError("Unexpected missing reputation values.")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    result.to_csv(OUTPUT, index=False)

    summary = result.groupby("candidate_group").agg(
        records=("normalized_name", "size"),
        with_prior_history=("has_prior_history", "sum"),
        mean_prior_releases=("prior_release_count", "mean"),
        median_prior_releases=("prior_release_count", "median"),
        mean_observed_age_days=(
            "observed_package_age_days", "mean"
        ),
        median_observed_age_days=(
            "observed_package_age_days", "median"
        ),
        median_days_since_previous=(
            "days_since_previous_release", "median"
        ),
    )

    report = [
        "TYPOSQUATSHIELD - HISTORICAL REPUTATION FEATURES",
        "=" * 65,
        f"Input records: {len(candidates)}",
        f"Output records: {len(result)}",
        f"Unique packages: {result['normalized_name'].nunique()}",
        "New reputation features: 5",
        "",
        "GROUP SUMMARY",
        summary.round(3).to_string(),
        "",
        "VALIDATION",
        "Candidate/history prior-count consistency: PASS",
        "Strictly earlier timestamps used: PASS",
        "",
        "LIMITATIONS",
        "Age means age since first observed release,",
        "not verified original package creation date.",
        "Historical records may be incomplete.",
        "No prior history is not proof of a new package.",
        "Missing age and interval values require explicit",
        "handling before model training.",
        "Upload timestamps are provisional assessment cutoffs.",
        "Labels remain provisional, not verified malware truth.",
    ]

    REPORT.write_text("\n".join(report), encoding="utf-8")

    print("\n".join(report))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Reputation features engineered.")


if __name__ == "__main__":
    main()
