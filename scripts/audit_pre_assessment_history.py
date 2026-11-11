
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

CANDIDATES = BASE / "data/full/year_matched_ml_candidates.csv"

HISTORY_FILES = [
    BASE / "data/full/historical_metadata_consolidated.csv",
    BASE / "data/legitimate/legitimate_historical_consolidated.csv",
]

OUTPUT = BASE / "reports/pre_assessment_history_audit.csv"
REPORT = BASE / "reports/pre_assessment_history_summary.txt"


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - PRE-ASSESSMENT HISTORY AUDIT")
    print("=" * 65)

    candidates = pd.read_csv(CANDIDATES, dtype={
        "normalized_name": str,
        "version": str,
    })

    histories = [
        pd.read_csv(
            path,
            dtype={
                "normalized_name": str,
                "version": str,
            },
        )
        for path in HISTORY_FILES
    ]

    history = pd.concat(histories, ignore_index=True)

    for frame in (candidates, history):
        frame["normalized_name"] = (
            frame["normalized_name"].str.strip().str.lower()
        )

        frame["first_upload_time"] = pd.to_datetime(
            frame["first_upload_time"],
            format="mixed",
            utc=True,
            errors="coerce",
        )

        if frame["first_upload_time"].isna().any():
            raise ValueError("Invalid timestamps detected.")

    if candidates["normalized_name"].duplicated().any():
        raise ValueError("Duplicate candidate names detected.")

    candidate_names = set(candidates["normalized_name"])

    history = history[
        history["normalized_name"].isin(candidate_names)
    ].copy()

    grouped_history = {
        name: group.sort_values("first_upload_time")
        for name, group in history.groupby("normalized_name")
    }

    records = []

    for row in candidates.itertuples(index=False):
        name = row.normalized_name
        cutoff = row.first_upload_time

        package_history = grouped_history[name]

        # Strictly earlier timestamps only.
        # Current and future versions are excluded.
        prior = package_history[
            package_history["first_upload_time"] < cutoff
        ]

        records.append({
            "normalized_name": name,
            "candidate_group": row.candidate_group,
            "assessment_timestamp": cutoff.isoformat(),
            "total_historical_records": len(package_history),
            "prior_version_records": len(prior),
            "has_prior_history": int(len(prior) > 0),
            "is_first_observed_version": int(len(prior) == 0),
        })

    result = pd.DataFrame(records)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    result.to_csv(OUTPUT, index=False)

    summary = result.groupby("candidate_group").agg(
        packages=("normalized_name", "count"),
        with_prior_history=("has_prior_history", "sum"),
        without_prior_history=("is_first_observed_version", "sum"),
        mean_prior_records=("prior_version_records", "mean"),
        median_prior_records=("prior_version_records", "median"),
    )

    lines = [
        "TYPOSQUATSHIELD - PRE-ASSESSMENT HISTORY SUMMARY",
        "=" * 65,
        f"Candidate packages: {len(result)}",
        "",
        "HISTORY AVAILABILITY BY GROUP",
        summary.to_string(),
        "",
        "OVERALL PRIOR RECORD DISTRIBUTION",
        result["prior_version_records"].describe().to_string(),
        "",
        "LIMITATIONS",
        "Only strictly earlier upload timestamps are counted.",
        "Same-timestamp records are excluded conservatively.",
        "First observed does not prove first-ever release.",
        "Historical metadata may be incomplete.",
        "Upload time is a provisional assessment cutoff.",
        "Historical source availability is not fully verified.",
    ]

    REPORT.write_text("\n".join(lines), encoding="utf-8")

    print("\n".join(lines))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Pre-assessment history audit completed.")


if __name__ == "__main__":
    main()
