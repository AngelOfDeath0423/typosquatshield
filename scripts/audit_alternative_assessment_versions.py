
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

CANDIDATES = BASE / "data/full/year_matched_ml_candidates.csv"

HISTORY_FILES = [
    BASE / "data/full/historical_metadata_consolidated.csv",
    BASE / "data/legitimate/legitimate_historical_consolidated.csv",
]

OUTPUT = BASE / "reports/alternative_assessment_versions.csv"
REPORT = BASE / "reports/alternative_assessment_summary.txt"


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - ALTERNATIVE ASSESSMENT AUDIT")
    print("=" * 65)

    candidates = pd.read_csv(
        CANDIDATES,
        dtype={"normalized_name": str, "version": str},
    )

    history = pd.concat(
        [
            pd.read_csv(
                path,
                dtype={"normalized_name": str, "version": str},
            )
            for path in HISTORY_FILES
        ],
        ignore_index=True,
    )

    for frame in [candidates, history]:
        frame["normalized_name"] = (
            frame["normalized_name"]
            .str.strip()
            .str.lower()
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
        raise ValueError("Duplicate candidate package names.")

    names = set(candidates["normalized_name"])

    history = history[
        history["normalized_name"].isin(names)
    ].copy()

    grouped = {
        name: group.sort_values("first_upload_time")
        for name, group in history.groupby("normalized_name")
    }

    records = []

    for row in candidates.itertuples(index=False):
        name = row.normalized_name
        selected_time = row.first_upload_time

        package_history = grouped[name]

        earlier = package_history[
            package_history["first_upload_time"] < selected_time
        ]

        later = package_history[
            package_history["first_upload_time"] > selected_time
        ]

        # Latest observed version is only a diagnostic example.
        latest = package_history.iloc[-1]
        latest_time = latest["first_upload_time"]

        prior_to_latest = package_history[
            package_history["first_upload_time"] < latest_time
        ]

        records.append({
            "normalized_name": name,
            "candidate_group": row.candidate_group,
            "selected_version": row.version,
            "selected_timestamp": selected_time.isoformat(),
            "selected_prior_records": len(earlier),
            "later_observed_records": len(later),
            "has_later_version": int(len(later) > 0),
            "latest_observed_version": latest["version"],
            "latest_observed_timestamp": latest_time.isoformat(),
            "prior_records_at_latest": len(prior_to_latest),
            "latest_has_prior_history": int(
                len(prior_to_latest) > 0
            ),
        })

    result = pd.DataFrame(records)

    summary = result.groupby("candidate_group").agg(
        packages=("normalized_name", "count"),
        with_later_versions=("has_later_version", "sum"),
        with_prior_at_selected=(
            "selected_prior_records",
            lambda x: int((x > 0).sum()),
        ),
        with_prior_at_latest=(
            "latest_has_prior_history",
            "sum",
        ),
        median_later_records=(
            "later_observed_records",
            "median",
        ),
        median_prior_at_latest=(
            "prior_records_at_latest",
            "median",
        ),
    )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(OUTPUT, index=False)

    lines = [
        "TYPOSQUATSHIELD - ALTERNATIVE ASSESSMENT AUDIT",
        "=" * 65,
        f"Candidate packages: {len(result)}",
        "",
        "GROUP SUMMARY",
        summary.to_string(),
        "",
        "LATER RECORD DISTRIBUTION",
        result["later_observed_records"].describe().to_string(),
        "",
        "LIMITATIONS",
        "Latest observed versions are diagnostic examples only.",
        "Later OpenSSF versions must not inherit labels automatically.",
        "Prior records are counted using strictly earlier times.",
        "Historical completeness is not established.",
        "Upload timestamps are provisional assessment times.",
        "No existing candidate files have been modified.",
    ]

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print("\n".join(lines))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Alternative assessment audit completed.")


if __name__ == "__main__":
    main()
