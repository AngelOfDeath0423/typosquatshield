
from pathlib import Path
import numpy as np
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

CANDIDATES = BASE / "data/features/version_aware_reputation_features.csv"

HISTORY_FILES = [
    BASE / "data/full/historical_metadata_consolidated.csv",
    BASE / "data/legitimate/legitimate_historical_consolidated.csv",
]

OUTPUT = BASE / "reports/short_release_interval_details.csv"
REPORT = BASE / "reports/short_release_interval_audit.txt"


def prepare(df):
    df = df.copy()

    df["normalized_name"] = (
        df["normalized_name"]
        .astype("string")
        .str.strip()
        .str.lower()
    )

    df["version"] = (
        df["version"].astype("string").str.strip()
    )

    df["first_upload_time"] = pd.to_datetime(
        df["first_upload_time"],
        format="mixed",
        utc=True,
        errors="raise",
    )

    return df


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - SHORT RELEASE INTERVAL AUDIT")
    print("=" * 65)

    candidates = prepare(pd.read_csv(
        CANDIDATES,
        dtype={"version": str},
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

    selected_names = set(candidates["normalized_name"])

    history = history[
        history["normalized_name"].isin(selected_names)
    ].copy()

    grouped = {
        name: group.sort_values(
            ["first_upload_time", "version"]
        ).reset_index(drop=True)
        for name, group in history.groupby("normalized_name")
    }

    records = []

    for row in candidates.itertuples(index=False):
        if row.prior_release_count == 0:
            continue

        package_history = grouped[row.normalized_name]

        prior = package_history[
            package_history["first_upload_time"]
            < row.first_upload_time
        ]

        if prior.empty:
            raise ValueError(
                f"Missing prior record: {row.normalized_name}"
            )

        previous = prior.iloc[-1]

        interval_hours = (
            row.first_upload_time
            - previous["first_upload_time"]
        ).total_seconds() / 3600

        same_version = (
            str(row.version) == str(previous["version"])
        )

        records.append({
            "normalized_name": row.normalized_name,
            "candidate_group": row.candidate_group,
            "selected_version": row.version,
            "previous_version": previous["version"],
            "selected_timestamp": row.first_upload_time,
            "previous_timestamp": previous["first_upload_time"],
            "interval_hours": interval_hours,
            "within_one_hour": int(interval_hours < 1),
            "within_one_day": int(interval_hours < 24),
            "same_version_as_previous": int(same_version),
            "prior_release_count": row.prior_release_count,
            "history_bucket": row.history_bucket,
            "previous_distribution_file_count": (
                previous.get("distribution_file_count", np.nan)
            ),
        })

    result = pd.DataFrame(records)

    if len(result) != 1566:
        raise ValueError(
            f"Unexpected prior-history records: {len(result)}"
        )

    if (result["interval_hours"] <= 0).any():
        raise ValueError("Non-positive intervals detected.")

    summary = result.groupby("candidate_group").agg(
        packages=("normalized_name", "count"),
        within_hour=("within_one_hour", "sum"),
        within_day=("within_one_day", "sum"),
        same_version=("same_version_as_previous", "sum"),
        median_interval_hours=("interval_hours", "median"),
    )

    short = result[
        result["within_one_hour"] == 1
    ].copy()

    same_version_short = short.groupby(
        "candidate_group"
    )["same_version_as_previous"].agg(["sum", "count"])

    examples = short.sort_values(
        "interval_hours"
    )[
        [
            "normalized_name",
            "candidate_group",
            "selected_version",
            "previous_version",
            "interval_hours",
            "same_version_as_previous",
            "previous_distribution_file_count",
        ]
    ].head(30)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    result.to_csv(OUTPUT, index=False)

    lines = [
        "TYPOSQUATSHIELD - SHORT RELEASE INTERVAL AUDIT",
        "=" * 65,
        f"Packages with prior history: {len(result)}",
        "",
        "GROUP SUMMARY",
        summary.round(4).to_string(),
        "",
        "SAME-VERSION RECORDS AMONG SHORT INTERVALS",
        same_version_short.to_string(),
        "",
        "FIRST 30 SHORTEST INTERVALS",
        examples.round(4).to_string(index=False),
        "",
        "LIMITATIONS",
        "Same-version matches may indicate source duplication",
        "or multiple historical observations.",
        "Different versions do not establish independent releases.",
        "Distribution counts alone do not establish provenance.",
        "Timestamp and source completeness remain unverified.",
        "Candidate labels are provisional.",
        "No model training performed.",
    ]

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print("\n".join(lines))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Short interval audit completed.")


if __name__ == "__main__":
    main()
