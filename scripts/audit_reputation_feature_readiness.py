
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

CANDIDATES = BASE / "data/full/year_matched_ml_candidates.csv"

OPENSSF_HISTORY = (
    BASE / "data/full/historical_metadata_consolidated.csv"
)

LEGITIMATE_HISTORY = (
    BASE / "data/legitimate/legitimate_historical_consolidated.csv"
)

REPORT = BASE / "reports/reputation_feature_readiness.txt"


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - REPUTATION FEATURE READINESS")
    print("=" * 65)

    candidates = pd.read_csv(CANDIDATES)
    openssf = pd.read_csv(OPENSSF_HISTORY)
    legitimate = pd.read_csv(LEGITIMATE_HISTORY)

    history = pd.concat(
        [openssf, legitimate],
        ignore_index=True,
    )

    required = [
        "normalized_name",
        "version",
        "first_upload_time",
    ]

    for name, df in [
        ("candidates", candidates),
        ("history", history),
    ]:
        missing = set(required) - set(df.columns)

        if missing:
            raise ValueError(
                f"{name} missing columns: {sorted(missing)}"
            )

    for df in [candidates, history]:
        df["normalized_name"] = (
            df["normalized_name"]
            .astype(str)
            .str.strip()
            .str.lower()
        )

        df["version"] = (
            df["version"]
            .astype(str)
            .str.strip()
        )

        df["first_upload_time"] = pd.to_datetime(
            df["first_upload_time"],
            format="mixed",
            utc=True,
            errors="coerce",
        )

    if candidates["first_upload_time"].isna().any():
        raise ValueError("Invalid candidate timestamps.")

    if history["first_upload_time"].isna().any():
        raise ValueError("Invalid historical timestamps.")

    candidate_keys = candidates[
        ["normalized_name", "version", "first_upload_time"]
    ].drop_duplicates()

    history_keys = history[
        ["normalized_name", "version", "first_upload_time"]
    ].drop_duplicates()

    matched = candidate_keys.merge(
        history_keys,
        on=[
            "normalized_name",
            "version",
            "first_upload_time",
        ],
        how="left",
        indicator=True,
    )

    missing_matches = matched[
        matched["_merge"] == "left_only"
    ]

    candidate_names = set(
        candidates["normalized_name"]
    )

    history_names = set(
        history["normalized_name"]
    )

    available_names = candidate_names & history_names

    report = [
        "TYPOSQUATSHIELD - REPUTATION FEATURE READINESS",
        "=" * 65,
        f"Candidate records: {len(candidates)}",
        f"Historical records: {len(history)}",
        f"Candidate packages: {len(candidate_names)}",
        f"Packages found in history: {len(available_names)}",
        f"Exact candidate version/timestamp matches: "
        f"{(matched['_merge'] == 'both').sum()}",
        f"Missing exact matches: {len(missing_matches)}",
        "",
        "HISTORICAL RECORD COUNTS FOR CANDIDATE PACKAGES",
    ]

    counts = (
        history[
            history["normalized_name"].isin(candidate_names)
        ]
        .groupby("normalized_name")
        .size()
    )

    report.extend([
        counts.describe().to_string(),
        "",
        "LIMITATIONS",
        "Historical records may represent aggregated version data.",
        "Version upload timestamps are not necessarily the",
        "package's original publication timestamps.",
        "Historical data completeness requires verification.",
        "Assessment-time leakage must be prevented.",
    ])

    REPORT.parent.mkdir(parents=True, exist_ok=True)

    REPORT.write_text(
        "\n".join(report),
        encoding="utf-8",
    )

    print("\n".join(report))
    print()
    print("Saved:", REPORT)
    print("[SUCCESS] Reputation readiness audit completed.")


if __name__ == "__main__":
    main()
