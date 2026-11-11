
from pathlib import Path
import pandas as pd

from static_feature_extractor import FEATURES

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/artifacts/batch_static_features.csv"
CANDIDATES = BASE / "data/full/version_aware_matched_candidates.csv"

OUTPUT = BASE / "data/artifacts/package_level_static_features.csv"
REPORT = BASE / "reports/package_level_static_feature_report.txt"

KEYS = [
    "normalized_name",
    "version",
]

def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - PACKAGE-LEVEL STATIC FEATURES")
    print("=" * 65)

    df = pd.read_csv(INPUT, dtype={"version": str})
    candidates = pd.read_csv(
        CANDIDATES,
        dtype={"version": str},
    )

    required = set(KEYS + [
        "candidate_group",
        "artifact_type",
        "scan_status",
    ] + list(FEATURES))

    missing = required - set(df.columns)

    if missing:
        raise ValueError(
            f"Missing static columns: {sorted(missing)}"
        )

    if len(candidates) != 4410:
        raise ValueError("Unexpected candidate count.")

    if candidates[KEYS].duplicated().any():
        raise ValueError("Duplicate candidate package versions.")

    # Only complete scans can supply usable features.
    complete = df[
        df["scan_status"] == "complete"
    ].copy()

    priority = {
        "sdist_tar_gz": 0,
        "wheel": 1,
    }

    complete["artifact_priority"] = (
        complete["artifact_type"]
        .map(priority)
        .fillna(99)
    )

    # Select exactly one archive per package version.
    selected = (
        complete.sort_values(
            KEYS + [
                "artifact_priority",
                "filename",
            ]
        )
        .drop_duplicates(
            subset=KEYS,
            keep="first",
        )
        .copy()
    )

    selected = selected[
        KEYS + [
            "artifact_type",
            "filename",
        ] + list(FEATURES)
    ].copy()

    selected = selected.rename(
        columns={
            "artifact_type": "selected_static_artifact_type",
            "filename": "selected_static_filename",
        }
    )

    result = candidates[
        KEYS + ["candidate_group"]
    ].merge(
        selected,
        on=KEYS,
        how="left",
        validate="one_to_one",
    )

    result["static_available"] = (
        result["selected_static_filename"].notna()
    ).astype(int)

    if len(result) != 4410:
        raise ValueError("Output count mismatch.")

    if result[KEYS].duplicated().any():
        raise ValueError("Duplicate output package versions.")

    # No zero-filling: unavailable static data stays missing.
    unavailable = result["static_available"] == 0

    if result.loc[
        unavailable, list(FEATURES)
    ].notna().any().any():
        raise ValueError(
            "Unavailable static features must remain missing."
        )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    result.to_csv(OUTPUT, index=False)

    coverage = (
        result.groupby("candidate_group")[
            "static_available"
        ]
        .agg(["sum", "count", "mean"])
        .round(4)
    )

    selected_types = (
        result[
            result["static_available"] == 1
        ]
        .groupby([
            "candidate_group",
            "selected_static_artifact_type",
        ])
        .size()
    )

    lines = [
        "TYPOSQUATSHIELD - PACKAGE-LEVEL STATIC FEATURE REPORT",
        "=" * 65,
        f"Archive scan records: {len(df)}",
        f"Complete archive scans: {len(complete)}",
        f"Selected package versions: {len(selected)}",
        f"Candidate records: {len(result)}",
        f"Candidates with static features: "
        f"{int(result['static_available'].sum())}",
        f"Candidates without static features: "
        f"{int((result['static_available'] == 0).sum())}",
        "",
        "STATIC COVERAGE BY CANDIDATE GROUP",
        coverage.to_string(),
        "",
        "SELECTED ARTIFACT TYPES",
        selected_types.to_string(),
        "",
        "LIMITATIONS",
        "One complete archive is selected per package version.",
        "Source distributions are preferred over wheels.",
        "Partial scans are excluded.",
        "Missing static features remain missing.",
        "Current artifact availability may introduce selection bias.",
        "Static indicators are not proof of maliciousness.",
        "Candidate-group labels remain provisional.",
        "No ML training performed.",
    ]

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print("\n".join(lines))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Static aggregation completed.")


if __name__ == "__main__":
    main()
