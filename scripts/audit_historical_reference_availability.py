
from pathlib import Path
import sys
import numpy as np
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
SCRIPTS = BASE / "scripts"

sys.path.insert(0, str(SCRIPTS))

from typosquatting_similarity import (
    load_reference_names,
    normalize_name,
)

from rapidfuzz.distance import DamerauLevenshtein

CANDIDATES = (
    BASE / "data/features/version_aware_combined_features.csv"
)

HISTORICAL_FILES = [
    BASE / "data/full/historical_metadata_consolidated.csv",
    BASE / "data/legitimate/legitimate_historical_consolidated.csv",
]

OUTPUT = (
    BASE / "reports/historical_reference_availability_audit.csv"
)

REFERENCE_OUTPUT = (
    BASE / "reports/historical_reference_inventory.csv"
)

REPORT = (
    BASE / "reports/historical_reference_availability_report.txt"
)

EXPECTED_CANDIDATES = 4410

FEATURE_COLUMNS = [
    "typo_min_edit_distance",
    "typo_max_similarity",
    "typo_potential_match",
    "typo_close_match_count",
    "typo_reference_length",
]


def parse_times(series):
    return pd.to_datetime(
        series,
        utc=True,
        errors="coerce",
    )


def load_historical_records():
    frames = []

    for path in HISTORICAL_FILES:
        if not path.exists():
            raise FileNotFoundError(
                f"Missing historical dataset: {path}"
            )

        frame = pd.read_csv(
            path,
            usecols=[
                "normalized_name",
                "first_upload_time",
            ],
        )

        frame["normalized_name"] = (
            frame["normalized_name"]
            .astype(str)
            .map(normalize_name)
        )

        frame["observed_time"] = parse_times(
            frame["first_upload_time"]
        )

        frames.append(
            frame[[
                "normalized_name",
                "observed_time",
            ]]
        )

    return pd.concat(
        frames,
        ignore_index=True,
    )


def build_reference_inventory(references, historical):
    earliest = (
        historical.dropna(subset=["observed_time"])
        .groupby("normalized_name")["observed_time"]
        .min()
    )

    records = []

    for reference in references:
        observed = earliest.get(reference, pd.NaT)

        records.append({
            "reference_package": reference,
            "earliest_observed_time": observed,
            "has_historical_evidence": pd.notna(observed),
        })

    return pd.DataFrame(records)


def calculate_historical_similarity(
    package_name,
    eligible_references,
):
    if not eligible_references:
        return {
            "historical_min_edit_distance": np.nan,
            "historical_max_similarity": np.nan,
            "historical_potential_match": np.nan,
            "historical_close_match_count": np.nan,
            "historical_reference_length": np.nan,
        }

    matches = []

    for reference in eligible_references:
        distance = DamerauLevenshtein.distance(
            package_name,
            reference,
        )

        similarity = (
            DamerauLevenshtein.normalized_similarity(
                package_name,
                reference,
            )
        )

        threshold = 1 if len(reference) <= 5 else 2

        matches.append({
            "reference": reference,
            "distance": distance,
            "similarity": similarity,
            "is_close": (
                package_name != reference
                and distance <= threshold
            ),
        })

    closest = min(
        matches,
        key=lambda item: (
            item["distance"],
            -item["similarity"],
            item["reference"],
        ),
    )

    return {
        "historical_min_edit_distance":
            closest["distance"],
        "historical_max_similarity":
            max(m["similarity"] for m in matches),
        "historical_potential_match":
            int(any(m["is_close"] for m in matches)),
        "historical_close_match_count":
            sum(m["is_close"] for m in matches),
        "historical_reference_length":
            len(closest["reference"]),
    }


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - HISTORICAL REFERENCE AUDIT")
    print("=" * 65)

    if not CANDIDATES.exists():
        raise FileNotFoundError(CANDIDATES)

    df = pd.read_csv(
        CANDIDATES,
        dtype={"version": str},
    )

    if len(df) != EXPECTED_CANDIDATES:
        raise ValueError(
            f"Expected {EXPECTED_CANDIDATES} records, "
            f"found {len(df)}"
        )

    if df["normalized_name"].duplicated().any():
        raise ValueError("Duplicate candidate package names.")

    missing = set(FEATURE_COLUMNS) - set(df.columns)

    if missing:
        raise ValueError(
            f"Missing similarity features: {sorted(missing)}"
        )

    df["assessment_time"] = parse_times(
        df["first_upload_time"]
    )

    if df["assessment_time"].isna().any():
        raise ValueError("Invalid assessment timestamps.")

    references = sorted({
        normalize_name(name)
        for name in load_reference_names()
    })

    historical = load_historical_records()

    inventory = build_reference_inventory(
        references,
        historical,
    )

    known = inventory[
        inventory["has_historical_evidence"]
    ].copy()

    known_times = dict(zip(
        known["reference_package"],
        known["earliest_observed_time"],
    ))

    unknown_references = set(references) - set(known_times)

    records = []

    for row in df.itertuples(index=False):
        name = normalize_name(row.normalized_name)
        cutoff = row.assessment_time

        # A reference is considered historically supported
        # only when its observed time is strictly earlier.
        eligible = [
            reference
            for reference, first_time in known_times.items()
            if first_time < cutoff
        ]

        not_yet_observed = [
            reference
            for reference, first_time in known_times.items()
            if first_time >= cutoff
        ]

        features = calculate_historical_similarity(
            name,
            eligible,
        )

        records.append({
            "normalized_name": name,
            "version": row.version,
            "candidate_group": row.candidate_group,
            "assessment_time": cutoff,
            "eligible_reference_count": len(eligible),
            "not_yet_observed_reference_count":
                len(not_yet_observed),
            "unknown_reference_count":
                len(unknown_references),
            "reference_coverage_complete":
                int(
                    len(eligible) == len(references)
                ),
            **features,
        })

    result = pd.DataFrame(records)

    if len(result) != len(df):
        raise ValueError("Audit output count mismatch.")

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    inventory.to_csv(
        REFERENCE_OUTPUT,
        index=False,
    )

    result.to_csv(
        OUTPUT,
        index=False,
    )

    known_count = int(
        inventory["has_historical_evidence"].sum()
    )

    zero_eligible = int(
        (result["eligible_reference_count"] == 0).sum()
    )

    incomplete_coverage = int(
        (result["reference_coverage_complete"] == 0).sum()
    )

    historical_match = result.groupby(
        "candidate_group"
    )["historical_potential_match"].agg(
        ["sum", "count"]
    )

    lines = [
        "TYPOSQUATSHIELD - HISTORICAL REFERENCE AVAILABILITY",
        "=" * 65,
        f"Candidate records: {len(df)}",
        f"Curated reference packages: {len(references)}",
        f"References with observed historical evidence: "
        f"{known_count}",
        f"References without observed evidence: "
        f"{len(unknown_references)}",
        "",
        "CANDIDATE REFERENCE COVERAGE",
        f"Candidates with zero eligible references: "
        f"{zero_eligible}",
        f"Candidates without complete reference coverage: "
        f"{incomplete_coverage}",
        "",
        "ELIGIBLE REFERENCE COUNT DISTRIBUTION",
        result["eligible_reference_count"]
        .describe()
        .to_string(),
        "",
        "HISTORICALLY SUPPORTED POTENTIAL TYPO MATCHES",
        historical_match.to_string(),
        "",
        "LIMITATIONS",
        "This audit uses only the two collected historical datasets.",
        "Absence from these datasets does not prove absence from PyPI.",
        "Observed timestamps are not verified first-publication times.",
        "Strictly earlier timestamps are required for eligibility.",
        "Reference availability is only partially established.",
        "Historical similarity values are diagnostic only.",
        "Original model features are not overwritten.",
        "No model training or final evaluation was performed.",
    ]

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print("\n".join(lines))
    print()
    print("Saved:", REFERENCE_OUTPUT)
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Historical reference audit completed.")


if __name__ == "__main__":
    main()
