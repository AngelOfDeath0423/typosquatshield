
from pathlib import Path
import pandas as pd
from rapidfuzz.distance import DamerauLevenshtein

from typosquatting_similarity import normalize_name

BASE = Path(__file__).resolve().parent.parent

CANDIDATES = (
    BASE / "data/features/version_aware_combined_features.csv"
)

REFERENCES = (
    BASE / "data/reference/historical_reference_evidence.csv"
)

OUTPUT = (
    BASE / "reports/historical_similarity_reassessment.csv"
)

REPORT = (
    BASE / "reports/historical_similarity_reassessment_report.txt"
)

FEATURES = [
    "typo_min_edit_distance",
    "typo_max_similarity",
    "typo_potential_match",
    "typo_close_match_count",
    "typo_reference_length",
]

KEY = [
    "normalized_name",
    "version",
    "matched_pair_id",
]


def parse_timestamps(series, description):
    """
    Parse timestamps with mixed ISO 8601 formats.

    PyPI timestamps may contain different fractional-second
    lengths, so pandas must not infer a single format.
    """
    parsed = pd.to_datetime(
        series,
        utc=True,
        errors="coerce",
        format="mixed",
    )

    invalid = parsed.isna()

    if invalid.any():
        print()
        print(f"[ERROR] Invalid {description}: {invalid.sum()}")

        problem_rows = pd.DataFrame({
            "original_value": series.loc[invalid]
        })

        print(problem_rows.head(20).to_string(index=False))

        raise ValueError(
            f"Failed to parse {invalid.sum()} {description}."
        )

    return parsed


def calculate_similarity(name, references):
    """
    Calculate similarity using only reference packages
    with observed distribution evidence before the
    candidate's assessment timestamp.
    """
    matches = []

    for reference in references:
        distance = DamerauLevenshtein.distance(
            name,
            reference,
        )

        similarity = (
            DamerauLevenshtein.normalized_similarity(
                name,
                reference,
            )
        )

        threshold = 1 if len(reference) <= 5 else 2

        matches.append({
            "reference": reference,
            "distance": distance,
            "similarity": similarity,
            "is_close": (
                name != reference
                and distance <= threshold
            ),
        })

    if not matches:
        return {
            "historical_min_edit_distance": float("nan"),
            "historical_max_similarity": float("nan"),
            "historical_potential_match": float("nan"),
            "historical_close_match_count": float("nan"),
            "historical_reference_length": float("nan"),
        }

    closest = min(
        matches,
        key=lambda item: (
            item["distance"],
            -item["similarity"],
            item["reference"],
        ),
    )

    return {
        "historical_min_edit_distance": closest["distance"],
        "historical_max_similarity": max(
            item["similarity"]
            for item in matches
        ),
        "historical_potential_match": int(
            any(
                item["is_close"]
                for item in matches
            )
        ),
        "historical_close_match_count": sum(
            item["is_close"]
            for item in matches
        ),
        "historical_reference_length": len(
            closest["reference"]
        ),
    }


def main():
    print("=" * 65)
    print(
        "TYPOSQUATSHIELD - "
        "HISTORICAL SIMILARITY REASSESSMENT"
    )
    print("=" * 65)

    # --------------------------------------------------
    # 1. Validate input files
    # --------------------------------------------------

    if not CANDIDATES.exists():
        raise FileNotFoundError(CANDIDATES)

    if not REFERENCES.exists():
        raise FileNotFoundError(REFERENCES)

    df = pd.read_csv(
        CANDIDATES,
        dtype={"version": str},
    )

    refs = pd.read_csv(REFERENCES)

    if len(df) != 4410:
        raise ValueError(
            f"Expected 4410 candidate records, found {len(df)}."
        )

    if len(refs) != 100:
        raise ValueError(
            f"Expected 100 references, found {len(refs)}."
        )

    if df["normalized_name"].duplicated().any():
        raise ValueError(
            "Duplicate candidate package names detected."
        )

    if not set(FEATURES).issubset(df.columns):
        missing = sorted(
            set(FEATURES) - set(df.columns)
        )

        raise ValueError(
            f"Missing original similarity features: {missing}"
        )

    if df.duplicated(KEY).any():
        raise ValueError(
            "Duplicate candidate package-version-pair keys."
        )

    # --------------------------------------------------
    # 2. Normalize reference package names
    # --------------------------------------------------

    refs["reference_package"] = (
        refs["reference_package"]
        .astype(str)
        .map(normalize_name)
    )

    if refs["reference_package"].duplicated().any():
        raise ValueError(
            "Duplicate normalized reference names."
        )

    # --------------------------------------------------
    # 3. Parse historical timestamps
    # --------------------------------------------------

    refs["first_observed"] = parse_timestamps(
        refs["earliest_observed_upload_time"],
        "reference timestamps",
    )

    df["assessment_time"] = parse_timestamps(
        df["first_upload_time"],
        "candidate assessment timestamps",
    )

    print()
    print("INPUT VALIDATION")
    print(f"Candidate records: {len(df)}")
    print(f"Unique packages: {df['normalized_name'].nunique()}")
    print(f"Reference packages: {len(refs)}")
    print(
        "Valid reference timestamps:",
        refs["first_observed"].notna().sum(),
    )
    print(
        "Valid assessment timestamps:",
        df["assessment_time"].notna().sum(),
    )

    # --------------------------------------------------
    # 4. Prepare reference availability records
    # --------------------------------------------------

    reference_records = list(
        zip(
            refs["reference_package"],
            refs["first_observed"],
        )
    )

    # --------------------------------------------------
    # 5. Recalculate historically supported similarity
    # --------------------------------------------------

    records = []

    for index, row in enumerate(
        df.itertuples(index=False),
        start=1,
    ):
        name = normalize_name(row.normalized_name)
        cutoff = row.assessment_time

        eligible = [
            reference
            for reference, first_time in reference_records
            if first_time < cutoff
        ]

        unresolved_count = (
            len(reference_records) - len(eligible)
        )

        features = calculate_similarity(
            name,
            eligible,
        )

        records.append({
            "normalized_name": name,
            "version": row.version,
            "matched_pair_id": row.matched_pair_id,
            "candidate_group": row.candidate_group,
            "assessment_time": cutoff,
            "eligible_reference_count": len(eligible),
            "unresolved_reference_count": unresolved_count,
            **features,
        })

        if index % 1000 == 0:
            print(
                f"Processed {index}/{len(df)} candidates..."
            )

    result = pd.DataFrame(records)

    # --------------------------------------------------
    # 6. Preserve original similarity features
    # --------------------------------------------------

    original = df[
        KEY + FEATURES
    ].copy()

    result = result.merge(
        original,
        on=KEY,
        how="left",
        validate="one_to_one",
    )

    if len(result) != 4410:
        raise ValueError(
            "Historical reassessment output count mismatch."
        )

    # --------------------------------------------------
    # 7. Compare historical and original typo indicators
    # --------------------------------------------------

    valid = result["eligible_reference_count"] > 0

    result["original_typo_match"] = (
        result["typo_potential_match"]
    )

    result["historical_typo_match"] = (
        result["historical_potential_match"]
    )

    # Unknown when no historical reference is supported.
    result["match_changed"] = pd.Series(
        pd.NA,
        index=result.index,
        dtype="boolean",
    )

    result.loc[valid, "match_changed"] = (
        result.loc[valid, "original_typo_match"]
        != result.loc[valid, "historical_typo_match"]
    ).to_numpy()

    changed = int(
        result["match_changed"]
        .fillna(False)
        .sum()
    )

    # --------------------------------------------------
    # 8. Summarize historical reference coverage
    # --------------------------------------------------

    zero_eligible = int(
        (result["eligible_reference_count"] == 0).sum()
    )

    at_least_one = int(
        (result["eligible_reference_count"] > 0).sum()
    )

    all_references = int(
        (result["eligible_reference_count"] == 100).sum()
    )

    coverage = (
        result["eligible_reference_count"]
        .describe()
        .to_string()
    )

    group_summary = (
        result.groupby("candidate_group")
        .agg(
            records=(
                "normalized_name",
                "count",
            ),
            mean_eligible_references=(
                "eligible_reference_count",
                "mean",
            ),
            historical_typo_matches=(
                "historical_typo_match",
                "sum",
            ),
        )
        .round(4)
    )

    original_match_counts = (
        result.groupby("candidate_group")[
            "original_typo_match"
        ]
        .sum()
    )

    # --------------------------------------------------
    # 9. Save reports
    # --------------------------------------------------

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    result.to_csv(
        OUTPUT,
        index=False,
    )

    lines = [
        "TYPOSQUATSHIELD - HISTORICAL SIMILARITY REASSESSMENT",
        "=" * 65,
        f"Candidate records: {len(result)}",
        f"Reference packages: {len(refs)}",
        f"Valid reference timestamps: "
        f"{refs['first_observed'].notna().sum()}",
        "",
        "REFERENCE COVERAGE",
        f"Candidates with zero supported references: "
        f"{zero_eligible}",
        f"Candidates with at least one supported reference: "
        f"{at_least_one}",
        f"Candidates with all 100 supported references: "
        f"{all_references}",
        "",
        "ELIGIBLE REFERENCE DISTRIBUTION",
        coverage,
        "",
        "ORIGINAL POTENTIAL TYPO MATCHES BY GROUP",
        original_match_counts.to_string(),
        "",
        "HISTORICALLY SUPPORTED MATCHES BY GROUP",
        group_summary.to_string(),
        "",
        "COMPARISON",
        f"Changed potential-typo indicators: {changed}",
        "",
        "LIMITATIONS",
        "Evidence comes from currently retained PyPI files.",
        "Earliest retained upload time may be later than "
        "original publication.",
        "References without earlier evidence remain unresolved.",
        "Historical popularity and trust are unverified.",
        "Original similarity features are preserved.",
        "Candidate-group labels remain provisional.",
        "This is not verified malware-detection performance.",
        "No model training was performed.",
    ]

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print()
    print("\n".join(lines))

    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)

    print(
        "[SUCCESS] Historical similarity "
        "reassessment completed."
    )


if __name__ == "__main__":
    main()
