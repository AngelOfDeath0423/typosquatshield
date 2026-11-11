
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/full/version_aware_assessment_pool.csv"

OUTPUT = BASE / "reports/version_aware_matching_capacity.csv"
REPORT = BASE / "reports/version_aware_matching_summary.txt"

POSITIVE = "openssf_exact_version_candidate"
NEGATIVE = "presumed_legitimate"

BUCKETS = ["0", "1-2", "3-10", "11+"]


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - VERSION-AWARE MATCHING AUDIT")
    print("=" * 65)

    df = pd.read_csv(
        INPUT,
        dtype={
            "normalized_name": str,
            "version": str,
            "history_bucket": str,
        },
    )

    required = [
        "normalized_name",
        "candidate_group",
        "assessment_year",
        "history_bucket",
        "prior_version_records",
    ]

    missing = set(required) - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    if df["normalized_name"].isna().any():
        raise ValueError("Missing package names.")

    if df["history_bucket"].isna().any():
        raise ValueError("Missing history buckets.")

    if set(df["candidate_group"]) != {POSITIVE, NEGATIVE}:
        raise ValueError("Unexpected candidate groups.")

    # Each package counts only once within a year/bucket.
    unique_strata = df[
        [
            "normalized_name",
            "candidate_group",
            "assessment_year",
            "history_bucket",
        ]
    ].drop_duplicates()

    counts = (
        unique_strata.groupby(
            [
                "assessment_year",
                "history_bucket",
                "candidate_group",
            ]
        )
        .size()
        .unstack("candidate_group", fill_value=0)
        .reindex(
            columns=[POSITIVE, NEGATIVE],
            fill_value=0,
        )
        .reset_index()
    )

    counts["potential_pairs"] = counts[
        [POSITIVE, NEGATIVE]
    ].min(axis=1)

    counts = counts.sort_values(
        ["assessment_year", "history_bucket"]
    )

    # This is a per-stratum upper bound, not a feasible
    # package-disjoint matching result. The same package
    # can occur in several year/bucket strata.
    naive_upper_bound = int(counts["potential_pairs"].sum())

    positive_names = set(
        df.loc[
            df["candidate_group"] == POSITIVE,
            "normalized_name",
        ]
    )

    negative_names = set(
        df.loc[
            df["candidate_group"] == NEGATIVE,
            "normalized_name",
        ]
    )

    if positive_names & negative_names:
        raise ValueError("Package groups overlap.")

    upper_bound = min(
        naive_upper_bound,
        len(positive_names),
        len(negative_names),
    )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    counts.to_csv(OUTPUT, index=False)

    lines = [
        "TYPOSQUATSHIELD - MATCHING CAPACITY AUDIT",
        "=" * 65,
        f"Unique OpenSSF candidate packages: {len(positive_names)}",
        f"Unique presumed legitimate packages: {len(negative_names)}",
        f"Per-stratum pair sum: {naive_upper_bound}",
        f"Capped theoretical upper bound: {upper_bound}",
        "",
        "MATCHING CAPACITY BY YEAR AND HISTORY BUCKET",
        counts.to_string(index=False),
        "",
        "IMPORTANT LIMITATIONS",
        "This audit does not select final package versions.",
        "A package may appear in multiple year/history strata.",
        "Summed stratum counts may overestimate feasible matches.",
        "Package-disjoint matching must be enforced later.",
        "OpenSSF evidence remains provisional.",
        "Presumed legitimate does not mean verified benign.",
        "Historical timestamp validity still requires review.",
    ]

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print("\n".join(lines))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Matching feasibility audit completed.")


if __name__ == "__main__":
    main()
