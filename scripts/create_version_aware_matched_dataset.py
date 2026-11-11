
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/full/version_aware_assessment_pool.csv"
OUTPUT = BASE / "data/full/version_aware_matched_candidates.csv"
REPORT = BASE / "reports/version_aware_matched_report.txt"

POS = "openssf_exact_version_candidate"
NEG = "presumed_legitimate"
SEED = 42

STRATA = ["assessment_year", "history_bucket"]


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - VERSION-AWARE MATCHING")
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
        "version",
        "first_upload_time",
        "candidate_group",
        "assessment_year",
        "history_bucket",
        "prior_version_records",
    ]

    missing = set(required) - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    if df[required].isna().any().any():
        raise ValueError("Missing required values.")

    if set(df["candidate_group"]) != {POS, NEG}:
        raise ValueError("Unexpected candidate groups.")

    df["first_upload_time"] = pd.to_datetime(
        df["first_upload_time"],
        format="mixed",
        utc=True,
        errors="raise",
    )

    if df.duplicated(
        ["normalized_name", "version", "first_upload_time"]
    ).any():
        raise ValueError("Duplicate package-version records.")

    if (
        df.groupby("normalized_name")["candidate_group"]
        .nunique().gt(1).any()
    ):
        raise ValueError("Package appears in both groups.")

    # Deterministic random order to avoid always preferring
    # alphabetically earlier packages.
    df = df.sample(frac=1, random_state=SEED).reset_index(
        drop=True
    )

    # Find the initial availability of each stratum.
    counts = (
        df.groupby(STRATA + ["candidate_group"])
        ["normalized_name"]
        .nunique()
        .unstack(fill_value=0)
    )

    for group in [POS, NEG]:
        if group not in counts.columns:
            counts[group] = 0

    counts["capacity"] = counts[[POS, NEG]].min(axis=1)

    # Process more constrained strata first.
    counts["total_available"] = counts[POS] + counts[NEG]

    ordered_strata = (
        counts[counts["capacity"] > 0]
        .sort_values(
            ["capacity", "total_available"],
            ascending=[True, True],
        )
        .index.tolist()
    )

    used_names = set()
    selected_rows = []
    pair_id = 0

    for year, bucket in ordered_strata:
        subset = df[
            (df["assessment_year"] == year)
            & (df["history_bucket"] == bucket)
            & (~df["normalized_name"].isin(used_names))
        ]

        positives = (
            subset[subset["candidate_group"] == POS]
            .drop_duplicates("normalized_name")
        )

        negatives = (
            subset[subset["candidate_group"] == NEG]
            .drop_duplicates("normalized_name")
        )

        n_pairs = min(len(positives), len(negatives))

        if n_pairs == 0:
            continue

        pos_rows = positives.head(n_pairs)
        neg_rows = negatives.head(n_pairs)

        for (_, p), (_, n) in zip(
            pos_rows.iterrows(),
            neg_rows.iterrows(),
        ):
            pair_id += 1

            p_record = p.to_dict()
            n_record = n.to_dict()

            p_record["matched_pair_id"] = pair_id
            n_record["matched_pair_id"] = pair_id

            selected_rows.extend([p_record, n_record])

            used_names.add(p["normalized_name"])
            used_names.add(n["normalized_name"])

    if not selected_rows:
        raise ValueError("No matched pairs found.")

    result = pd.DataFrame(selected_rows)

    # Validate package uniqueness.
    if result["normalized_name"].duplicated().any():
        raise ValueError("Package uniqueness violated.")

    # Validate pair composition and matching.
    for _, pair in result.groupby("matched_pair_id"):
        if len(pair) != 2:
            raise ValueError("Invalid pair size.")

        if set(pair["candidate_group"]) != {POS, NEG}:
            raise ValueError("Invalid pair composition.")

        if pair["assessment_year"].nunique() != 1:
            raise ValueError("Assessment year mismatch.")

        if pair["history_bucket"].nunique() != 1:
            raise ValueError("History bucket mismatch.")

    result["label_verified"] = False
    result["ml_label"] = "unassigned"
    result["assessment_selection_status"] = (
        "matched_provisional_candidate"
    )

    result = result.sort_values(
        ["matched_pair_id", "candidate_group"]
    ).reset_index(drop=True)

    summary = (
        result.groupby("candidate_group")
        .agg(
            records=("normalized_name", "size"),
            unique_packages=("normalized_name", "nunique"),
            with_prior_history=(
                "prior_version_records",
                lambda x: int((x > 0).sum()),
            ),
            mean_prior_records=("prior_version_records", "mean"),
            median_prior_records=("prior_version_records", "median"),
        )
    )

    strata_summary = (
        result.groupby(
            STRATA + ["candidate_group"]
        )["normalized_name"]
        .nunique()
        .unstack(fill_value=0)
    )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    result.to_csv(OUTPUT, index=False)

    lines = [
        "TYPOSQUATSHIELD - VERSION-AWARE MATCHED DATASET",
        "=" * 65,
        f"Selected records: {len(result)}",
        f"Matched pairs: {pair_id}",
        f"Unique packages: {result['normalized_name'].nunique()}",
        "",
        "GROUP SUMMARY",
        summary.to_string(),
        "",
        "MATCHED YEAR/HISTORY STRATA",
        strata_summary.to_string(),
        "",
        "VALIDATION",
        "One selected version per package: PASS",
        "One package per candidate group: PASS",
        "Matched assessment year: PASS",
        "Matched prior-history bucket: PASS",
        "",
        "LIMITATIONS",
        "Greedy matching is not guaranteed maximum-cardinality.",
        "Matching does not establish label correctness.",
        "OpenSSF evidence is provisional.",
        "Presumed legitimate packages are not verified benign.",
        "Release-count matching does not eliminate all bias.",
        "Reference and metadata timing require further validation.",
        "This dataset is not yet approved for final ML evaluation.",
    ]

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print("\n".join(lines))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Version-aware matching completed.")


if __name__ == "__main__":
    main()
