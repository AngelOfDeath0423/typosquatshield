
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

SOURCE = (
    BASE / "data/legitimate/bigquery_legitimate_candidate_pool.csv"
)
OUTPUT = (
    BASE / "data/legitimate/legitimate_selected_10000.csv"
)
REPORT = (
    BASE / "reports/legitimate_sampling_report.txt"
)

TARGET = 10000
SEED = 42

def main():
    df = pd.read_csv(
        SOURCE,
        dtype={"normalized_name": str},
        encoding="utf-8-sig",
    )

    df["version_count"] = pd.to_numeric(
        df["version_count"],
        errors="coerce",
    )

    df["distribution_file_count"] = pd.to_numeric(
        df["distribution_file_count"],
        errors="coerce",
    )

    if df["normalized_name"].duplicated().any():
        raise ValueError("Duplicate normalized names found.")

    if df["version_count"].isna().any():
        raise ValueError("Invalid version counts.")

    # These are history-size strata, not popularity tiers.
    def history_group(count):
        if count <= 2:
            return "very_short_history"
        elif count <= 10:
            return "short_history"
        elif count <= 50:
            return "medium_history"
        return "long_history"

    df["history_group"] = df["version_count"].map(
        history_group
    )

    groups = sorted(df["history_group"].unique())
    base_quota = TARGET // len(groups)

    selected = []
    remaining = []

    for group in groups:
        subset = df[df["history_group"] == group]
        n = min(base_quota, len(subset))

        sample = subset.sample(
            n=n,
            random_state=SEED,
        )

        selected.append(sample)
        remaining.append(subset.drop(sample.index))

    result = pd.concat(selected, ignore_index=True)
    pool = pd.concat(remaining, ignore_index=True)

    # Fill unused quota if any stratum is undersized.
    missing = min(TARGET - len(result), len(pool))

    if missing > 0:
        extra = pool.sample(
            n=missing,
            random_state=SEED + 1,
        )
        result = pd.concat(
            [result, extra],
            ignore_index=True,
        )

    result = result.sample(
        frac=1,
        random_state=SEED,
    ).reset_index(drop=True)

    if len(result) != TARGET:
        raise ValueError(
            f"Expected {TARGET} records, got {len(result)}."
        )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    result.to_csv(
        OUTPUT,
        index=False,
        encoding="utf-8-sig",
    )

    counts = result["history_group"].value_counts()

    report = [
        "TYPOSQUATSHIELD - LEGITIMATE SAMPLING REPORT",
        "=" * 60,
        f"Candidate pool: {len(df)}",
        f"Selected candidates: {len(result)}",
        f"Random seed: {SEED}",
        "",
        "HISTORY GROUPS:",
        *(f"{key}: {value}" for key, value in counts.items()),
        "",
        "LIMITATIONS:",
        "These are presumed legitimate candidates.",
        "OpenSSF absence is not proof of benignness.",
        "Version count is not a popularity measure.",
        "Selection is stratified, not population-proportional.",
        "Historical feature comparability requires review.",
    ]

    REPORT.write_text(
        "\n".join(report),
        encoding="utf-8",
    )

    print("\n".join(report))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Sampling completed.")


if __name__ == "__main__":
    main()
