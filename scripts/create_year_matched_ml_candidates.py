
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/full/package_level_ml_candidates.csv"
OUTPUT = BASE / "data/full/year_matched_ml_candidates.csv"
REPORT = BASE / "reports/year_matched_ml_candidates_report.txt"

SEED = 42
GROUP_A = "openssf_exact_version_candidate"
GROUP_B = "presumed_legitimate"


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - YEAR-MATCHED ML CANDIDATES")
    print("=" * 65)

    df = pd.read_csv(
        INPUT,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )

    required = [
        "normalized_name",
        "version",
        "first_upload_time",
        "candidate_group",
    ]

    missing = set(required) - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    if df["normalized_name"].duplicated().any():
        raise ValueError("Input contains repeated package names.")

    df["upload_dt"] = pd.to_datetime(
        df["first_upload_time"],
        format="mixed",
        utc=True,
        errors="coerce",
    )

    if df["upload_dt"].isna().any():
        raise ValueError("Invalid upload timestamps.")

    df["upload_year"] = df["upload_dt"].dt.year

    if set(df["candidate_group"]) != {GROUP_A, GROUP_B}:
        raise ValueError("Unexpected candidate groups.")

    matched_frames = []
    summary = []

    for year in sorted(df["upload_year"].unique()):
        positive = df[
            (df["upload_year"] == year)
            & (df["candidate_group"] == GROUP_A)
        ]

        negative = df[
            (df["upload_year"] == year)
            & (df["candidate_group"] == GROUP_B)
        ]

        n = min(len(positive), len(negative))

        if n == 0:
            continue

        positive_sample = positive.sample(
            n=n,
            random_state=SEED + int(year),
        )

        negative_sample = negative.sample(
            n=n,
            random_state=SEED + int(year),
        )

        matched_frames.extend([
            positive_sample,
            negative_sample,
        ])

        summary.append({
            "year": int(year),
            "available_openssf": len(positive),
            "available_legitimate": len(negative),
            "selected_per_group": n,
        })

    if not matched_frames:
        raise ValueError("No overlapping years available.")

    result = pd.concat(
        matched_frames,
        ignore_index=True,
    )

    result = result.drop(columns=["upload_dt"])

    # Validate equal counts within every year.
    counts = pd.crosstab(
        result["upload_year"],
        result["candidate_group"],
    )

    if not counts[GROUP_A].equals(counts[GROUP_B]):
        raise ValueError("Year matching validation failed.")

    if result["normalized_name"].duplicated().any():
        raise ValueError("Repeated package names after matching.")

    # Retain unassigned labels: this is a candidate dataset.
    if "ml_label" in result.columns:
        if not result["ml_label"].eq("unassigned").all():
            raise ValueError("Unexpected ML labels found.")

    result = result.sort_values(
        ["upload_year", "candidate_group", "normalized_name"],
        kind="stable",
    ).reset_index(drop=True)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    result.to_csv(
        OUTPUT,
        index=False,
        encoding="utf-8-sig",
    )

    report_lines = [
        "TYPOSQUATSHIELD - YEAR-MATCHED CANDIDATE REPORT",
        "=" * 65,
        f"Original records: {len(df)}",
        f"Matched records: {len(result)}",
        f"OpenSSF candidates: {(result['candidate_group'] == GROUP_A).sum()}",
        f"Presumed legitimate: {(result['candidate_group'] == GROUP_B).sum()}",
        f"Unique packages: {result['normalized_name'].nunique()}",
        f"Random seed: {SEED}",
        "",
        "YEAR MATCHING:",
    ]

    for item in summary:
        report_lines.append(
            f"{item['year']}: "
            f"OpenSSF available={item['available_openssf']}, "
            f"legitimate available={item['available_legitimate']}, "
            f"selected per group={item['selected_per_group']}"
        )

    report_lines.extend([
        "",
        "LIMITATIONS:",
        "Year matching does not eliminate all temporal bias.",
        "Candidate groups are not verified ground-truth labels.",
        "Earliest-version selection is provisional.",
        "No ML model has been trained.",
        "Features must be restricted to assessment-time information.",
    ])

    REPORT.write_text(
        "\n".join(report_lines),
        encoding="utf-8",
    )

    print("\n".join(report_lines))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Year matching completed.")


if __name__ == "__main__":
    main()
