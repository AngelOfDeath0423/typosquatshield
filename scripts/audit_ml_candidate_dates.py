
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/full/package_level_ml_candidates.csv"
REPORT = BASE / "reports/ml_candidate_date_audit.txt"
DETAIL = BASE / "data/full/ml_candidate_date_distribution.csv"

def main():
    df = pd.read_csv(
        INPUT,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )

    df["upload_dt"] = pd.to_datetime(
        df["first_upload_time"],
        format="mixed",
        utc=True,
        errors="coerce",
    )

    if df["upload_dt"].isna().any():
        raise ValueError("Invalid upload dates found.")

    df["upload_year"] = df["upload_dt"].dt.year

    distribution = (
        df.groupby(["candidate_group", "upload_year"])
        .size()
        .reset_index(name="record_count")
    )

    report = [
        "TYPOSQUATSHIELD - ML CANDIDATE DATE AUDIT",
        "=" * 60,
    ]

    for group, subset in df.groupby("candidate_group"):
        report.extend([
            "",
            f"GROUP: {group}",
            f"Records: {len(subset)}",
            f"Earliest upload: {subset['upload_dt'].min()}",
            f"Latest upload: {subset['upload_dt'].max()}",
            f"Median upload year: {subset['upload_year'].median()}",
            "",
            "YEAR DISTRIBUTION:",
            subset["upload_year"].value_counts()
            .sort_index()
            .to_string(),
        ])

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    DETAIL.parent.mkdir(parents=True, exist_ok=True)

    REPORT.write_text(
        "\n".join(report),
        encoding="utf-8",
    )

    distribution.to_csv(
        DETAIL,
        index=False,
        encoding="utf-8-sig",
    )

    print("\n".join(report))
    print()
    print("Saved:", REPORT)
    print("Saved:", DETAIL)
    print("[SUCCESS] Date audit completed.")


if __name__ == "__main__":
    main()
