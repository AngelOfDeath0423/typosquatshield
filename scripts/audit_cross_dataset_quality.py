
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

POSITIVE_PATH = BASE / "data/full/historical_metadata_consolidated.csv"
NEGATIVE_PATH = BASE / "data/legitimate/legitimate_historical_consolidated.csv"

REPORT_PATH = BASE / "reports/cross_dataset_quality_report.txt"
OVERLAP_PATH = BASE / "data/full/cross_dataset_overlaps.csv"

KEY = ["normalized_name", "version"]


def load_dataset(path):
    if not path.exists():
        raise FileNotFoundError(path)

    return pd.read_csv(
        path,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )


def summarize(df, label):
    dates = pd.to_datetime(
        df["first_upload_time"],
        format="mixed",
        utc=True,
        errors="coerce",
    )

    return [
        f"{label} records: {len(df)}",
        f"{label} unique packages: {df['normalized_name'].nunique()}",
        f"{label} duplicate pairs: {df.duplicated(KEY).sum()}",
        f"{label} invalid timestamps: {dates.isna().sum()}",
        f"{label} earliest upload: {dates.min()}",
        f"{label} latest upload: {dates.max()}",
        f"{label} missing summaries: {df['summary'].eq('').sum()}",
        f"{label} missing requires_python: {df['requires_python'].eq('').sum()}",
    ]


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - CROSS-DATASET QUALITY AUDIT")
    print("=" * 65)

    positive = load_dataset(POSITIVE_PATH)
    negative = load_dataset(NEGATIVE_PATH)

    positive_names = set(positive["normalized_name"])
    negative_names = set(negative["normalized_name"])

    overlapping_names = positive_names & negative_names

    positive_pairs = set(
        zip(positive["normalized_name"], positive["version"])
    )
    negative_pairs = set(
        zip(negative["normalized_name"], negative["version"])
    )

    overlapping_pairs = positive_pairs & negative_pairs

    overlap_rows = negative[
        negative["normalized_name"].isin(overlapping_names)
    ].copy()

    OVERLAP_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    overlap_rows.to_csv(
        OVERLAP_PATH,
        index=False,
        encoding="utf-8-sig",
    )

    report = [
        "TYPOSQUATSHIELD - CROSS-DATASET QUALITY REPORT",
        "=" * 65,
        *summarize(positive, "OpenSSF-associated"),
        "",
        *summarize(negative, "Presumed legitimate"),
        "",
        f"Overlapping package names: {len(overlapping_names)}",
        f"Overlapping package-version pairs: {len(overlapping_pairs)}",
        "",
        "LIMITATIONS:",
        "OpenSSF-associated does not mean confirmed malware.",
        "Presumed legitimate does not mean verified benign.",
        "Upload-time differences can introduce model bias.",
        "Further evidence and temporal checks are required.",
    ]

    REPORT_PATH.write_text(
        "\n".join(report),
        encoding="utf-8",
    )

    print("\n".join(report))
    print()
    print("Saved:", OVERLAP_PATH)
    print("Saved:", REPORT_PATH)

    if overlapping_names:
        print()
        print("[REVIEW REQUIRED] Cross-dataset overlap detected.")
    else:
        print()
        print("[SUCCESS] No cross-dataset package-name overlap.")


if __name__ == "__main__":
    main()
