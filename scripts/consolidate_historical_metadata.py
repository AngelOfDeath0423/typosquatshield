
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
EXPORT_DIR = BASE / "data" / "full" / "historical_exports"
OUTPUT_DIR = BASE / "data" / "full"
REPORT_DIR = BASE / "reports"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

REQUIRED_COLUMNS = [
    "package_name",
    "normalized_name",
    "version",
    "first_upload_time",
    "distribution_file_count",
    "summary",
    "requires_python",
]


def main():
    print("=" * 60)
    print("TYPOSQUATSHIELD - HISTORICAL DATA CONSOLIDATION")
    print("=" * 60)

    files = sorted(EXPORT_DIR.glob("batch_*_historical.csv"))

    if len(files) != 24:
        raise ValueError(
            f"Expected 24 exports, found {len(files)}."
        )

    frames = []

    for path in files:
        df = pd.read_csv(
            path,
            dtype=str,
            keep_default_na=False,
            encoding="utf-8-sig",
        )

        missing = set(REQUIRED_COLUMNS) - set(df.columns)

        if missing:
            raise ValueError(
                f"{path.name} missing columns: {missing}"
            )

        df = df[REQUIRED_COLUMNS].copy()
        df["source_batch"] = path.stem.replace(
            "_historical", ""
        )

        frames.append(df)
        print(f"[LOADED] {path.name}: {len(df)} records")

    data = pd.concat(frames, ignore_index=True)

    # Validate identifiers.
    if data["normalized_name"].eq("").any():
        raise ValueError("Empty normalized package names found.")

    if data["version"].eq("").any():
        raise ValueError("Empty versions found.")

    # Ensure one observation per normalized package-version.
    duplicate_count = data.duplicated(
        ["normalized_name", "version"]
    ).sum()

    if duplicate_count:
        raise ValueError(
            f"Duplicate package-version pairs: {duplicate_count}"
        )

    # Validate timestamps.
    timestamps = pd.to_datetime(
        data["first_upload_time"],
        utc=True,
        format="mixed",
        errors="coerce",
    )

    invalid_timestamps = timestamps.isna().sum()

    if invalid_timestamps:
        raise ValueError(
            f"Invalid timestamps: {invalid_timestamps}"
        )

    # Validate distribution counts.
    counts = pd.to_numeric(
        data["distribution_file_count"],
        errors="coerce",
    )

    invalid_counts = (
        counts.isna() | (counts <= 0)
    ).sum()

    if invalid_counts:
        raise ValueError(
            f"Invalid distribution counts: {invalid_counts}"
        )

    data["first_upload_time"] = timestamps.dt.strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    data["distribution_file_count"] = counts.astype(int)

    data = data.sort_values(
        ["normalized_name", "first_upload_time", "version"],
        kind="stable",
    ).reset_index(drop=True)

    output_path = (
        OUTPUT_DIR / "historical_metadata_consolidated.csv"
    )

    data.to_csv(
        output_path,
        index=False,
        encoding="utf-8-sig",
    )

    unique_packages = data["normalized_name"].nunique()

    missing_summary = data["summary"].eq("").sum()
    missing_python = data["requires_python"].eq("").sum()

    report = [
        "TYPOSQUATSHIELD - HISTORICAL DATA QUALITY REPORT",
        "=" * 60,
        f"Export files: {len(files)}",
        f"Historical records: {len(data)}",
        f"Unique packages: {unique_packages}",
        f"Duplicate package-version pairs: {duplicate_count}",
        f"Invalid timestamps: {invalid_timestamps}",
        f"Invalid distribution counts: {invalid_counts}",
        f"Missing summaries: {missing_summary}",
        f"Missing requires_python: {missing_python}",
        "",
        "DATASET LIMITATIONS",
        "Historical metadata is not malware ground truth.",
        "Original package names may differ in capitalization.",
        "A package can have multiple historical versions.",
        "Missing metadata must not automatically imply maliciousness.",
    ]

    report_path = (
        REPORT_DIR / "historical_metadata_quality_report.txt"
    )

    report_path.write_text(
        "\n".join(report),
        encoding="utf-8",
    )

    print()
    print("\n".join(report))
    print()
    print("Consolidated CSV:", output_path)
    print("Quality report:", report_path)
    print()
    print("[SUCCESS] Consolidation completed.")


if __name__ == "__main__":
    main()
