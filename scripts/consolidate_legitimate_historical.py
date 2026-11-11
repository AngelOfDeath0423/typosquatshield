
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

INPUT_DIR = BASE / "data/legitimate/historical_batches"
OUTPUT_DIR = BASE / "data/legitimate"
REPORT_DIR = BASE / "reports"

OUTPUT = OUTPUT_DIR / "legitimate_historical_consolidated.csv"
REPORT = REPORT_DIR / "legitimate_historical_quality_report.txt"

EXPECTED_BATCHES = 20
EXPECTED_NAMES = 10000

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
    print("=" * 65)
    print("TYPOSQUATSHIELD - LEGITIMATE HISTORICAL CONSOLIDATION")
    print("=" * 65)

    files = sorted(INPUT_DIR.glob("batch_*_historical.csv"))

    if len(files) != EXPECTED_BATCHES:
        raise ValueError(
            f"Expected {EXPECTED_BATCHES} files, found {len(files)}"
        )

    frames = []

    for file in files:
        df = pd.read_csv(
            file,
            dtype=str,
            keep_default_na=False,
            encoding="utf-8-sig",
        )

        missing = set(REQUIRED_COLUMNS) - set(df.columns)

        if missing:
            raise ValueError(
                f"{file.name} missing columns: {sorted(missing)}"
            )

        print(f"[LOADED] {file.name}: {len(df):,} records")
        frames.append(df)

    data = pd.concat(frames, ignore_index=True)

    duplicate_count = data.duplicated(
        ["normalized_name", "version"]
    ).sum()

    timestamps = pd.to_datetime(
        data["first_upload_time"],
        format="mixed",
        utc=True,
        errors="coerce",
    )

    invalid_timestamps = timestamps.isna().sum()

    counts = pd.to_numeric(
        data["distribution_file_count"],
        errors="coerce",
    )

    invalid_counts = (
        counts.isna() | (counts <= 0)
    ).sum()

    missing_names = data["normalized_name"].eq("").sum()
    missing_versions = data["version"].eq("").sum()

    unique_names = data["normalized_name"].nunique()

    print()
    print("QUALITY VALIDATION")
    print("=" * 65)
    print("Export files:", len(files))
    print("Historical records:", len(data))
    print("Unique packages:", unique_names)
    print("Duplicate package-version pairs:", duplicate_count)
    print("Invalid timestamps:", invalid_timestamps)
    print("Invalid distribution counts:", invalid_counts)
    print("Missing package names:", missing_names)
    print("Missing versions:", missing_versions)

    problems = []

    if duplicate_count:
        problems.append("Duplicate package-version pairs")

    if invalid_timestamps:
        problems.append("Invalid timestamps")

    if invalid_counts:
        problems.append("Invalid distribution counts")

    if missing_names or missing_versions:
        problems.append("Missing essential identifiers")

    if unique_names != EXPECTED_NAMES:
        problems.append(
            f"Expected {EXPECTED_NAMES} unique names, "
            f"found {unique_names}"
        )

    if problems:
        raise ValueError(
            "Validation failed: " + "; ".join(problems)
        )

    # These records are candidate negatives, not verified benign.
    data["label_status"] = "presumed_legitimate"
    data["label_verified"] = False
    data["label_source"] = "historical_bigquery_stratified_sample"

    # Stable ordering for reproducibility.
    data = data.sort_values(
        ["normalized_name", "version"],
        kind="stable",
    ).reset_index(drop=True)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # Write to a temporary file before replacing the final output.
    temp_output = OUTPUT.with_suffix(".tmp")

    data.to_csv(
        temp_output,
        index=False,
        encoding="utf-8-sig",
    )

    temp_output.replace(OUTPUT)

    report_lines = [
        "TYPOSQUATSHIELD - LEGITIMATE HISTORICAL QUALITY REPORT",
        "=" * 65,
        f"Export files: {len(files)}",
        f"Historical records: {len(data)}",
        f"Unique packages: {unique_names}",
        f"Duplicate package-version pairs: {duplicate_count}",
        f"Invalid timestamps: {invalid_timestamps}",
        f"Invalid distribution counts: {invalid_counts}",
        f"Missing package names: {missing_names}",
        f"Missing versions: {missing_versions}",
        f"Missing summaries: {data['summary'].eq('').sum()}",
        f"Missing requires_python: {data['requires_python'].eq('').sum()}",
        "",
        "LABEL LIMITATIONS:",
        "All records are presumed legitimate candidates.",
        "OpenSSF absence does not verify benignness.",
        "Historical metadata is not malware ground truth.",
        "No final ML training labels assigned.",
    ]

    REPORT.write_text(
        "\n".join(report_lines),
        encoding="utf-8",
    )

    print()
    print("Missing summaries:", data["summary"].eq("").sum())
    print(
        "Missing requires_python:",
        data["requires_python"].eq("").sum(),
    )
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print()
    print("[SUCCESS] Legitimate consolidation completed.")


if __name__ == "__main__":
    main()
