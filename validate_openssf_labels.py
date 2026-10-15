
import pandas as pd
from pathlib import Path

BASE = Path(__file__).resolve().parent
INPUT = BASE / "openssf_pypi_labels_raw.csv"

df = pd.read_csv(INPUT, dtype=str, keep_default_na=False)

print("=" * 55)
print("OPENSSF PYPI DATASET VALIDATION")
print("=" * 55)

print(f"\nTotal CSV records: {len(df):,}")

print(
    "Unique package names:",
    df["package_name"].nunique()
)

print(
    "Unique package-version pairs:",
    df[["package_name", "package_version"]]
    .drop_duplicates()
    .shape[0]
)

print(
    "Unique report IDs:",
    df["report_id"].nunique()
)

print("\n--- Missing values ---")
for col in [
    "package_name",
    "package_version",
    "report_id",
    "published",
    "summary",
]:
    missing = df[col].str.strip().eq("").sum()
    print(f"{col}: {missing:,}")

print("\n--- Duplicate records ---")
print(
    "Exact duplicate rows:",
    df.duplicated().sum()
)

print(
    "Duplicate package-version-report combinations:",
    df.duplicated(
        subset=[
            "package_name",
            "package_version",
            "report_id",
        ]
    ).sum()
)

print("\n--- Withdrawn reports ---")
withdrawn = df["withdrawn"].str.strip().ne("")
print("Withdrawn CSV records:", withdrawn.sum())
print(
    "Unique withdrawn report IDs:",
    df.loc[withdrawn, "report_id"].nunique()
)

print("\n--- Label status ---")
print(df["label_status"].value_counts())

print("\n--- Ecosystem ---")
print(df["ecosystem"].value_counts())

print("\nValidation completed.")
