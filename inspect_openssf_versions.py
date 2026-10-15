
import pandas as pd
import json
import subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parent
REPO = BASE / "malicious-packages"

df = pd.read_csv(
    BASE / "openssf_pypi_labels_raw.csv",
    dtype=str,
    keep_default_na=False
)

missing = df[df["package_version"].str.strip() == ""]

print("=" * 55)
print("OPENSSF MISSING VERSION INVESTIGATION")
print("=" * 55)

print(f"Total records: {len(df):,}")
print(f"Records with blank versions: {len(missing):,}")

with_ranges = 0
without_ranges = 0
examples = []

# Each report may appear more than once.
report_paths = missing["report_path"].drop_duplicates()

for path in report_paths:
    result = subprocess.run(
        ["git", "-C", str(REPO), "show", f"HEAD:{path}"],
        capture_output=True,
        check=True
    )

    report = json.loads(result.stdout.decode("utf-8"))

    has_ranges = any(
        bool(affected.get("ranges"))
        for affected in (report.get("affected") or [])
        if isinstance(affected, dict)
    )

    if has_ranges:
        with_ranges += 1
    else:
        without_ranges += 1
        if len(examples) < 5:
            examples.append(path)

print("\n--- Reports with blank version rows ---")
print(f"Reports containing ranges: {with_ranges:,}")
print(f"Reports without ranges: {without_ranges:,}")

print("\n--- Example reports without ranges ---")
for path in examples:
    print(path)

print("\nInvestigation completed.")
