
import json
import subprocess
import pandas as pd
from pathlib import Path
from packaging.utils import canonicalize_name

BASE = Path(__file__).resolve().parent
REPO = BASE / "malicious-packages"

df = pd.read_csv(
    BASE / "openssf_pypi_labels_reviewed.csv",
    dtype=str,
    keep_default_na=False
)

def git_command(*args):
    result = subprocess.run(
        ["git", "-C", str(REPO), *args],
        capture_output=True,
        check=True
    )
    return result.stdout

paths = git_command(
    "ls-tree", "-r", "--name-only",
    "HEAD", "--", "osv/withdrawn"
).decode("utf-8").splitlines()

withdrawn_ids = set()
withdrawn_names = set()

for path in paths:
    if not path.endswith(".json"):
        continue

    report = json.loads(
        git_command("show", f"HEAD:{path}")
    )

    for affected in (report.get("affected") or []):
        if not isinstance(affected, dict):
            continue

        package = affected.get("package") or {}
        if package.get("ecosystem") != "PyPI":
            continue

        withdrawn_ids.add(str(report.get("id", "")))

        name = package.get("name")
        if name:
            withdrawn_names.add(canonicalize_name(name))

df["normalized_name"] = df["package_name"].map(
    canonicalize_name
)

id_match = df["report_id"].isin(withdrawn_ids)
name_match = df["normalized_name"].isin(withdrawn_names)

print("=" * 55)
print("OPENSSF WITHDRAWN REPORT COMPARISON")
print("=" * 55)

print("Withdrawn PyPI report IDs:", len(withdrawn_ids))
print("Withdrawn PyPI package names:", len(withdrawn_names))

print("\nMatches in active dataset:")
print("Rows matching withdrawn report IDs:", id_match.sum())
print("Rows matching withdrawn package names:", name_match.sum())
print(
    "Unique packages with name matches:",
    df.loc[name_match, "normalized_name"].nunique()
)

print("\nMatching packages:")
print(
    df.loc[
        id_match | name_match,
        ["package_name", "report_id", "label_status"]
    ].drop_duplicates().head(30).to_string(index=False)
)

print("\nComparison completed.")
