
import json
import subprocess
from _paths import OPENSSF_REPO as REPO

def git_command(*args):
    result = subprocess.run(
        ["git", "-C", str(REPO), *args],
        capture_output=True,
        check=True
    )
    return result.stdout

paths = git_command(
    "ls-tree", "-r", "--name-only",
    "HEAD", "--", "osv/malicious/pypi"
).decode("utf-8").splitlines()

total_reports = 0
reports_with_annotations = 0
examples = []

for path in paths:
    if not path.endswith(".json"):
        continue

    report = json.loads(
        git_command("show", f"HEAD:{path}")
    )

    total_reports += 1
    found = False

    for affected in (report.get("affected") or []):
        if not isinstance(affected, dict):
            continue

        specific = affected.get("database_specific") or {}

        if not isinstance(specific, dict):
            continue

        keys = [
            str(key).lower()
            for key in specific.keys()
        ]

        if any(
            "false" in key or "positive" in key
            for key in keys
        ):
            found = True

    if found:
        reports_with_annotations += 1

        if len(examples) < 10:
            examples.append({
                "report_id": report.get("id"),
                "path": path
            })

print("=" * 55)
print("OPENSSF DISPUTED VERSION CHECK")
print("=" * 55)

print("Total reports:", total_reports)
print(
    "Reports with possible false-positive annotations:",
    reports_with_annotations
)

print("\nExamples:")
for item in examples:
    print(item["report_id"], item["path"])

print("\nCheck completed.")
