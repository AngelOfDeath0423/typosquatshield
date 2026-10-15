
import subprocess
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
REPO = BASE / "malicious-packages"

def git_files(folder):
    result = subprocess.run(
        ["git", "-C", str(REPO),
         "ls-tree", "-r", "--name-only",
         "HEAD", "--", folder],
        capture_output=True,
        text=True,
        check=True
    )
    return [
        line for line in result.stdout.splitlines()
        if line.endswith(".json")
    ]

def read_report(path):
    result = subprocess.run(
        ["git", "-C", str(REPO),
         "show", f"HEAD:{path}"],
        capture_output=True,
        check=True
    )
    return json.loads(result.stdout)

withdrawn_paths = git_files("osv/withdrawn")

print("Withdrawn JSON reports:", len(withdrawn_paths))

pypi_withdrawn = []
for path in withdrawn_paths:
    report = read_report(path)

    affected = report.get("affected") or []
    if any(
        isinstance(a, dict)
        and isinstance(a.get("package"), dict)
        and a["package"].get("ecosystem") == "PyPI"
        for a in affected
    ):
        pypi_withdrawn.append({
            "report_id": report.get("id"),
            "path": path
        })

print("Withdrawn PyPI reports:", len(pypi_withdrawn))

print("\nExamples:")
for item in pypi_withdrawn[:10]:
    print(item["report_id"], item["path"])

print("\nCheck completed.")
