
import subprocess
import json
import csv
from _paths import LABELS_DATA_DIR, OPENSSF_REPO as REPO

OUTPUT = LABELS_DATA_DIR / "openssf_pypi_labels_raw.csv"

def git_read(*args):
    return subprocess.run(
        ["git", "-C", str(REPO), *args],
        capture_output=True,
        check=True
    ).stdout

print("Finding OpenSSF PyPI reports...")

paths = git_read(
    "ls-tree", "-r", "--name-only",
    "HEAD", "--", "osv/malicious/pypi"
).decode("utf-8").splitlines()

paths = [p for p in paths if p.endswith(".json")]
print(f"Found {len(paths)} JSON reports.")

fields = [
    "package_name",
    "package_version",
    "affected_ranges",
    "ecosystem",
    "report_id",
    "published",
    "modified",
    "withdrawn",
    "summary",
    "details",
    "references",
    "origin_sources",
    "report_path",
    "label_source",
    "label_status",
]

count = 0
errors = 0

with OUTPUT.open("w", newline="", encoding="utf-8-sig") as file:
    writer = csv.DictWriter(file, fieldnames=fields)
    writer.writeheader()

    for index, path in enumerate(paths, start=1):
        try:
            raw = git_read("show", f"HEAD:{path}")
            report = json.loads(raw.decode("utf-8"))

            database_specific = report.get("database_specific") or {}

            origins = database_specific.get(
                "malicious-packages-origins"
            ) or []

            sources = sorted({
                item.get("source")
                for item in origins
                if isinstance(item, dict) and item.get("source")
            })

            references = [
                item.get("url", "")
                for item in (report.get("references") or [])
                if isinstance(item, dict) and item.get("url")
            ]

            for affected in (report.get("affected") or []):
                if not isinstance(affected, dict):
                    continue

                package = affected.get("package") or {}

                if package.get("ecosystem") != "PyPI":
                    continue

                versions = affected.get("versions") or [None]
                ranges = affected.get("ranges") or []

                for version in versions:
                    writer.writerow({
                        "package_name": package.get("name"),
                        "package_version": version,
                        "affected_ranges": json.dumps(ranges),
                        "ecosystem": "PyPI",
                        "report_id": report.get("id"),
                        "published": report.get("published"),
                        "modified": report.get("modified"),
                        "withdrawn": report.get("withdrawn"),
                        "summary": report.get("summary"),
                        "details": report.get("details"),
                        "references": json.dumps(references),
                        "origin_sources": json.dumps(sources),
                        "report_path": path,
                        "label_source": "OpenSSF",
                        "label_status": "needs_review",
                    })
                    count += 1

        except Exception as error:
            errors += 1
            print(f"Error reading {path}: {error}")

        if index % 1000 == 0:
            print(f"Processed {index}/{len(paths)} reports...")

print("\nExtraction completed.")
print(f"CSV records created: {count}")
print(f"Reports with errors: {errors}")
print(f"Saved to: {OUTPUT}")
