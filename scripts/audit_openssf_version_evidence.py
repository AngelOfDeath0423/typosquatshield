
import csv
import json
import subprocess
from collections import defaultdict
from pathlib import Path

import pandas as pd
from packaging.utils import canonicalize_name
from packaging.version import Version, InvalidVersion


BASE = Path(__file__).resolve().parent.parent

REPO = BASE / "malicious-packages"
INPUT = (
    BASE / "data" / "audit" /
    "openssf_version_evaluation_100.csv"
)
RAW = (
    BASE / "data" / "labels" /
    "openssf_pypi_labels_raw.csv"
)
OUTPUT = (
    BASE / "data" / "audit" /
    "openssf_original_report_audit_100.csv"
)
SUMMARY = (
    BASE / "reports" /
    "openssf_original_report_audit_summary.txt"
)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
SUMMARY.parent.mkdir(parents=True, exist_ok=True)


def git_command(*args):
    return subprocess.run(
        ["git", "-C", str(REPO), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=True,
    ).stdout


def parse_version(value):
    try:
        return Version(str(value).strip())
    except (InvalidVersion, TypeError, ValueError):
        return None


def versions_equal(a, b):
    av = parse_version(a)
    bv = parse_version(b)
    if av is not None and bv is not None:
        return av == bv
    return str(a).strip() == str(b).strip()


def evaluate_range(target, range_obj):
    if not isinstance(range_obj, dict):
        return "unresolved"

    if range_obj.get("type") != "ECOSYSTEM":
        return "unresolved"

    events = range_obj.get("events", [])
    target_v = parse_version(target)

    if target_v is None or not events:
        return "unresolved"

    intervals = []
    start = None

    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return "unresolved"

        key, value = next(iter(event.items()))

        if key == "introduced":
            if start is not None:
                return "unresolved"

            if str(value) == "0":
                start = "0"
            else:
                start = parse_version(value)
                if start is None:
                    return "unresolved"

        elif key in ("fixed", "last_affected", "limit"):
            if start is None:
                return "unresolved"

            end = parse_version(value)
            if end is None:
                return "unresolved"

            intervals.append((start, key, end))
            start = None

        else:
            return "unresolved"

    if start is not None:
        intervals.append((start, "open", None))

    if not intervals:
        return "unresolved"

    for beginning, end_type, ending in intervals:
        after_start = (
            beginning == "0" or target_v >= beginning
        )

        if end_type in ("fixed", "limit"):
            before_end = target_v < ending
        elif end_type == "last_affected":
            before_end = target_v <= ending
        else:
            before_end = True

        if after_start and before_end:
            return "affected"

    return "not_affected"


print("=" * 65)
print("TYPOSQUATSHIELD - ORIGINAL OPENSSF REPORT AUDIT")
print("=" * 65)

historical = pd.read_csv(
    INPUT,
    dtype=str,
    keep_default_na=False,
    encoding="utf-8-sig",
)

raw = pd.read_csv(
    RAW,
    dtype=str,
    keep_default_na=False,
    encoding="utf-8-sig",
)

historical["normalized_name"] = historical[
    "package_name"
].map(canonicalize_name)

raw["normalized_name"] = raw[
    "package_name"
].map(canonicalize_name)

# Identify original report paths for the 100 sampled names.
target_names = set(historical["normalized_name"])

report_paths = raw[
    raw["normalized_name"].isin(target_names)
][["report_id", "report_path"]].drop_duplicates()

print("Historical records:", len(historical))
print("Unique packages:", len(target_names))
print("Original reports to inspect:", len(report_paths))

# Read original reports from the pinned Git snapshot.
# No malicious package files are downloaded or executed.
source_commit = git_command("rev-parse", "HEAD").strip()

reports = {}
read_errors = []

for _, row in report_paths.iterrows():
    report_id = row["report_id"]
    path = row["report_path"]

    try:
        content = git_command(
            "show",
            f"{source_commit}:{path}"
        )
        reports[(report_id, path)] = json.loads(content)
    except Exception as error:
        read_errors.append(
            f"{report_id} | {path} | {error}"
        )

print("Reports loaded:", len(reports))
print("Report read errors:", len(read_errors))

# Index original PyPI affected entries by normalized name.
evidence = defaultdict(list)

for (report_id, path), report in reports.items():
    if report.get("id") != report_id:
        read_errors.append(
            f"ID mismatch: {report_id} at {path}"
        )
        continue

    for affected in report.get("affected", []):
        package = affected.get("package") or {}

        if package.get("ecosystem", "").lower() != "pypi":
            continue

        name = canonicalize_name(package.get("name", ""))

        if name not in target_names:
            continue

        evidence[name].append({
            "report_id": report_id,
            "report_path": path,
            "versions": affected.get("versions") or [],
            "ranges": affected.get("ranges") or [],
            "database_specific": affected.get(
                "database_specific"
            ) or {},
        })


results = []

for _, item in historical.iterrows():
    name = item["normalized_name"]
    version = item["version"]

    explicit_ids = set()
    range_ids = set()
    unresolved_ids = set()
    report_ids = set()

    for entry in evidence.get(name, []):
        report_id = entry["report_id"]
        report_ids.add(report_id)

        if any(
            versions_equal(version, reported)
            for reported in entry["versions"]
        ):
            explicit_ids.add(report_id)
            continue

        outcomes = [
            evaluate_range(version, r)
            for r in entry["ranges"]
        ]

        if "affected" in outcomes:
            range_ids.add(report_id)
        elif "unresolved" in outcomes:
            unresolved_ids.add(report_id)

    if explicit_ids:
        status = "explicit_version_match"
    elif range_ids:
        status = "range_affected_candidate"
    elif unresolved_ids:
        status = "range_unresolved"
    else:
        status = "no_confirmed_affected_version"

    record = {
        "package_name": item["package_name"],
        "normalized_name": name,
        "version": version,
        "previous_status": item["evidence_status"],
        "original_report_status": status,
        "status_agrees": (
            item["evidence_status"] == status
        ),
        "original_report_ids": ";".join(
            sorted(report_ids)
        ),
        "explicit_report_ids": ";".join(
            sorted(explicit_ids)
        ),
        "range_report_ids": ";".join(
            sorted(range_ids)
        ),
        "unresolved_report_ids": ";".join(
            sorted(unresolved_ids)
        ),
        "label_verified": False,
    }

    results.append(record)


result_df = pd.DataFrame(results)
result_df.to_csv(
    OUTPUT,
    index=False,
    encoding="utf-8-sig",
)

agreement = int(result_df["status_agrees"].sum())
disagreement = len(result_df) - agreement

counts = result_df[
    "original_report_status"
].value_counts()

summary_lines = [
    "TYPOSQUATSHIELD - ORIGINAL OPENSSF REPORT AUDIT",
    "=" * 60,
    f"Git snapshot: {source_commit}",
    f"Historical records: {len(result_df)}",
    f"Original reports loaded: {len(reports)}",
    f"Report read errors: {len(read_errors)}",
    "",
    f"Status agreements: {agreement}",
    f"Status disagreements: {disagreement}",
    "",
    "ORIGINAL REPORT EVIDENCE:",
]

for status in [
    "explicit_version_match",
    "range_affected_candidate",
    "range_unresolved",
    "no_confirmed_affected_version",
]:
    summary_lines.append(
        f"{status}: {int(counts.get(status, 0))}"
    )

if read_errors:
    summary_lines.extend([
        "",
        "READ ERRORS:",
        *read_errors[:20],
    ])

summary_lines.extend([
    "",
    "NOTES:",
    "Agreement checks consistency with the original JSON.",
    "Agreement does not independently verify maliciousness.",
    "A missing affected-version match is not a benign label.",
    "No package artifacts were downloaded or executed.",
    "No records are automatically marked label_verified=True.",
])

SUMMARY.write_text(
    "\n".join(summary_lines),
    encoding="utf-8",
)

print("\n".join(summary_lines))
print("\nSaved CSV:", OUTPUT)
print("Saved summary:", SUMMARY)
print("\nOriginal report audit completed.")
