
import json
from collections import defaultdict
from pathlib import Path

import pandas as pd
from packaging.utils import canonicalize_name
from packaging.version import Version, InvalidVersion


BASE = Path(__file__).resolve().parent.parent

HISTORICAL = (
    BASE / "data" / "audit" / "bigquery_versions_100.csv"
)
OPENSSF = (
    BASE / "data" / "labels" / "openssf_pypi_labels_raw.csv"
)
OUTPUT = (
    BASE / "data" / "audit" /
    "openssf_version_evaluation_100.csv"
)
REPORT = (
    BASE / "reports" /
    "openssf_range_evaluation_summary.txt"
)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
REPORT.parent.mkdir(parents=True, exist_ok=True)


def parse_version(value):
    try:
        return Version(str(value).strip())
    except (InvalidVersion, TypeError, ValueError):
        return None


def equal_versions(a, b):
    av = parse_version(a)
    bv = parse_version(b)

    if av is not None and bv is not None:
        return av == bv

    return str(a).strip() == str(b).strip()


def load_ranges(value):
    try:
        result = json.loads(value) if value.strip() else []
        return result if isinstance(result, list) else None
    except (ValueError, TypeError):
        return None


def evaluate_range(target, range_object):
    """
    Return:
      affected
      not_affected
      unresolved

    Supports ordered OSV ECOSYSTEM events with
    introduced, fixed, and last_affected boundaries.

    Unsupported or ambiguous ranges stay unresolved.
    """
    if not isinstance(range_object, dict):
        return "unresolved"

    if range_object.get("type") != "ECOSYSTEM":
        return "unresolved"

    events = range_object.get("events")

    if not isinstance(events, list) or not events:
        return "unresolved"

    target_v = parse_version(target)

    if target_v is None:
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

            if start != "0" and end < start:
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
print("TYPOSQUATSHIELD - OSV RANGE EVALUATION")
print("=" * 65)

historical = pd.read_csv(
    HISTORICAL,
    dtype=str,
    keep_default_na=False,
    encoding="utf-8-sig",
)

openssf = pd.read_csv(
    OPENSSF,
    dtype=str,
    keep_default_na=False,
    encoding="utf-8-sig",
)

required_historical = {"package_name", "version"}
required_openssf = {
    "package_name",
    "package_version",
    "affected_ranges",
    "report_id",
}

if not required_historical.issubset(historical.columns):
    raise ValueError("Missing historical columns")

if not required_openssf.issubset(openssf.columns):
    raise ValueError("Missing OpenSSF columns")

historical["normalized_name"] = historical[
    "package_name"
].map(canonicalize_name)

openssf["normalized_name"] = openssf[
    "package_name"
].map(canonicalize_name)

# Combine evidence by report ID to avoid repeatedly
# interpreting the same report's range.
evidence = defaultdict(
    lambda: {
        "versions": set(),
        "ranges": set(),
    }
)

for _, row in openssf.iterrows():
    key = (
        row["normalized_name"],
        row["report_id"].strip(),
    )

    if row["package_version"].strip():
        evidence[key]["versions"].add(
            row["package_version"].strip()
        )

    if row["affected_ranges"].strip():
        evidence[key]["ranges"].add(
            row["affected_ranges"].strip()
        )


results = []

for _, item in historical.iterrows():
    name = item["normalized_name"]
    version = item["version"]

    exact_ids = set()
    range_ids = set()
    unresolved_ids = set()
    evaluated_not_affected_ids = set()

    for (report_name, report_id), report in evidence.items():
        if report_name != name:
            continue

        if any(
            equal_versions(version, v)
            for v in report["versions"]
        ):
            exact_ids.add(report_id)
            continue

        for raw_range in report["ranges"]:
            ranges = load_ranges(raw_range)

            if ranges is None:
                unresolved_ids.add(report_id)
                continue

            if not ranges:
                continue

            outcomes = [
                evaluate_range(version, r)
                for r in ranges
            ]

            if "affected" in outcomes:
                range_ids.add(report_id)
            elif "unresolved" in outcomes:
                unresolved_ids.add(report_id)
            elif outcomes and all(
                x == "not_affected" for x in outcomes
            ):
                evaluated_not_affected_ids.add(report_id)

    if exact_ids:
        status = "explicit_version_match"
    elif range_ids:
        status = "range_affected_candidate"
    elif unresolved_ids:
        status = "range_unresolved"
    else:
        status = "no_confirmed_affected_version"

    record = item.to_dict()

    record.update({
        "evidence_status": status,
        "explicit_report_ids": ";".join(sorted(exact_ids)),
        "range_affected_report_ids": ";".join(
            sorted(range_ids)
        ),
        "unresolved_report_ids": ";".join(
            sorted(unresolved_ids)
        ),
        "evaluated_not_affected_report_ids": ";".join(
            sorted(evaluated_not_affected_ids)
        ),
        "label_verified": False,
    })

    results.append(record)


result_df = pd.DataFrame(results)

result_df.to_csv(
    OUTPUT,
    index=False,
    encoding="utf-8-sig",
)

counts = result_df["evidence_status"].value_counts()

statuses = [
    "explicit_version_match",
    "range_affected_candidate",
    "range_unresolved",
    "no_confirmed_affected_version",
]

lines = [
    "TYPOSQUATSHIELD - OSV RANGE EVALUATION",
    "=" * 60,
    f"Historical records: {len(result_df)}",
    f"Unique packages: {result_df['normalized_name'].nunique()}",
    "",
    "EVIDENCE STATUS COUNTS:",
]

for status in statuses:
    lines.append(
        f"{status}: {int(counts.get(status, 0))}"
    )

lines.extend([
    "",
    "IMPORTANT:",
    "Only explicit versions and supported ECOSYSTEM ranges",
    "are classified as affected-version candidates.",
    "Open-ended ranges are interpreted literally.",
    "An OSV range match is not independent malware proof.",
    "Unsupported range formats remain unresolved.",
    "No confirmed benign labels are assigned.",
    "All records remain unverified for ML training.",
])

REPORT.write_text(
    "\n".join(lines),
    encoding="utf-8",
)

print("\n".join(lines))
print("\nSaved CSV:", OUTPUT)
print("Saved report:", REPORT)
print("\nRange evaluation completed.")
