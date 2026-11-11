
import re
from pathlib import Path

import pandas as pd
from packaging.utils import canonicalize_name
from packaging.version import Version, InvalidVersion


BASE = Path(__file__).resolve().parent.parent

HISTORICAL = (
    BASE / "data" / "audit" / "bigquery_versions_100.csv"
)

OPENSSF = (
    BASE / "data" / "labels" /
    "openssf_pypi_labels_raw.csv"
)

OUTPUT = (
    BASE / "data" / "audit" /
    "openssf_bigquery_version_matches_100.csv"
)

REPORT = (
    BASE / "reports" /
    "openssf_bigquery_version_matching_summary.txt"
)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
REPORT.parent.mkdir(parents=True, exist_ok=True)


def normalize_name(value):
    return canonicalize_name(str(value).strip())


def versions_equal(a, b):
    """Compare versions without treating ranges as exact versions."""
    a = str(a).strip()
    b = str(b).strip()

    if not a or not b:
        return False

    try:
        return Version(a) == Version(b)
    except InvalidVersion:
        return a == b


print("=" * 65)
print("TYPOSQUATSHIELD - OPENSSF VERSION MATCHING")
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

required_historical = {
    "package_name",
    "version",
    "first_upload_time",
}

required_openssf = {
    "package_name",
    "package_version",
    "affected_ranges",
    "report_id",
}

if not required_historical.issubset(historical.columns):
    raise ValueError(
        "Historical CSV missing: "
        + str(required_historical - set(historical.columns))
    )

if not required_openssf.issubset(openssf.columns):
    raise ValueError(
        "OpenSSF CSV missing: "
        + str(required_openssf - set(openssf.columns))
    )

historical["normalized_name"] = (
    historical["package_name"].map(normalize_name)
)

openssf["normalized_name"] = (
    openssf["package_name"].map(normalize_name)
)

reports_by_name = {
    name: group
    for name, group in openssf.groupby("normalized_name")
}

results = []

for _, item in historical.iterrows():
    name = item["normalized_name"]
    version = item["version"]

    reports = reports_by_name.get(name)

    exact_ids = set()
    range_ids = set()
    name_only_ids = set()

    if reports is not None:
        for _, report in reports.iterrows():
            report_id = report["report_id"].strip()
            explicit = report["package_version"].strip()
            affected_range = report["affected_ranges"].strip()

            if explicit and versions_equal(version, explicit):
                exact_ids.add(report_id)

            elif affected_range and affected_range not in ("[]", "{}", "null"):
                range_ids.add(report_id)

            else:
                name_only_ids.add(report_id)

    if exact_ids:
        status = "explicit_version_match"
    elif range_ids:
        status = "range_evaluation_required"
    elif name_only_ids:
        status = "name_only_evidence"
    else:
        status = "no_matching_version_evidence"

    record = item.to_dict()

    record.update({
        "evidence_status": status,
        "explicit_match_report_ids": ";".join(
            sorted(exact_ids)
        ),
        "range_report_ids": ";".join(
            sorted(range_ids)
        ),
        "name_only_report_ids": ";".join(
            sorted(name_only_ids)
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

summary = [
    "TYPOSQUATSHIELD - OPENSSF VERSION MATCHING",
    "=" * 60,
    f"Historical records: {len(result_df)}",
    f"Unique packages: {result_df['normalized_name'].nunique()}",
    "",
    "EVIDENCE STATUS COUNTS:",
]

for status in [
    "explicit_version_match",
    "range_evaluation_required",
    "name_only_evidence",
    "no_matching_version_evidence",
]:
    summary.append(
        f"{status}: {int(counts.get(status, 0))}"
    )

summary += [
    "",
    "IMPORTANT:",
    "Explicit version matches are candidates for verification.",
    "Range evaluation is not yet implemented.",
    "Name-only evidence is not version-level proof.",
    "No negative labels are assigned by this script.",
    "No records are marked as verified training labels.",
    "Historical metadata is not proof of malicious behavior.",
]

REPORT.write_text(
    "\n".join(summary),
    encoding="utf-8",
)

print("\n".join(summary))
print("\nSaved CSV:", OUTPUT)
print("Saved report:", REPORT)
print("\nVersion matching completed.")
