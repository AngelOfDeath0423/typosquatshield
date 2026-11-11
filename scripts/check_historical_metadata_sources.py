
import csv
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


# ============================================================
# TYPOSQUATSHIELD - HISTORICAL METADATA FEASIBILITY TEST
# ============================================================

BASE = Path(__file__).resolve().parent.parent

AUDIT_FILE = (
    BASE / "data" / "audit" /
    "malicious_metadata_audit_100.csv"
)

OUTPUT_DIR = BASE / "data" / "audit"
REPORT_DIR = BASE / "reports"

OUTPUT_FILE = (
    OUTPUT_DIR / "historical_metadata_sources_10.csv"
)

SUMMARY_FILE = (
    REPORT_DIR / "historical_metadata_sources_summary.txt"
)

SAMPLE_SIZE = 10
REQUEST_DELAY = 0.5

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# 1. LOAD PREVIOUS AUDIT
# ============================================================

if not AUDIT_FILE.exists():
    raise FileNotFoundError(
        f"Previous audit file not found: {AUDIT_FILE}"
    )

df = pd.read_csv(
    AUDIT_FILE,
    dtype=str,
    keep_default_na=False,
    encoding="utf-8-sig",
)

required = {"package_name", "http_status"}

if not required.issubset(df.columns):
    raise ValueError(
        f"Missing columns: {required - set(df.columns)}"
    )

unavailable = df[
    df["http_status"].str.strip() == "404"
].copy()

sample = unavailable.head(SAMPLE_SIZE)

print("=" * 65)
print("TYPOSQUATSHIELD - HISTORICAL METADATA FEASIBILITY")
print("=" * 65)
print("Previous HTTP 404 packages:", len(unavailable))
print("Selected for test:", len(sample))


# ============================================================
# 2. HTTP HELPER
# ============================================================

def fetch_json(url):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": (
                "TyposquatShield-FYP/0.1 "
                "(academic metadata research)"
            ),
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=20,
        ) as response:
            return json.load(response), response.status, ""

    except urllib.error.HTTPError as error:
        return None, error.code, str(error)

    except (
        urllib.error.URLError,
        TimeoutError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        return None, "", str(error)


# ============================================================
# 3. CHECK OSV API
# ============================================================

# OSV is primarily a vulnerability/advisory source.
# It can provide report evidence, not necessarily
# the historical PyPI project metadata needed for ML.

def check_osv(report_id):
    if not report_id:
        return False, "", ""

    url = (
        "https://api.osv.dev/v1/vulns/"
        + urllib.parse.quote(report_id, safe="")
    )

    data, status, error = fetch_json(url)

    if data and isinstance(data, dict):
        return True, status, error

    return False, status, error


# ============================================================
# 4. CHECK PYPI VERSION ENDPOINT
# ============================================================

# This tests whether a version-specific endpoint is
# accessible even if the project-level endpoint returned 404.
# It is NOT an independent historical archive.

def check_pypi_version(name, version):
    if not version:
        return False, "", ""

    encoded_name = urllib.parse.quote(name, safe="")
    encoded_version = urllib.parse.quote(version, safe="")

    url = (
        f"https://pypi.org/pypi/"
        f"{encoded_name}/{encoded_version}/json"
    )

    data, status, error = fetch_json(url)

    if data and isinstance(data, dict):
        return True, status, error

    return False, status, error


# ============================================================
# 5. LOAD OPENSSF REPORT AND VERSION LOOKUPS
# ============================================================

RAW_LABELS = (
    BASE / "data" / "labels" /
    "openssf_pypi_labels_raw.csv"
)

raw = pd.read_csv(
    RAW_LABELS,
    dtype=str,
    keep_default_na=False,
    encoding="utf-8-sig",
)

from packaging.utils import canonicalize_name

raw["normalized_name"] = raw[
    "package_name"
].map(canonicalize_name)

lookup = {}

for _, row in raw.iterrows():
    name = row["normalized_name"]

    entry = lookup.setdefault(
        name,
        {"report_ids": set(), "versions": set()}
    )

    if row["report_id"]:
        entry["report_ids"].add(row["report_id"])

    if row["package_version"]:
        entry["versions"].add(row["package_version"])


# ============================================================
# 6. RUN FEASIBILITY TEST
# ============================================================

results = []

for index, (_, row) in enumerate(
    sample.iterrows(), start=1
):
    name = row["package_name"]
    normalized = canonicalize_name(name)

    evidence = lookup.get(
        normalized,
        {"report_ids": set(), "versions": set()}
    )

    report_ids = sorted(evidence["report_ids"])
    versions = sorted(evidence["versions"])

    report_id = report_ids[0] if report_ids else ""
    version = versions[0] if versions else ""

    osv_found, osv_status, osv_error = check_osv(
        report_id
    )

    version_found, version_status, version_error = (
        check_pypi_version(name, version)
    )

    result = {
        "package_name": name,
        "normalized_name": normalized,
        "report_id_tested": report_id,
        "version_tested": version,
        "osv_report_available": osv_found,
        "osv_http_status": osv_status,
        "pypi_version_metadata_available": version_found,
        "pypi_version_http_status": version_status,
        "osv_error": osv_error,
        "pypi_version_error": version_error,
        "checked_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    results.append(result)

    print(
        f"[{index}/{len(sample)}] {name} | "
        f"OSV: {osv_status} | "
        f"PyPI version: "
        f"{version_status if version else 'NO VERSION'}",
        flush=True,
    )

    time.sleep(REQUEST_DELAY)


# ============================================================
# 7. SAVE RESULTS
# ============================================================

result_df = pd.DataFrame(results)

result_df.to_csv(
    OUTPUT_FILE,
    index=False,
    encoding="utf-8-sig",
)

osv_count = int(
    result_df["osv_report_available"].sum()
)

version_count = int(
    result_df["pypi_version_metadata_available"].sum()
)

summary = [
    "TYPOSQUATSHIELD - HISTORICAL METADATA FEASIBILITY",
    "=" * 60,
    f"Packages tested: {len(result_df)}",
    f"OSV reports accessible: {osv_count}",
    f"PyPI version metadata accessible: {version_count}",
    "",
    "NOTES:",
    "OSV reports provide advisory evidence, not necessarily",
    "historical PyPI metadata suitable for model features.",
    "PyPI version endpoint is not an independent archive.",
    "No distribution artifacts were downloaded or executed.",
]

SUMMARY_FILE.write_text(
    "\n".join(summary),
    encoding="utf-8",
)

print("\n" + "=" * 65)
print("\n".join(summary))
print("\nSaved CSV:", OUTPUT_FILE)
print("Saved report:", SUMMARY_FILE)
print("\nFeasibility test completed.")
