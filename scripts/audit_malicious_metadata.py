
import csv
import json
import random
import time
import urllib.error
import urllib.request

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from packaging.utils import canonicalize_name


# ============================================================
# TYPOSQUATSHIELD - MALICIOUS METADATA AVAILABILITY AUDIT
# ============================================================

BASE = Path(__file__).resolve().parent.parent

LABEL_DIR = BASE / "data" / "labels"
OUTPUT_DIR = BASE / "data" / "audit"
REPORT_DIR = BASE / "reports"

MANIFEST = LABEL_DIR / "openssf_pypi_label_manifest.csv"
RAW_LABELS = LABEL_DIR / "openssf_pypi_labels_raw.csv"

OUTPUT = OUTPUT_DIR / "malicious_metadata_audit_100.csv"
SUMMARY = REPORT_DIR / "malicious_metadata_audit_summary.txt"

SAMPLE_SIZE = 100
RANDOM_SEED = 42
REQUEST_DELAY = 0.3

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# 1. LOAD DATA
# ============================================================

print("=" * 65)
print("TYPOSQUATSHIELD - MALICIOUS METADATA AUDIT")
print("=" * 65)

if not MANIFEST.exists():
    raise FileNotFoundError(f"Missing manifest: {MANIFEST}")

if not RAW_LABELS.exists():
    raise FileNotFoundError(f"Missing raw labels: {RAW_LABELS}")

manifest = pd.read_csv(
    MANIFEST,
    dtype=str,
    keep_default_na=False,
    encoding="utf-8-sig",
)

raw = pd.read_csv(
    RAW_LABELS,
    dtype=str,
    keep_default_na=False,
    encoding="utf-8-sig",
)

required_manifest = {
    "package_name",
    "normalized_name",
    "label_status",
}

required_raw = {
    "package_name",
    "package_version",
    "affected_ranges",
}

if not required_manifest.issubset(manifest.columns):
    raise ValueError(
        "Manifest missing columns: "
        + str(required_manifest - set(manifest.columns))
    )

if not required_raw.issubset(raw.columns):
    raise ValueError(
        "Raw labels missing columns: "
        + str(required_raw - set(raw.columns))
    )

manifest["normalized_name"] = (
    manifest["package_name"].map(canonicalize_name)
)

raw["normalized_name"] = (
    raw["package_name"].map(canonicalize_name)
)

print("Manifest packages:", len(manifest))
print("Raw report rows:", len(raw))


# ============================================================
# 2. BUILD REPORTED VERSION LOOKUP
# ============================================================

# Preserve exact reported versions.
# Affected ranges are counted separately.
# We do NOT assume the latest PyPI release is malicious.

version_lookup = {}
range_lookup = {}

for row in raw.itertuples(index=False):
    name = row.normalized_name

    version_lookup.setdefault(name, set())
    range_lookup.setdefault(name, set())

    if row.package_version:
        version_lookup[name].add(row.package_version.strip())

    if row.affected_ranges:
        range_lookup[name].add(row.affected_ranges.strip())


# ============================================================
# 3. SELECT REPRODUCIBLE RANDOM SAMPLE
# ============================================================

# Prefer candidate_malicious entries for this pilot.
# This is still a provisional label, not verified ground truth.

candidates = manifest[
    manifest["label_status"] == "candidate_malicious"
].copy()

if candidates.empty:
    raise ValueError("No candidate_malicious records found.")

sample = candidates.sample(
    n=min(SAMPLE_SIZE, len(candidates)),
    random_state=RANDOM_SEED,
)

print("Candidate pool:", len(candidates))
print("Audit sample:", len(sample))
print("Random seed:", RANDOM_SEED)


# ============================================================
# 4. FETCH PYPI METADATA
# ============================================================

def fetch_pypi(name):
    url = f"https://pypi.org/pypi/{name}/json"

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": (
                "TyposquatShield-FYP/0.1 "
                "(academic metadata availability audit)"
            ),
            "Accept": "application/json",
        },
    )

    with urllib.request.urlopen(
        request,
        timeout=15,
    ) as response:
        return json.load(response)


# ============================================================
# 5. AUDIT EACH PACKAGE
# ============================================================

results = []

for index, (_, package) in enumerate(
    sample.iterrows(),
    start=1,
):
    name = package["package_name"]
    normalized = package["normalized_name"]

    reported_versions = version_lookup.get(
        normalized, set()
    )

    affected_ranges = range_lookup.get(
        normalized, set()
    )

    result = {
        "package_name": name,
        "normalized_name": normalized,
        "label_status": package["label_status"],
        "reported_explicit_version_count": len(
            reported_versions
        ),
        "reported_range_count": len(affected_ranges),
        "pypi_available": False,
        "http_status": "",
        "latest_version": "",
        "latest_version_reported": False,
        "reported_version_in_pypi_history": False,
        "matching_reported_version_count": 0,
        "version_count": 0,
        "has_summary": False,
        "has_author": False,
        "has_home_page": False,
        "has_requires_dist": False,
        "error": "",
        "checked_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    try:
        data = fetch_pypi(name)

        info = data.get("info") or {}
        releases = data.get("releases") or {}

        latest_version = info.get("version") or ""

        # PyPI releases can contain historical versions,
        # but their presence is not proof of artifact access.
        historical_versions = set(releases.keys())

        matches = (
            reported_versions & historical_versions
        )

        result.update({
            "pypi_available": True,
            "http_status": 200,
            "latest_version": latest_version,
            "latest_version_reported": (
                latest_version in reported_versions
            ),
            "reported_version_in_pypi_history": (
                len(matches) > 0
            ),
            "matching_reported_version_count": len(
                matches
            ),
            "version_count": len(releases),
            "has_summary": bool(
                str(info.get("summary") or "").strip()
            ),
            "has_author": bool(
                str(info.get("author") or "").strip()
            ),
            "has_home_page": bool(
                str(info.get("home_page") or "").strip()
            ),
            "has_requires_dist": bool(
                info.get("requires_dist")
            ),
        })

        status = "AVAILABLE"

    except urllib.error.HTTPError as error:
        result["http_status"] = error.code
        result["error"] = str(error)
        status = f"HTTP {error.code}"

    except (
        urllib.error.URLError,
        TimeoutError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        result["error"] = str(error)
        status = "REQUEST ERROR"

    results.append(result)

    print(
        f"[{index}/{len(sample)}] "
        f"{name}: {status}",
        flush=True,
    )

    time.sleep(REQUEST_DELAY)


# ============================================================
# 6. SAVE CSV
# ============================================================

df = pd.DataFrame(results)

df.to_csv(
    OUTPUT,
    index=False,
    encoding="utf-8-sig",
)


# ============================================================
# 7. GENERATE SUMMARY
# ============================================================

total = len(df)

available = int(df["pypi_available"].sum())

not_found = int(
    (df["http_status"] == 404).sum()
)

request_errors = total - available - not_found

version_matches = int(
    df["reported_version_in_pypi_history"].sum()
)

summary_lines = [
    "TYPOSQUATSHIELD - MALICIOUS METADATA AUDIT",
    "=" * 55,
    f"Audit sample: {total}",
    f"Random seed: {RANDOM_SEED}",
    "",
    f"PyPI package metadata available: {available}",
    f"PyPI HTTP 404: {not_found}",
    f"Other request errors: {request_errors}",
    "",
    f"Packages with reported version in PyPI history: "
    f"{version_matches}",
    "",
    "INTERPRETATION:",
    "A PyPI 404 does not mean the OpenSSF report is invalid.",
    "An available package name does not establish that the "
    "reported malicious version is still available.",
    "Version ranges require separate interpretation.",
    "All labels remain provisional.",
]

SUMMARY.write_text(
    "\n".join(summary_lines),
    encoding="utf-8",
)

print("\n" + "=" * 65)
print("\n".join(summary_lines))
print("\nSaved audit CSV:", OUTPUT)
print("Saved summary:", SUMMARY)
print("\nAudit completed.")
