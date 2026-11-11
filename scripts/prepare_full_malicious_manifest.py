
from pathlib import Path
import json
import re
import hashlib

import pandas as pd
from packaging.utils import canonicalize_name


# ============================================================
# TYPOSQUATSHIELD - FULL MALICIOUS CANDIDATE MANIFEST
# ============================================================

BASE = Path(__file__).resolve().parent.parent

RAW_FILE = (
    BASE / "data" / "labels" /
    "openssf_pypi_labels_raw.csv"
)

REVIEWED_FILE = (
    BASE / "data" / "labels" /
    "openssf_pypi_labels_reviewed.csv"
)

SOURCE_VERSION_FILE = (
    BASE / "data" / "labels" /
    "openssf_source_version.txt"
)

OUTPUT_DIR = BASE / "data" / "full"
REPORT_DIR = BASE / "reports"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT = OUTPUT_DIR / "malicious_manifest.csv"
SUMMARY = REPORT_DIR / "full_malicious_manifest_summary.txt"


# ============================================================
# 1. HELPERS
# ============================================================

def load_csv(path):
    if not path.exists():
        raise FileNotFoundError(
            f"Required input not found: {path}"
        )

    return pd.read_csv(
        path,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )


def normalize_name(value):
    return canonicalize_name(str(value).strip())


def valid_report_id(value):
    return bool(
        re.fullmatch(r"MAL-\d{4}-\d+", str(value).strip())
    )


def normalize_ranges(value):
    text = str(value).strip()

    if not text or text.lower() in {"nan", "none", "null"}:
        return "[]"

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None

    if not isinstance(parsed, list):
        return None

    return json.dumps(
        parsed,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest()


# ============================================================
# 2. LOAD SOURCE DATA
# ============================================================

print("=" * 65)
print("TYPOSQUATSHIELD - FULL MALICIOUS MANIFEST")
print("=" * 65)

raw = load_csv(RAW_FILE)
reviewed = load_csv(REVIEWED_FILE)

required = {
    "package_name",
    "package_version",
    "affected_ranges",
    "report_id",
    "ecosystem",
    "published",
    "withdrawn",
    "report_path",
}

for title, frame in [
    ("Raw", raw),
    ("Reviewed", reviewed),
]:
    missing = required - set(frame.columns)

    if missing:
        raise ValueError(
            f"{title} missing columns: {sorted(missing)}"
        )

if len(raw) != len(reviewed):
    raise ValueError(
        "Raw and reviewed OpenSSF row counts differ."
    )

print("Raw rows:", len(raw))
print("Reviewed rows:", len(reviewed))


# ============================================================
# 3. PREPARE VERSION-LEVEL MANIFEST
# ============================================================

records = []
invalid_report_ids = 0
invalid_ranges = 0
invalid_names = 0
non_pypi_rows = 0

for _, row in reviewed.iterrows():

    if str(row["ecosystem"]).strip().lower() != "pypi":
        non_pypi_rows += 1
        continue

    report_id = str(row["report_id"]).strip()

    if not valid_report_id(report_id):
        invalid_report_ids += 1
        continue

    package_name = str(row["package_name"]).strip()

    if not package_name:
        invalid_names += 1
        continue

    normalized_name = normalize_name(package_name)

    affected_ranges = normalize_ranges(
        row["affected_ranges"]
    )

    if affected_ranges is None:
        invalid_ranges += 1
        continue

    package_version = str(
        row["package_version"]
    ).strip()

    has_explicit_version = bool(package_version)
    has_range = affected_ranges != "[]"

    if has_explicit_version and has_range:
        version_evidence_type = "explicit_and_range"
    elif has_explicit_version:
        version_evidence_type = "explicit_version"
    elif has_range:
        version_evidence_type = "affected_range"
    else:
        version_evidence_type = "name_only"

    records.append({
        "package_name": package_name,
        "normalized_name": normalized_name,
        "package_version": package_version,
        "affected_ranges": affected_ranges,
        "report_id": report_id,
        "ecosystem": "PyPI",
        "published": str(row["published"]).strip(),
        "withdrawn": str(row["withdrawn"]).strip(),
        "report_path": str(row["report_path"]).strip(),
        "label_status": str(
            row.get("label_status", "")
        ).strip(),
        "version_evidence_type": version_evidence_type,
        "label_verified": False,
        "source_repository": (
            "ossf/malicious-packages"
        ),
    })


manifest = pd.DataFrame(records)

if manifest.empty:
    raise ValueError(
        "No valid OpenSSF PyPI records were prepared."
    )


# ============================================================
# 4. VALIDATE DUPLICATES AND SOURCE COVERAGE
# ============================================================

key_columns = [
    "normalized_name",
    "package_version",
    "affected_ranges",
    "report_id",
]

duplicates = int(
    manifest.duplicated(
        subset=key_columns
    ).sum()
)

if duplicates:
    raise ValueError(
        f"Duplicate manifest records: {duplicates}"
    )

unique_packages = manifest[
    "normalized_name"
].nunique()

unique_reports = manifest[
    "report_id"
].nunique()

evidence_counts = (
    manifest["version_evidence_type"]
    .value_counts()
    .to_dict()
)

label_counts = (
    manifest["label_status"]
    .value_counts()
    .to_dict()
)


# ============================================================
# 5. SAVE MANIFEST
# ============================================================

manifest = manifest.sort_values(
    [
        "normalized_name",
        "report_id",
        "package_version",
    ],
    kind="stable",
).reset_index(drop=True)

manifest.to_csv(
    OUTPUT,
    index=False,
    encoding="utf-8-sig",
)


# ============================================================
# 6. CREATE AUDIT SUMMARY
# ============================================================

source_version = (
    SOURCE_VERSION_FILE.read_text(
        encoding="utf-8"
    ).strip()
    if SOURCE_VERSION_FILE.exists()
    else "SOURCE VERSION FILE NOT FOUND"
)

summary = [
    "TYPOSQUATSHIELD - FULL MALICIOUS MANIFEST",
    "=" * 60,
    f"Raw OpenSSF rows: {len(raw)}",
    f"Reviewed OpenSSF rows: {len(reviewed)}",
    f"Manifest rows: {len(manifest)}",
    f"Unique packages: {unique_packages}",
    f"Unique reports: {unique_reports}",
    f"Duplicate evidence rows: {duplicates}",
    "",
    "VERSION EVIDENCE TYPES:",
]

for status, count in sorted(evidence_counts.items()):
    summary.append(
        f"{status}: {count}"
    )

summary.extend([
    "",
    "LABEL STATUS COUNTS:",
])

for status, count in sorted(label_counts.items()):
    summary.append(
        f"{status}: {count}"
    )

summary.extend([
    "",
    "VALIDATION COUNTS:",
    f"Invalid report IDs: {invalid_report_ids}",
    f"Invalid affected ranges: {invalid_ranges}",
    f"Invalid package names: {invalid_names}",
    f"Non-PyPI rows: {non_pypi_rows}",
    "",
    "SOURCE VERSION:",
    source_version,
    "",
    f"Raw CSV SHA256: {sha256_file(RAW_FILE)}",
    f"Reviewed CSV SHA256: {sha256_file(REVIEWED_FILE)}",
    "",
    "IMPORTANT:",
    "This is a candidate evidence manifest.",
    "It is not a verified binary ML training dataset.",
    "Package names alone do not prove version-level maliciousness.",
    "Affected ranges require OSV-aware evaluation.",
    "Withdrawn/disputed reports require separate handling.",
    "No malicious package artifacts were downloaded.",
])

SUMMARY.write_text(
    "\n".join(summary),
    encoding="utf-8",
)

print()
print("\n".join(summary))
print()
print("Saved manifest:", OUTPUT)
print("Saved report:", SUMMARY)
print()
print("Full malicious manifest preparation completed.")
