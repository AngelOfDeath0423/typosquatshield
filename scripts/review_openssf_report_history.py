
import json
import subprocess
from collections import defaultdict
from pathlib import Path

import pandas as pd
from packaging.utils import canonicalize_name
from packaging.version import Version, InvalidVersion


# ============================================================
# TYPOSQUATSHIELD - OPENSSF REPORT HISTORY REVIEW
# ============================================================

BASE = Path(__file__).resolve().parent.parent

REPO = BASE / "malicious-packages"

ANOMALIES = (
    BASE / "data" / "audit" /
    "timeline_anomalies_100.csv"
)

RAW_LABELS = (
    BASE / "data" / "labels" /
    "openssf_pypi_labels_raw.csv"
)

OUTPUT = (
    BASE / "data" / "audit" /
    "openssf_report_history_review_100.csv"
)

SUMMARY = (
    BASE / "reports" /
    "openssf_report_history_review_summary.txt"
)

SOURCE_COMMIT = (
    "3812671bee8aa766a40bcdf9ee322d7c6456cf29"
)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
SUMMARY.parent.mkdir(parents=True, exist_ok=True)


# ============================================================
# 1. GIT HELPERS
# ============================================================

def git(*args, timeout=60):
    result = subprocess.run(
        ["git", "-C", str(REPO), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Git command failed: {' '.join(args)}\n"
            f"{result.stderr.strip()}"
        )

    return result.stdout.strip()


def read_report(commit, path):
    content = git(
        "show",
        f"{commit}:{path}",
    )
    return json.loads(content)


def parse_date(value):
    text = str(value).strip()

    if not text or text.lower() in (
        "nan", "nat", "null", "none"
    ):
        return pd.NaT

    if text.endswith(" UTC"):
        text = text[:-4] + "+00:00"

    return pd.to_datetime(
        text,
        utc=True,
        errors="coerce",
    )


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


def explicit_version_in_report(
    report,
    package_name,
    version,
):
    target = canonicalize_name(package_name)

    for affected in report.get("affected", []):
        package = affected.get("package") or {}

        if str(
            package.get("ecosystem", "")
        ).lower() != "pypi":
            continue

        report_name = canonicalize_name(
            package.get("name", "")
        )

        if report_name != target:
            continue

        for listed_version in (
            affected.get("versions") or []
        ):
            if versions_equal(version, listed_version):
                return True

    return False


# ============================================================
# 2. LOAD DATA
# ============================================================

print("=" * 65)
print("TYPOSQUATSHIELD - OPENSSF REPORT HISTORY REVIEW")
print("=" * 65)

anomalies = pd.read_csv(
    ANOMALIES,
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

required_anomalies = {
    "package_name",
    "version",
    "supporting_report_ids",
    "first_upload_time",
    "earliest_report_published",
}

required_raw = {
    "report_id",
    "report_path",
}

for title, frame, required in (
    ("Anomalies", anomalies, required_anomalies),
    ("Raw labels", raw, required_raw),
):
    missing = required - set(frame.columns)

    if missing:
        raise ValueError(
            f"{title} missing columns: {missing}"
        )

source_check = git(
    "rev-parse",
    SOURCE_COMMIT,
)

if source_check != SOURCE_COMMIT:
    raise ValueError(
        "Pinned source commit could not be verified."
    )

print("Anomalous records:", len(anomalies))
print(
    "Unique packages:",
    anomalies["package_name"].nunique(),
)
print("Pinned source commit:", SOURCE_COMMIT)


# ============================================================
# 3. BUILD REPORT PATH LOOKUP
# ============================================================

report_paths = defaultdict(set)

for _, row in raw.iterrows():
    report_id = row["report_id"].strip()
    path = row["report_path"].strip()

    if report_id and path:
        report_paths[report_id].add(path)


# ============================================================
# 4. READ REPORT GIT HISTORY
# ============================================================

# Cache history so each report is processed only once.

history_cache = {}


def get_report_history(report_id):
    if report_id in history_cache:
        return history_cache[report_id]

    paths = report_paths.get(report_id, set())

    if not paths:
        history_cache[report_id] = []
        return []

    history = []

    for path in sorted(paths):
        # Git history is restricted to the pinned snapshot.
        # --follow allows simple file rename tracking.
        commits = git(
            "log",
            "--follow",
            "--format=%H",
            SOURCE_COMMIT,
            "--",
            path,
        ).splitlines()

        for commit in reversed(commits):
            try:
                report = read_report(commit, path)
            except Exception:
                # The file might have had a different path
                # before a rename. Do not invent evidence.
                continue

            history.append({
                "commit": commit,
                "path": path,
                "report": report,
                "published": report.get("published", ""),
                "modified": report.get("modified", ""),
            })

    history_cache[report_id] = history
    return history


# ============================================================
# 5. REVIEW EACH ANOMALOUS VERSION
# ============================================================

results = []

for index, (_, row) in enumerate(
    anomalies.iterrows(),
    start=1,
):
    name = row["package_name"]
    version = row["version"]

    report_ids = [
        x.strip()
        for x in row["supporting_report_ids"].split(";")
        if x.strip()
    ]

    upload_date = parse_date(
        row["first_upload_time"]
    )

    publication_date = parse_date(
        row["earliest_report_published"]
    )

    for report_id in report_ids:
        history = get_report_history(report_id)

        first_seen_commit = ""
        first_seen_git_date = ""
        first_seen_report_modified = ""
        first_seen_report_published = ""

        earliest_available_commit = (
            history[0]["commit"] if history else ""
        )

        for entry in history:
            if explicit_version_in_report(
                entry["report"],
                name,
                version,
            ):
                first_seen_commit = entry["commit"]
                first_seen_report_modified = (
                    entry["modified"]
                )
                first_seen_report_published = (
                    entry["published"]
                )

                try:
                    first_seen_git_date = git(
                        "show",
                        "-s",
                        "--format=%cI",
                        first_seen_commit,
                    )
                except Exception:
                    pass

                break

        if not history:
            status = "history_unavailable"
        elif not first_seen_commit:
            status = "version_not_found_in_history"
        elif first_seen_commit == earliest_available_commit:
            status = "present_in_earliest_available_commit"
        else:
            status = "added_in_later_commit"

        results.append({
            "package_name": name,
            "version": version,
            "report_id": report_id,
            "first_upload_time": (
                upload_date.isoformat()
                if pd.notna(upload_date) else ""
            ),
            "report_published": (
                publication_date.isoformat()
                if pd.notna(publication_date) else ""
            ),
            "first_seen_commit": first_seen_commit,
            "first_seen_git_date": first_seen_git_date,
            "first_seen_report_published": (
                first_seen_report_published
            ),
            "first_seen_report_modified": (
                first_seen_report_modified
            ),
            "git_history_entries": len(history),
            "history_status": status,
            "requires_manual_review": True,
        })

    print(
        f"[{index}/{len(anomalies)}] "
        f"{name} {version}: reviewed",
        flush=True,
    )


# ============================================================
# 6. SAVE RESULTS
# ============================================================

result_df = pd.DataFrame(results)

result_df.to_csv(
    OUTPUT,
    index=False,
    encoding="utf-8-sig",
)

counts = (
    result_df["history_status"].value_counts()
    if not result_df.empty
    else pd.Series(dtype=int)
)

statuses = [
    "present_in_earliest_available_commit",
    "added_in_later_commit",
    "version_not_found_in_history",
    "history_unavailable",
]

summary_lines = [
    "TYPOSQUATSHIELD - OPENSSF REPORT HISTORY REVIEW",
    "=" * 60,
    f"Anomalous records: {len(anomalies)}",
    f"Report-version checks: {len(result_df)}",
    f"Unique packages: {anomalies['package_name'].nunique()}",
    f"Pinned source commit: {SOURCE_COMMIT}",
    "",
    "GIT HISTORY RESULTS:",
]

for status in statuses:
    summary_lines.append(
        f"{status}: {int(counts.get(status, 0))}"
    )

summary_lines.extend([
    "",
    "INTERPRETATION:",
    "Git history shows when versions first appear in",
    "the available repository history.",
    "Git commit dates are not guaranteed to equal",
    "the actual report update or discovery dates.",
    "A version present in the earliest available commit",
    "may have existed in the report before repository import.",
    "No version is automatically excluded or verified.",
    "Manual review remains required.",
])

SUMMARY.write_text(
    "\n".join(summary_lines),
    encoding="utf-8",
)

print()
print("\n".join(summary_lines))
print("\nSaved CSV:", OUTPUT)
print("Saved report:", SUMMARY)
print("\nReport history review completed.")
