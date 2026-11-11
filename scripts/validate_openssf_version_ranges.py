
from pathlib import Path
import json
import re
from collections import defaultdict

import pandas as pd
from packaging.version import Version, InvalidVersion


BASE = Path(__file__).resolve().parent.parent

HISTORY_PATH = BASE / "data/full/historical_metadata_consolidated.csv"
REPORTS_PATH = BASE / "data/labels/openssf_pypi_labels_reviewed.csv"
OUTPUT_DIR = BASE / "data/full"
REPORT_DIR = BASE / "reports"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def normalize_name(name):
    return re.sub(r"[-_.]+", "-", str(name).strip().lower())


def check_range(version_text, range_data):
    """
    Evaluate supported OSV ECOSYSTEM range events.

    Returns:
        (True, reason)  - version lies in the range
        (False, reason) - version lies outside the range
        (None, reason)  - cannot safely evaluate
    """
    if range_data.get("type") != "ECOSYSTEM":
        return None, "unsupported_range_type"

    events = range_data.get("events", [])
    if not isinstance(events, list) or not events:
        return None, "invalid_events"

    try:
        version = Version(version_text)
    except InvalidVersion:
        return None, "invalid_package_version"

    intervals = []
    introduced = None
    open_interval = False

    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return None, "unsupported_event_structure"

        if "introduced" in event:
            if open_interval:
                return None, "ambiguous_introduced_event"

            value = str(event["introduced"])
            try:
                introduced = None if value == "0" else Version(value)
            except InvalidVersion:
                return None, "invalid_introduced_version"

            open_interval = True

        elif "fixed" in event or "last_affected" in event:
            if not open_interval:
                return None, "missing_introduced_event"

            inclusive = "last_affected" in event
            value = event.get("last_affected", event.get("fixed"))

            try:
                ending = Version(str(value))
            except InvalidVersion:
                return None, "invalid_ending_version"

            intervals.append((introduced, ending, inclusive))
            introduced = None
            open_interval = False

        else:
            return None, "unsupported_event_type"

    if open_interval:
        intervals.append((introduced, None, False))

    for start, end, inclusive in intervals:
        lower_ok = start is None or version >= start
        upper_ok = (
            end is None
            or version < end
            or (inclusive and version == end)
        )

        if lower_ok and upper_ok:
            return True, "range_matched"

    return False, "outside_range"


def main():
    history = pd.read_csv(
        HISTORY_PATH,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )

    reports = pd.read_csv(
        REPORTS_PATH,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )

    history["normalized_name"] = history["normalized_name"].map(
        normalize_name
    )
    reports["normalized_name"] = reports["package_name"].map(
        normalize_name
    )

    evidence_by_name = defaultdict(list)
    invalid_json = 0

    for _, report in reports.iterrows():
        raw = report["affected_ranges"].strip()
        if not raw or raw == "[]":
            continue

        try:
            ranges = json.loads(raw)
        except (ValueError, TypeError):
            invalid_json += 1
            continue

        if not isinstance(ranges, list):
            invalid_json += 1
            continue

        for item in ranges:
            if isinstance(item, dict):
                evidence_by_name[report["normalized_name"]].append(
                    {
                        "report_id": report["report_id"],
                        "label_status": report["label_status"],
                        "withdrawn": report["withdrawn"],
                        "range": item,
                    }
                )

    exact_pairs = set(
        zip(
            reports.loc[
                reports["package_version"].ne(""),
                "normalized_name",
            ],
            reports.loc[
                reports["package_version"].ne(""),
                "package_version",
            ],
        )
    )

    output_rows = []
    matched_range_rows = []
    ambiguous_rows = []

    for record in history.to_dict("records"):
        name = record["normalized_name"]
        version = record["version"]

        exact_match = (name, version) in exact_pairs

        matched_reports = []
        ambiguous_reasons = []

        for evidence in evidence_by_name.get(name, []):
            result, reason = check_range(
                version,
                evidence["range"],
            )

            if result is True:
                matched_reports.append(evidence)
            elif result is None:
                ambiguous_reasons.append(reason)

        range_match = bool(matched_reports)

        if exact_match:
            category = "explicit_version_evidence"
        elif range_match:
            category = "range_supported_evidence"
        else:
            category = "insufficient_version_evidence"

        row = {
            "normalized_name": name,
            "version": version,
            "first_upload_time": record["first_upload_time"],
            "exact_version_match": exact_match,
            "range_match": range_match,
            "range_report_ids": ";".join(sorted({
                x["report_id"] for x in matched_reports
            })),
            "range_has_candidate_report": any(
                x["label_status"] == "candidate_malicious"
                and not x["withdrawn"].strip()
                for x in matched_reports
            ),
            "ambiguous_range_evaluation": bool(ambiguous_reasons),
            "ambiguous_reasons": ";".join(
                sorted(set(ambiguous_reasons))
            ),
            "evidence_category": category,
            "ml_label": "unassigned",
        }

        output_rows.append(row)

        if range_match:
            matched_range_rows.append(row)

        if ambiguous_reasons:
            ambiguous_rows.append(row)

    result = pd.DataFrame(output_rows)

    result_path = OUTPUT_DIR / "openssf_version_range_validation.csv"
    range_path = OUTPUT_DIR / "openssf_range_supported_versions.csv"
    ambiguous_path = OUTPUT_DIR / "openssf_ambiguous_range_reviews.csv"

    result.to_csv(result_path, index=False, encoding="utf-8-sig")
    pd.DataFrame(matched_range_rows).to_csv(
        range_path, index=False, encoding="utf-8-sig"
    )
    pd.DataFrame(ambiguous_rows).to_csv(
        ambiguous_path, index=False, encoding="utf-8-sig"
    )

    counts = result["evidence_category"].value_counts()

    report_lines = [
        "TYPOSQUATSHIELD - VERSION RANGE VALIDATION",
        "=" * 60,
        f"Historical records: {len(history)}",
        f"Reports with range evidence: {len(evidence_by_name)}",
        f"Invalid range JSON: {invalid_json}",
        "",
        "EVIDENCE CATEGORIES:",
        *(f"{key}: {value}" for key, value in counts.items()),
        "",
        f"Range-matched records: {len(matched_range_rows)}",
        f"Ambiguous evaluations: {len(ambiguous_rows)}",
        "",
        "LIMITATIONS:",
        "Open-ended ranges are report claims, not verified malware.",
        "Exact version matches are report associations.",
        "No final binary ML labels have been assigned.",
    ]

    report_path = REPORT_DIR / "openssf_version_range_validation_report.txt"
    report_path.write_text("\n".join(report_lines), encoding="utf-8")

    print("\n".join(report_lines))
    print()
    print("Saved:", result_path)
    print("Saved:", range_path)
    print("Saved:", ambiguous_path)
    print("Saved:", report_path)
    print()
    print("[SUCCESS] Version-range validation completed.")


if __name__ == "__main__":
    main()
