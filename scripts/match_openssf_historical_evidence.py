
from pathlib import Path
import json
import re
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

HISTORICAL = (
    BASE / "data/full/historical_metadata_consolidated.csv"
)
LABELS = (
    BASE / "data/labels/openssf_pypi_labels_reviewed.csv"
)
OUTPUT_DIR = BASE / "data/full"
REPORT_DIR = BASE / "reports"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def normalize_name(value):
    return re.sub(r"[-_.]+", "-", str(value).lower().strip())


def parse_affected_ranges(value):
    if pd.isna(value) or str(value).strip() in ("", "[]"):
        return []

    try:
        parsed = json.loads(str(value))
        return parsed if isinstance(parsed, list) else []
    except (ValueError, TypeError):
        return []


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - OPENSSF HISTORICAL EVIDENCE MATCHING")
    print("=" * 65)

    history = pd.read_csv(
        HISTORICAL,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )

    labels = pd.read_csv(
        LABELS,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )

    print("Historical records:", len(history))
    print("OpenSSF evidence records:", len(labels))

    required_history = {
        "normalized_name", "version", "first_upload_time"
    }
    required_labels = {
        "package_name", "package_version",
        "affected_ranges", "report_id",
        "published", "withdrawn", "label_status"
    }

    if required_history - set(history.columns):
        raise ValueError("Missing required historical columns.")

    if required_labels - set(labels.columns):
        raise ValueError("Missing required OpenSSF columns.")

    labels["normalized_name"] = (
        labels["package_name"].map(normalize_name)
    )

    labels["package_version"] = (
        labels["package_version"].str.strip()
    )

    labels["parsed_ranges"] = (
        labels["affected_ranges"].map(parse_affected_ranges)
    )

    labels["has_range_evidence"] = (
        labels["parsed_ranges"].map(bool)
    )

    labels["has_explicit_version"] = (
        labels["package_version"].ne("")
    )

    labels["is_withdrawn"] = (
        labels["withdrawn"].str.strip().ne("")
    )

    labels["is_reviewed"] = (
        labels["label_status"].str.lower().eq("reviewed")
    )

    # Explicit package-version evidence only.
    explicit = labels[
        labels["has_explicit_version"]
    ].copy()

    exact = history.merge(
        explicit,
        left_on=["normalized_name", "version"],
        right_on=["normalized_name", "package_version"],
        how="left",
        suffixes=("", "_openssf"),
        indicator=True,
    )

    exact["evidence_match_type"] = exact["_merge"].map({
        "both": "exact_version",
        "left_only": "no_exact_version",
    })

    # Preserve all report matches separately.
    exact_matches = exact[
        exact["_merge"].eq("both")
    ].copy()

    exact_matches.drop(
        columns=["_merge"],
        inplace=True,
    )

    exact_path = (
        OUTPUT_DIR / "openssf_exact_version_matches.csv"
    )

    exact_matches.to_csv(
        exact_path,
        index=False,
        encoding="utf-8-sig",
    )

    # Summarize exact evidence at package-version level.
    if len(exact_matches):
        summary = (
            exact_matches.groupby(
                ["normalized_name", "version"],
                as_index=False,
            )
            .agg(
                exact_report_count=("report_id", "nunique"),
                withdrawn_report_count=("is_withdrawn", "sum"),
                reviewed_report_count=("is_reviewed", "sum"),
            )
        )
    else:
        summary = pd.DataFrame(columns=[
            "normalized_name",
            "version",
            "exact_report_count",
            "withdrawn_report_count",
            "reviewed_report_count",
        ])

    result = history.merge(
        summary,
        on=["normalized_name", "version"],
        how="left",
        validate="one_to_one",
    )

    for col in (
        "exact_report_count",
        "withdrawn_report_count",
        "reviewed_report_count",
    ):
        result[col] = (
            pd.to_numeric(result[col], errors="coerce")
            .fillna(0)
            .astype(int)
        )

    names_in_reports = set(labels["normalized_name"])

    result["has_name_level_report"] = (
        result["normalized_name"].isin(names_in_reports)
    )

    result["evidence_category"] = "no_exact_evidence"

    result.loc[
        result["has_name_level_report"],
        "evidence_category",
    ] = "name_level_only"

    result.loc[
        result["exact_report_count"] > 0,
        "evidence_category",
    ] = "exact_version_reported"

    result.loc[
        (result["exact_report_count"] > 0)
        & (
            result["withdrawn_report_count"]
            == result["exact_report_count"]
        ),
        "evidence_category",
    ] = "exact_version_all_reports_withdrawn"

    # Do not assign binary malicious/benign labels here.
    result["ml_label"] = "unassigned"

    output_path = (
        OUTPUT_DIR / "historical_openssf_evidence_matched.csv"
    )

    result.to_csv(
        output_path,
        index=False,
        encoding="utf-8-sig",
    )

    counts = result["evidence_category"].value_counts()

    report_lines = [
        "TYPOSQUATSHIELD - OPENSSF EVIDENCE MATCHING",
        "=" * 60,
        f"Historical records: {len(history)}",
        f"OpenSSF evidence records: {len(labels)}",
        f"Exact report-match rows: {len(exact_matches)}",
        f"Unique exact package-version matches: {len(summary)}",
        "",
        "EVIDENCE CATEGORIES:",
        *(
            f"{category}: {count}"
            for category, count in counts.items()
        ),
        "",
        "IMPORTANT LIMITATIONS:",
        "Exact version matches are evidence associations.",
        "Withdrawn reports require separate review.",
        "Name-only matches do not prove version-level risk.",
        "Affected version ranges are not evaluated here.",
        "No ML ground-truth labels were assigned.",
    ]

    report_path = (
        REPORT_DIR / "openssf_historical_matching_report.txt"
    )

    report_path.write_text(
        "\n".join(report_lines),
        encoding="utf-8",
    )

    print()
    print("\n".join(report_lines))
    print()
    print("Saved:", exact_path)
    print("Saved:", output_path)
    print("Saved:", report_path)
    print()
    print("[SUCCESS] Evidence matching completed.")


if __name__ == "__main__":
    main()
