
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
FULL = BASE / "data/full"
LEGIT = BASE / "data/legitimate"
REPORTS = BASE / "reports"

POSITIVE_FILE = FULL / "training_label_eligibility_audit.csv"
NEGATIVE_FILE = LEGIT / "legitimate_historical_consolidated.csv"

OUTPUT_FILE = FULL / "package_level_ml_candidates.csv"
REPORT_FILE = REPORTS / "package_level_ml_candidates_report.txt"

SEED = 42

def load(path):
    return pd.read_csv(
        path,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )

def select_earliest(df):
    df = df.copy()

    df["_upload_dt"] = pd.to_datetime(
        df["first_upload_time"],
        format="mixed",
        utc=True,
        errors="coerce",
    )

    if df["_upload_dt"].isna().any():
        raise ValueError("Invalid upload timestamps found.")

    df = df.sort_values(
        ["normalized_name", "_upload_dt", "version"],
        kind="stable",
    )

    return (
        df.drop_duplicates("normalized_name", keep="first")
        .drop(columns=["_upload_dt"])
        .copy()
    )

def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - PACKAGE-LEVEL ML CANDIDATES")
    print("=" * 65)

    positive = load(POSITIVE_FILE)
    negative = load(NEGATIVE_FILE)

    # Exclude any positive-side package that has conflicting
    # or temporally questionable exact-version evidence.
    excluded_names = set(
        positive.loc[
            positive["training_evidence_status"].eq(
                "conflicting_or_temporal_review"
            ),
            "normalized_name",
        ]
    )

    eligible = positive[
        positive["training_evidence_status"].eq(
            "candidate_training_review"
        )
        & ~positive["normalized_name"].isin(excluded_names)
    ].copy()

    positive_selected = select_earliest(eligible)

    # Select one historical observation per presumed
    # legitimate package.
    negative_selected = select_earliest(negative)

    # Reproducible package-level sample of equal size.
    target = len(positive_selected)

    if len(negative_selected) < target:
        raise ValueError("Insufficient negative candidates.")

    negative_selected = negative_selected.sample(
        n=target,
        random_state=SEED,
    ).copy()

    # Keep the same core metadata fields.
    columns = [
        "package_name",
        "normalized_name",
        "version",
        "first_upload_time",
        "distribution_file_count",
        "summary",
        "requires_python",
    ]

    for name, frame in [
        ("positive", positive_selected),
        ("negative", negative_selected),
    ]:
        missing = set(columns) - set(frame.columns)
        if missing:
            raise ValueError(
                f"{name} missing columns: {sorted(missing)}"
            )

    positive_output = positive_selected[columns].copy()
    negative_output = negative_selected[columns].copy()

    positive_output["candidate_group"] = (
        "openssf_exact_version_candidate"
    )
    positive_output["evidence_status"] = (
        "candidate_training_review"
    )

    negative_output["candidate_group"] = (
        "presumed_legitimate"
    )
    negative_output["evidence_status"] = (
        "no_openssf_name_overlap"
    )

    result = pd.concat(
        [positive_output, negative_output],
        ignore_index=True,
    )

    if result["normalized_name"].duplicated().any():
        raise ValueError(
            "Duplicate package names in candidate manifest."
        )

    result["ml_label"] = "unassigned"
    result["label_verified"] = False

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)

    result.to_csv(
        OUTPUT_FILE,
        index=False,
        encoding="utf-8-sig",
    )

    report = [
        "TYPOSQUATSHIELD - PACKAGE-LEVEL CANDIDATE REPORT",
        "=" * 65,
        f"Positive candidate records before package exclusion: "
        f"{len(eligible) + len(positive[(positive['training_evidence_status'] == 'candidate_training_review') & positive['normalized_name'].isin(excluded_names)])}",
        f"Packages excluded for conflicting/temporal evidence: "
        f"{len(excluded_names)}",
        f"Selected positive candidate packages: "
        f"{len(positive_output)}",
        f"Selected presumed legitimate packages: "
        f"{len(negative_output)}",
        f"Total candidate records: {len(result)}",
        f"Random seed: {SEED}",
        "",
        "LIMITATIONS:",
        "No verified binary labels assigned.",
        "OpenSSF evidence remains provisional.",
        "Absence from OpenSSF does not establish benignness.",
        "Earliest-version selection is provisional.",
        "Upload-date comparability must be evaluated.",
        "Only features available at assessment time may be used.",
    ]

    REPORT_FILE.write_text(
        "\n".join(report),
        encoding="utf-8",
    )

    print("\n".join(report))
    print()
    print("Saved:", OUTPUT_FILE)
    print("Saved:", REPORT_FILE)
    print("[SUCCESS] Package-level candidate preparation completed.")

if __name__ == "__main__":
    main()
