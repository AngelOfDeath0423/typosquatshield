
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
SOURCE = BASE / "data/full/openssf_exact_version_matches.csv"
OUT = BASE / "data/full"
REPORTS = BASE / "reports"

OUT.mkdir(parents=True, exist_ok=True)
REPORTS.mkdir(parents=True, exist_ok=True)


def main():
    df = pd.read_csv(
        SOURCE,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )

    required = [
        "normalized_name", "version", "report_id",
        "label_status", "first_upload_time",
        "published", "withdrawn",
    ]
    missing = set(required) - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    upload = pd.to_datetime(
        df["first_upload_time"],
        format="mixed",
        utc=True,
        errors="coerce",
    )
    published = pd.to_datetime(
        df["published"],
        format="mixed",
        utc=True,
        errors="coerce",
    )

    if upload.isna().any() or published.isna().any():
        raise ValueError("Invalid timestamps detected.")

    df["uploaded_before_report"] = upload < published
    df["uploaded_after_report"] = upload > published
    df["days_between_upload_and_report"] = (
        (published - upload).dt.total_seconds() / 86400
    ).round(2)

    withdrawn = df["withdrawn"].str.strip().ne("")
    candidate = df["label_status"].eq("candidate_malicious")
    review = df["label_status"].eq("needs_review")

    df["evidence_review_category"] = "manual_review"

    df.loc[
        candidate & (upload < published) & ~withdrawn,
        "evidence_review_category",
    ] = "candidate_temporally_consistent"

    df.loc[
        review,
        "evidence_review_category",
    ] = "needs_source_review"

    df.loc[
        upload > published,
        "evidence_review_category",
    ] = "uploaded_after_report_review"

    df.loc[
        withdrawn,
        "evidence_review_category",
    ] = "withdrawn_report_review"

    # Preserve uncertainty: no binary labels assigned.
    df["ml_label"] = "unassigned"

    output = OUT / "openssf_temporal_evidence_audit.csv"
    df.to_csv(output, index=False, encoding="utf-8-sig")

    review_queue = df[
        df["evidence_review_category"]
        != "candidate_temporally_consistent"
    ].copy()

    review_path = OUT / "openssf_evidence_review_queue.csv"
    review_queue.to_csv(
        review_path, index=False, encoding="utf-8-sig"
    )

    counts = df["evidence_review_category"].value_counts()

    report = [
        "TYPOSQUATSHIELD - FULL TEMPORAL EVIDENCE AUDIT",
        "=" * 60,
        f"Exact-match records: {len(df)}",
        f"Unique matched package versions: "
        f"{df[['normalized_name','version']].drop_duplicates().shape[0]}",
        "",
        "REVIEW CATEGORIES:",
        *(f"{k}: {v}" for k, v in counts.items()),
        "",
        f"Review queue rows: {len(review_queue)}",
        "",
        "LIMITATIONS:",
        "Temporal consistency does not verify maliciousness.",
        "Affected ranges are not evaluated.",
        "Historical feature availability still requires review.",
        "No ML ground-truth labels assigned.",
    ]

    report_path = REPORTS / "openssf_temporal_audit_report.txt"
    report_path.write_text("\n".join(report), encoding="utf-8")

    print("\n".join(report))
    print()
    print("Saved:", output)
    print("Saved:", review_path)
    print("Saved:", report_path)
    print("[SUCCESS] Temporal audit completed.")


if __name__ == "__main__":
    main()
