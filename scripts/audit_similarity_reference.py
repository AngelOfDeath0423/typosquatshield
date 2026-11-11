
from pathlib import Path
import sys
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "scripts"))

from typosquatting_similarity import load_reference_names, normalize_name

DATASET = BASE / "data/features/year_matched_features.csv"
REPORT = BASE / "reports/similarity_reference_audit.txt"


def main():
    df = pd.read_csv(DATASET)
    references = set(load_reference_names())

    names = df["normalized_name"].map(normalize_name)
    exact_matches = names.isin(references)

    print("=" * 60)
    print("TYPOSQUATSHIELD - REFERENCE LIST AUDIT")
    print("=" * 60)

    print("Reference packages:", len(references))
    print("ML candidate packages:", len(df))
    print("Exact reference overlaps:", int(exact_matches.sum()))

    print("\nOVERLAP BY CANDIDATE GROUP")
    overlap = (
        df.assign(exact_reference_overlap=exact_matches)
        .groupby("candidate_group")["exact_reference_overlap"]
        .agg(["sum", "count"])
    )
    print(overlap.to_string())

    print("\nOVERLAPPING PACKAGE NAMES")
    overlapping_names = sorted(set(names[exact_matches]))
    for name in overlapping_names:
        print(name)

    report_lines = [
        "TYPOSQUATSHIELD - REFERENCE LIST AUDIT",
        "=" * 60,
        f"Reference packages: {len(references)}",
        f"ML candidates: {len(df)}",
        f"Exact overlaps: {int(exact_matches.sum())}",
        "",
        "OVERLAP BY GROUP",
        overlap.to_string(),
        "",
        "OVERLAPPING NAMES",
        *overlapping_names,
        "",
        "LIMITATIONS",
        "Exact overlap alone does not establish data leakage.",
        "Reference-list provenance and historical availability",
        "must be verified before final model evaluation.",
    ]

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "\n".join(report_lines),
        encoding="utf-8",
    )

    print("\nSaved:", REPORT)
    print("[SUCCESS] Reference audit completed.")


if __name__ == "__main__":
    main()
