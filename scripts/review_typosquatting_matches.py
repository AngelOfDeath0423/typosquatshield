
from pathlib import Path
import pandas as pd

from rapidfuzz.distance import DamerauLevenshtein

from typosquatting_similarity import (
    load_reference_names,
    normalize_name,
)

BASE = Path(__file__).resolve().parent.parent

INPUT = (
    BASE / "data/features/year_matched_with_typo_features.csv"
)

OUTPUT = (
    BASE / "reports/typosquatting_match_review.csv"
)

REFERENCES = load_reference_names()


def find_matches(package_name):
    name = normalize_name(package_name)
    results = []

    for reference in REFERENCES:
        distance = DamerauLevenshtein.distance(
            name, reference
        )

        threshold = 1 if len(reference) <= 5 else 2

        if distance <= threshold and name != reference:
            results.append({
                "reference": reference,
                "distance": distance,
                "similarity": round(
                    DamerauLevenshtein.normalized_similarity(
                        name, reference
                    ),
                    4,
                ),
            })

    return sorted(
        results,
        key=lambda item: (
            item["distance"],
            -item["similarity"],
            item["reference"],
        ),
    )


def main():
    df = pd.read_csv(INPUT)

    candidates = df[
        df["typo_potential_match"] == 1
    ].copy()

    records = []

    for _, row in candidates.iterrows():
        matches = find_matches(row["normalized_name"])

        if not matches:
            raise ValueError(
                f"No match for {row['normalized_name']}"
            )

        for match in matches:
            records.append({
                "package_name": row["normalized_name"],
                "candidate_group": row["candidate_group"],
                "version": row["version"],
                "first_upload_time": row["first_upload_time"],
                "reference_package": match["reference"],
                "edit_distance": match["distance"],
                "similarity": match["similarity"],
                "review_status": "unreviewed",
                "review_notes": "",
            })

    result = pd.DataFrame(records)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(OUTPUT, index=False)

    print("=" * 65)
    print("TYPOSQUATSHIELD - TYPO MATCH REVIEW")
    print("=" * 65)

    print("Packages flagged:", len(candidates))
    print("Candidate/reference pairs:", len(result))

    print("\nFLAGGED PACKAGES BY GROUP")
    print(
        candidates["candidate_group"].value_counts().to_string()
    )

    print("\nFIRST 30 CANDIDATE/REFERENCE PAIRS")

    columns = [
        "package_name",
        "reference_package",
        "edit_distance",
        "similarity",
        "candidate_group",
    ]

    print(
        result[columns].head(30).to_string(index=False)
    )

    print("\nSaved:", OUTPUT)
    print("[SUCCESS] Match review file created.")


if __name__ == "__main__":
    main()
