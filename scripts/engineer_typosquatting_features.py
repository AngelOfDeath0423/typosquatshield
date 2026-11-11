
from pathlib import Path
import pandas as pd

from rapidfuzz.distance import DamerauLevenshtein

from scripts.typosquatting_similarity import (
    load_reference_names,
    normalize_name,
)

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/features/year_matched_features.csv"
OUTPUT = BASE / "data/features/year_matched_with_typo_features.csv"
REPORT = BASE / "reports/typosquatting_feature_report.txt"

FEATURES = [
    "typo_min_edit_distance",
    "typo_max_similarity",
    "typo_potential_match",
    "typo_close_match_count",
    "typo_reference_length",
]


def calculate_features(package_name, references):
    name = normalize_name(package_name)

    matches = []

    for reference in references:
        distance = DamerauLevenshtein.distance(
            name, reference
        )

        similarity = (
            DamerauLevenshtein.normalized_similarity(
                name, reference
            )
        )

        threshold = 1 if len(reference) <= 5 else 2

        matches.append({
            "reference": reference,
            "distance": distance,
            "similarity": similarity,
            "is_close": distance <= threshold,
        })

    # Closest reference by edit distance, then similarity.
    closest = min(
        matches,
        key=lambda x: (
            x["distance"],
            -x["similarity"],
            x["reference"],
        ),
    )

    return {
        "typo_min_edit_distance": closest["distance"],
        "typo_max_similarity": max(
            item["similarity"] for item in matches
        ),
        "typo_potential_match": int(
            any(item["is_close"] for item in matches)
        ),
        "typo_close_match_count": sum(
            item["is_close"] for item in matches
        ),
        "typo_reference_length": len(
            closest["reference"]
        ),
    }


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - TYPOSQUATTING FEATURE ENGINEERING")
    print("=" * 65)

    df = pd.read_csv(INPUT)
    references = load_reference_names()

    if not references:
        raise ValueError("Reference list is empty.")

    if df["normalized_name"].duplicated().any():
        raise ValueError("Duplicate candidate packages detected.")

    normalized_names = df["normalized_name"].map(
        normalize_name
    )

    if normalized_names.isin(references).any():
        raise ValueError(
            "Candidate/reference overlap detected."
        )

    engineered = [
        calculate_features(name, references)
        for name in normalized_names
    ]

    feature_df = pd.DataFrame(engineered)
    result = pd.concat(
        [
            df.reset_index(drop=True),
            feature_df,
        ],
        axis=1,
    )

    if result[FEATURES].isna().any().any():
        raise ValueError("Missing similarity features.")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    result.to_csv(OUTPUT, index=False)

    group_stats = (
        result.groupby("candidate_group")[FEATURES]
        .mean()
        .round(4)
    )

    report = [
        "TYPOSQUATSHIELD - TYPOSQUATTING FEATURE REPORT",
        "=" * 65,
        f"Input records: {len(df)}",
        f"Output records: {len(result)}",
        f"Reference packages: {len(references)}",
        f"New features: {len(FEATURES)}",
        "",
        "GROUP FEATURE MEANS:",
        group_stats.to_string(),
        "",
        "POTENTIAL TYPO MATCHES BY GROUP:",
        result.groupby("candidate_group")[
            "typo_potential_match"
        ].agg(["sum", "count"]).to_string(),
        "",
        "LIMITATIONS:",
        "Reference list contains only 100 packages.",
        "Reference-list historical availability is not yet verified.",
        "Similarity does not establish maliciousness.",
        "Candidate-group labels remain provisional.",
        "No final model evaluation is performed here.",
    ]

    REPORT.write_text(
        "\n".join(report),
        encoding="utf-8",
    )

    print("\n".join(report))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Typosquatting features engineered.")


if __name__ == "__main__":
    main()
