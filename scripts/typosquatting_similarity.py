
from pathlib import Path
import argparse
import json
import re

import pandas as pd
from rapidfuzz.distance import DamerauLevenshtein

BASE = Path(__file__).resolve().parent.parent

REFERENCE_FILE = (
    BASE / "data/legitimate/legitimate_pypi_pilot_100.csv"
)


def normalize_name(name):
    """Normalize according to PyPI name normalization rules."""
    return re.sub(r"[-_.]+", "-", str(name).strip()).lower()


def load_reference_names():
    if not REFERENCE_FILE.exists():
        raise FileNotFoundError(REFERENCE_FILE)

    df = pd.read_csv(
        REFERENCE_FILE,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8-sig",
    )

    column = (
        "normalized_name"
        if "normalized_name" in df.columns
        else "package_name"
    )

    names = {
        normalize_name(name)
        for name in df[column]
        if str(name).strip()
    }

    return sorted(names)


def analyze_package(package_name, references, limit=5):
    requested = normalize_name(package_name)

    if not requested:
        raise ValueError("Package name cannot be empty.")

    if not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
        requested,
    ):
        raise ValueError("Invalid normalized package name.")

    # Exact names are not typosquatting candidates.
    if requested in references:
        return {
            "requested_package": requested,
            "exact_reference_match": True,
            "potential_typo": False,
            "suggestions": [],
            "explanation": (
                "Exact match in the curated reference list. "
                "This does not guarantee package safety."
            ),
        }

    suggestions = []

    for reference in references:
        distance = DamerauLevenshtein.distance(
            requested,
            reference,
        )

        similarity = DamerauLevenshtein.normalized_similarity(
            requested,
            reference,
        )

        # Conservative initial candidate-generation rule.
        max_distance = 1 if len(reference) <= 5 else 2

        if distance <= max_distance:
            suggestions.append({
                "reference_package": reference,
                "edit_distance": int(distance),
                "similarity": round(float(similarity), 4),
            })

    suggestions.sort(
        key=lambda item: (
            item["edit_distance"],
            -item["similarity"],
            item["reference_package"],
        )
    )

    suggestions = suggestions[:limit]

    return {
        "requested_package": requested,
        "exact_reference_match": False,
        "potential_typo": bool(suggestions),
        "suggestions": suggestions,
        "explanation": (
            "Similar to a curated reference package. "
            "Check the intended spelling before installation."
            if suggestions
            else
            "No close match found in the limited reference list. "
            "This does not imply the package is safe."
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description="TyposquatShield name similarity checker"
    )

    parser.add_argument(
        "package",
        help="PyPI package name to assess",
    )

    args = parser.parse_args()

    references = load_reference_names()
    result = analyze_package(args.package, references)

    print("=" * 60)
    print("TYPOSQUATSHIELD - NAME SIMILARITY CHECK")
    print("=" * 60)
    print("Reference packages loaded:", len(references))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
