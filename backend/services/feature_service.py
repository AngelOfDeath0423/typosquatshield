
import math
import re

from packaging.version import Version, InvalidVersion
from rapidfuzz.distance import DamerauLevenshtein

from backend.services.reputation_service import (
    calculate_live_reputation,
)

EXPECTED_FEATURES = [
    "name_length",
    "name_separator_count",
    "name_digit_count",
    "version_is_prerelease",
    "summary_length",
    "summary_word_count",
    "summary_missing",
    "requires_python_missing",
    "typo_min_edit_distance",
    "typo_max_similarity",
    "typo_potential_match",
    "typo_close_match_count",
    "typo_reference_length",
    "prior_release_count",
    "has_prior_history",
    "observed_package_age_days",
]


def normalize_name(name):
    return re.sub(
        r"[-_.]+",
        "-",
        str(name).strip().lower(),
    )


def version_prerelease_flag(version):
    if not version:
        return None

    try:
        return int(
            Version(str(version)).is_prerelease
        )
    except InvalidVersion:
        return None


def calculate_similarity_features(
    package_name,
    references,
):
    """
    Reproduce the original training similarity
    feature calculations across all references.
    """

    name = normalize_name(package_name)

    reference_names = sorted({
        normalize_name(reference)
        for reference in references
        if str(reference).strip()
    })

    if not reference_names:
        raise ValueError(
            "Similarity reference list is empty."
        )

    matches = []

    for reference in reference_names:
        distance = DamerauLevenshtein.distance(
            name,
            reference,
        )

        similarity = (
            DamerauLevenshtein.normalized_similarity(
                name,
                reference,
            )
        )

        threshold = (
            1 if len(reference) <= 5 else 2
        )

        matches.append({
            "reference": reference,
            "distance": distance,
            "similarity": similarity,
            "is_close": distance <= threshold,
        })

    closest = min(
        matches,
        key=lambda item: (
            item["distance"],
            -item["similarity"],
            item["reference"],
        ),
    )

    return {
        "typo_min_edit_distance": int(
            closest["distance"]
        ),
        "typo_max_similarity": float(
            max(
                item["similarity"]
                for item in matches
            )
        ),
        "typo_potential_match": int(
            any(
                item["is_close"]
                for item in matches
            )
        ),
        "typo_close_match_count": sum(
            item["is_close"]
            for item in matches
        ),
        "typo_reference_length": len(
            closest["reference"]
        ),
    }


def prepare_live_features(
    metadata,
    typo_result=None,
    references=None,
):
    """
    Prepare the 16 features required by the
    exported TyposquatShield model.

    The live reputation features are approximations
    based on currently retained PyPI release data.

    This function does not perform ML inference.
    """

    if references is None:
        from scripts.typosquatting_similarity import (
            load_reference_names,
        )
        references = load_reference_names()

    name = normalize_name(
        metadata.get("package_name", "")
    )

    version = metadata.get("version")
    summary = metadata.get("summary") or ""
    requires_python = metadata.get(
        "requires_python"
    )

    similarity = calculate_similarity_features(
        name,
        references,
    )

    reputation = calculate_live_reputation(
        metadata
    )

    features = {
        "name_length": len(name),
        "name_separator_count": name.count("-"),
        "name_digit_count": sum(
            character.isdigit()
            for character in name
        ),
        "version_is_prerelease": (
            version_prerelease_flag(version)
        ),
        "summary_length": len(summary),
        "summary_word_count": len(
            summary.split()
        ),
        "summary_missing": int(
            not summary.strip()
        ),
        "requires_python_missing": int(
            not requires_python
        ),
        "typo_min_edit_distance": (
            similarity["typo_min_edit_distance"]
        ),
        "typo_max_similarity": (
            similarity["typo_max_similarity"]
        ),
        "typo_potential_match": (
            similarity["typo_potential_match"]
        ),
        "typo_close_match_count": (
            similarity["typo_close_match_count"]
        ),
        "typo_reference_length": (
            similarity["typo_reference_length"]
        ),
        "prior_release_count": (
            reputation["prior_release_count"]
        ),
        "has_prior_history": (
            reputation["has_prior_history"]
        ),
        "observed_package_age_days": (
            reputation["observed_package_age_days"]
        ),
    }

    if list(features) != EXPECTED_FEATURES:
        raise ValueError(
            "Feature ordering does not match "
            "the exported model."
        )

    for feature, value in features.items():
        if (
            isinstance(value, (int, float))
            and not math.isfinite(value)
        ):
            raise ValueError(
                f"Non-finite feature: {feature}"
            )

    available = [
        feature
        for feature, value in features.items()
        if value is not None
    ]

    missing = [
        feature
        for feature, value in features.items()
        if value is None
    ]

    return {
        "features": features,
        "similarity_features": similarity,
        "reputation_features": reputation,
        "available_features": available,
        "missing_features": missing,
        "feature_count": len(features),
        "feature_status": (
            "complete"
            if not missing
            else "partial"
        ),
        "limitations": [
            "Candidate-group labels remain provisional.",
            "Live release history may differ from historical training coverage.",
            "Observed package age is not verified creation age.",
            "Similarity references are limited to the original curated list.",
            "An exact reference match does not guarantee safety.",
            "Feature preparation does not establish malware risk.",
        ],
    }


if __name__ == "__main__":
    print(
        "TYPOSQUATSHIELD - LIVE FEATURE SERVICE"
    )
    print(
        "Expected features:",
        len(EXPECTED_FEATURES),
    )
