
from functools import lru_cache

from scripts.model_inference import TyposquatShieldModel
from backend.services.feature_service import prepare_live_features
from backend.services.reputation_service import (
    calculate_live_reputation,
)


@lru_cache(maxsize=1)
def load_model():
    """Load the exported model once per backend process."""
    return TyposquatShieldModel()


def assess_with_ml(metadata, typo_result=None):
    """
    Perform experimental candidate-group inference.

    Exact reference-list matches are excluded from
    experimental ML inference because the original
    training dataset excluded these packages.

    This is not a verified malware detector or a
    final Low/Caution/High installation-risk decision.
    """

    if typo_result is None:
        typo_result = {}

    # Exact reference-list packages were excluded
    # from the historical ML training dataset.
    if typo_result.get("exact_reference_match") is True:

        reputation = calculate_live_reputation(
            metadata
        )

        return {
            "assessment_status": (
                "exact_reference_match_ml_not_applicable"
            ),
            "risk_level": None,
            "ml_prediction": None,
            "feature_status": "not_applicable",
            "missing_features": [],
            "reputation": reputation,
            "limitations": [
                "Package exactly matches the curated reference list.",
                "Exact reference matches were excluded from ML training.",
                "The experimental model was not applied.",
                "Reference-list membership does not guarantee safety.",
                "No final installation-risk advisory has been assigned.",
            ],
        }

    prepared = prepare_live_features(
        metadata,
        typo_result=typo_result,
    )

    model = load_model()

    if prepared["feature_count"] != len(model.features):
        raise ValueError("Feature count mismatch.")

    if list(prepared["features"]) != model.features:
        raise ValueError("Feature ordering mismatch.")

    prediction = model.predict(
        prepared["features"]
    )

    return {
        "assessment_status": "experimental_ml_completed",
        "risk_level": None,
        "ml_prediction": prediction,
        "feature_status": prepared["feature_status"],
        "missing_features": prepared["missing_features"],
        "reputation": prepared["reputation_features"],
        "limitations": [
            "Model labels represent provisional candidate groups.",
            "The ML score is not a malware probability.",
            "Live metadata differs from historical training data.",
            "The final advisory policy is not yet implemented.",
        ],
    }


if __name__ == "__main__":
    model = load_model()

    print("TYPOSQUATSHIELD - ML SERVICE")
    print("Model loaded:", model.metadata["experiment"])
    print("Expected features:", len(model.features))
