
from backend.services.advisory_service import generate_advisory


def typo_result(
    potential_typo=False,
    exact_reference_match=False,
    suggestions=None,
):
    return {
        "potential_typo": potential_typo,
        "exact_reference_match": exact_reference_match,
        "suggestions": suggestions or [],
    }


def test_unavailable_similar_package():
    result = generate_advisory(
        metadata_status="not_found",
        typo_result=typo_result(
            potential_typo=True,
            suggestions=[
                {
                    "reference_package": "requests",
                    "edit_distance": 1,
                    "similarity": 0.8889,
                }
            ],
        ),
    )

    assert result["risk_level"] == "High Risk"
    assert (
        "unavailable_package_with_close_name"
        in result["advisory_evidence"]
    )


def test_unavailable_unknown_package():
    result = generate_advisory(
        metadata_status="not_found",
        typo_result=typo_result(),
    )

    assert result["risk_level"] == "Caution"
    assert "package_not_found" in result["advisory_evidence"]


def test_exact_reference_with_complete_metadata():
    result = generate_advisory(
        metadata_status="available",
        typo_result=typo_result(
            exact_reference_match=True
        ),
        metadata={
            "summary": "A Python HTTP library.",
            "project_urls": {
                "Homepage": "https://example.org"
            },
        },
        reputation={
            "prior_release_count": 10
        },
    )

    assert result["risk_level"] == "Low Risk"


def test_exact_reference_missing_summary():
    result = generate_advisory(
        metadata_status="available",
        typo_result=typo_result(
            exact_reference_match=True
        ),
        metadata={
            "summary": "",
            "project_urls": {
                "Homepage": "https://example.org"
            },
        },
        reputation={
            "prior_release_count": 10
        },
    )

    assert result["risk_level"] == "Caution"
    assert "missing_summary" in result["advisory_evidence"]


def test_available_similar_package():
    result = generate_advisory(
        metadata_status="available",
        typo_result=typo_result(
            potential_typo=True,
            suggestions=[
                {
                    "reference_package": "requests",
                    "edit_distance": 1,
                    "similarity": 0.8889,
                }
            ],
        ),
        metadata={
            "summary": "Example package.",
            "project_urls": {
                "Homepage": "https://example.org"
            },
        },
        reputation={
            "prior_release_count": 3
        },
    )

    assert result["risk_level"] == "High Risk"
    assert "close_name_similarity" in result["advisory_evidence"]


def test_unknown_metadata_status():
    result = generate_advisory(
        metadata_status="unknown",
        typo_result=typo_result(),
    )

    assert result["risk_level"] == "Caution"
    assert "metadata_status_unknown" in result["advisory_evidence"]


def test_ml_prediction_does_not_override_advisory():
    result = generate_advisory(
        metadata_status="available",
        typo_result=typo_result(
            exact_reference_match=True
        ),
        metadata={
            "summary": "Example package.",
            "project_urls": {
                "Homepage": "https://example.org"
            },
        },
        reputation={
            "prior_release_count": 5
        },
        ml_prediction={
            "predicted_candidate_group":
                "openssf_exact_version_candidate",
            "openssf_association_score": 0.95,
        },
    )

    assert result["risk_level"] == "Low Risk"
    assert result["advisory_basis"] == "rule_based"
