
"""
TyposquatShield - Risk Advisory Decision Service

Produces explainable pre-installation advisories.

The experimental ML candidate-group score is NOT
treated as a verified malware probability.
"""

from datetime import datetime, timezone


ADVISORY_POLICY_VERSION = "0.1.0"


def _add_reason(reasons, message):
    if message not in reasons:
        reasons.append(message)


def generate_advisory(
    metadata_status,
    typo_result,
    metadata=None,
    ml_prediction=None,
    reputation=None,
):
    """
    Generate a conservative, evidence-based advisory.

    Returns:
        risk_level: Low Risk / Caution / High Risk
        advisory_reasons: explanatory messages
        advisory_policy_version: policy identifier

    The experimental ML prediction is retained as
    supporting context only and does not determine
    the advisory level.
    """

    reasons = []
    evidence = []

    potential_typo = bool(
        typo_result.get("potential_typo", False)
    )

    exact_reference = bool(
        typo_result.get("exact_reference_match", False)
    )

    suggestions = typo_result.get("suggestions") or []

    # 1. Handle unavailable PyPI metadata.
    if metadata_status == "not_found":
        if potential_typo and suggestions:
            best = suggestions[0]

            risk_level = "High Risk"

            _add_reason(
                reasons,
                "The requested package was not found on PyPI.",
            )

            _add_reason(
                reasons,
                (
                    "Its name closely resembles the curated "
                    f"package '{best['reference_package']}'."
                ),
            )

            _add_reason(
                reasons,
                "Verify the intended package name before installation.",
            )

            evidence.append("unavailable_package_with_close_name")

        else:
            risk_level = "Caution"

            _add_reason(
                reasons,
                "The requested package was not found on PyPI.",
            )

            _add_reason(
                reasons,
                "Package availability and safety could not be established.",
            )

            evidence.append("package_not_found")

        return {
            "risk_level": risk_level,
            "advisory_reasons": reasons,
            "advisory_evidence": evidence,
            "advisory_policy_version": ADVISORY_POLICY_VERSION,
            "advisory_basis": "rule_based",
        }

    # 2. Guard against unsupported metadata states.
    if metadata_status != "available":
        return {
            "risk_level": "Caution",
            "advisory_reasons": [
                "Package metadata availability is uncertain.",
                "The assessment could not establish sufficient evidence.",
            ],
            "advisory_evidence": ["metadata_status_unknown"],
            "advisory_policy_version": ADVISORY_POLICY_VERSION,
            "advisory_basis": "rule_based",
        }

    metadata = metadata or {}
    reputation = reputation or {}

    # 3. Evaluate name-similarity concerns.
    if potential_typo:
        evidence.append("close_name_similarity")

        if suggestions:
            best = suggestions[0]

            _add_reason(
                reasons,
                (
                    "The package name resembles "
                    f"'{best['reference_package']}' "
                    "in the curated reference list."
                ),
            )

    # 4. Evaluate available package metadata.
    summary = str(metadata.get("summary") or "").strip()

    if not summary:
        evidence.append("missing_summary")

        _add_reason(
            reasons,
            "The package does not provide a summary.",
        )

    project_urls = metadata.get("project_urls") or {}

    if not project_urls:
        evidence.append("missing_project_links")

        _add_reason(
            reasons,
            "No project links were provided in PyPI metadata.",
        )

    # 5. Evaluate observed release history.
    prior_release_count = reputation.get(
        "prior_release_count"
    )

    if prior_release_count is None:
        evidence.append("release_history_unavailable")

        _add_reason(
            reasons,
            "Release-history evidence is unavailable.",
        )

    elif prior_release_count == 0:
        evidence.append("no_observed_release_history")

        _add_reason(
            reasons,
            "No earlier releases were observed in the available PyPI history.",
        )

    # 6. Experimental ML is not used as a security verdict.
    if ml_prediction is not None:
        _add_reason(
            reasons,
            (
                "Experimental ML results are supplementary "
                "and are not verified malware probabilities."
            ),
        )

    # 7. Apply transparent advisory rules.
    if potential_typo:
        risk_level = "High Risk"

        _add_reason(
            reasons,
            "Confirm the intended spelling before installation.",
        )

    elif exact_reference:
        if evidence:
            risk_level = "Caution"
        else:
            risk_level = "Low Risk"

        _add_reason(
            reasons,
            (
                "The name matches the curated reference list, "
                "but this does not guarantee package safety."
            ),
        )

    elif evidence:
        risk_level = "Caution"

        _add_reason(
            reasons,
            "Review the identified indicators before installation.",
        )

    else:
        risk_level = "Caution"

        _add_reason(
            reasons,
            (
                "No major concerns were identified by these rules, "
                "but the available evidence is insufficient "
                "to establish a Low Risk advisory."
            ),
        )

    return {
        "risk_level": risk_level,
        "advisory_reasons": reasons,
        "advisory_evidence": evidence,
        "advisory_policy_version": ADVISORY_POLICY_VERSION,
        "advisory_basis": "rule_based",
    }


if __name__ == "__main__":
    print("TYPOSQUATSHIELD - ADVISORY SERVICE")
    print("Policy version:", ADVISORY_POLICY_VERSION)
    print("[SUCCESS] Advisory service loaded.")
