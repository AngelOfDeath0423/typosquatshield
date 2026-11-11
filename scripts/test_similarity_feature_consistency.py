
from backend.services.feature_service import (
    calculate_similarity_features,
)
from scripts.engineer_typosquatting_features import (
    calculate_features,
)
from scripts.typosquatting_similarity import (
    analyze_package,
    load_reference_names,
)

TEST_PACKAGES = [
    "requestss",
    "numpyy",
    "pandass",
    "flaskk",
    "django-rest-frameworkm",
    "some-unique-test-package",
]


def main():
    references = load_reference_names()

    print("=" * 65)
    print("TYPOSQUATSHIELD - SIMILARITY CONSISTENCY TEST")
    print("=" * 65)

    failures = []

    for package in TEST_PACKAGES:
        historical = calculate_features(
            package,
            references,
        )

        live = calculate_similarity_features(
            package,
            references,
        )

        typo_result = analyze_package(
            package,
            references,
        )

        consistent = historical == live

        print(f"\nPackage: {package}")
        print("Historical:", historical)
        print("Live:      ", live)
        print("Match:     ", consistent)
        print(
            "Potential typo:",
            typo_result["potential_typo"],
        )

        if not consistent:
            failures.append(package)

    print("\n" + "=" * 65)

    if failures:
        raise AssertionError(
            f"Feature mismatches: {failures}"
        )

    print("[SUCCESS] Historical and live similarity features match.")


if __name__ == "__main__":
    main()
