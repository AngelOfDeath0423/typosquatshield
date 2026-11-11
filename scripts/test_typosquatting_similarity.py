
from typosquatting_similarity import (
    analyze_package,
    load_reference_names,
    normalize_name,
)

def main():
    references = load_reference_names()
    print("=" * 60)
    print("TYPOSQUATSHIELD - SIMILARITY MODULE TESTS")
    print("=" * 60)

    assert len(references) == 100
    assert "requests" in references
    assert "numpy" in references

    # PyPI name normalization.
    assert normalize_name("My_Package") == "my-package"
    assert normalize_name("my..package") == "my-package"

    # Known reference names must not be flagged as typos.
    for name in ["requests", "numpy"]:
        result = analyze_package(name, references)
        assert result["exact_reference_match"]
        assert not result["potential_typo"]

    # Controlled typo examples.
    examples = {
        "requsets": "requests",  # Transposition
        "request": "requests",   # Deletion
        "requestss": "requests", # Insertion
        "reqeests": "requests",  # Substitution
    }

    for requested, expected in examples.items():
        result = analyze_package(requested, references)
        suggestions = [
            item["reference_package"]
            for item in result["suggestions"]
        ]

        assert expected in suggestions, (
            f"{requested}: expected {expected}, got {suggestions}"
        )
        print(f"[PASS] {requested} -> {expected}")

    # An exact reference match is not a safety guarantee.
    result = analyze_package("requests", references)
    assert "does not guarantee" in result["explanation"]
    print("[PASS] Exact match does not imply safety")

    # Empty and invalid names must be rejected.
    for invalid in ["", "-invalid", "bad/name"]:
        try:
            analyze_package(invalid, references)
        except ValueError:
            print(f"[PASS] Rejected invalid name: {invalid!r}")
        else:
            raise AssertionError(
                f"Invalid name was accepted: {invalid!r}"
            )

    print()
    print("[SUCCESS] All similarity tests passed.")


if __name__ == "__main__":
    main()
