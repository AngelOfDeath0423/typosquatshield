
import pandas as pd
import re
from _paths import LABELS_DATA_DIR

df = pd.read_csv(
    LABELS_DATA_DIR / "openssf_pypi_labels_reviewed.csv",
    dtype=str,
    keep_default_na=False
)

patterns = {
    "probably_pentest": r"\bprobably_pentest\b",
    "pentest": r"\bpentest\b",
    "security_research": r"\bsecurity research\b|\bresearcher\b",
    "proof_of_concept": r"\bproof.of.concept\b",
    "false_positive": r"\bfalse positive\b",
    "test_package": r"\btest package\b",
    "demonstration": r"\bdemonstration\b",
    "localhost": r"\blocalhost\b|\b127\.0\.0\.1\b",
}

text = df["summary"] + " " + df["details"]

print("=" * 55)
print("OPENSSF REVIEW REASON ANALYSIS")
print("=" * 55)

print("\nReview signal counts:")
for name, pattern in patterns.items():
    matches = text.str.contains(
        pattern,
        case=False,
        regex=True,
        na=False
    )

    print(f"{name}: {matches.sum():,}")

print("\nExamples requiring review:")
review = df[df["label_status"] == "needs_review"]

print(
    review[
        ["package_name", "report_id", "summary"]
    ].head(15).to_string(index=False)
)

print("\nAnalysis completed.")
