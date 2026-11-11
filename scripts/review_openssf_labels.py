
import pandas as pd
import re
from _paths import LABELS_DATA_DIR

INPUT = LABELS_DATA_DIR / "openssf_pypi_labels_raw.csv"
OUTPUT = LABELS_DATA_DIR / "openssf_pypi_labels_reviewed.csv"

df = pd.read_csv(
    INPUT,
    dtype=str,
    keep_default_na=False
)

# These terms are review signals, not proof of maliciousness.
REVIEW_PATTERNS = [
    r"\bprobably_pentest\b",
    r"\bpentest\b",
    r"\bsecurity research\b",
    r"\bresearcher\b",
    r"\bproof.of.concept\b",
    r"\bfalse positive\b",
    r"\btest package\b",
    r"\bdemonstration\b",
    r"\blocalhost\b",
    r"\b127\.0\.0\.1\b",
]

pattern = re.compile(
    "|".join(REVIEW_PATTERNS),
    flags=re.IGNORECASE
)

def classify(row):
    if row["withdrawn"].strip():
        return "excluded_withdrawn"

    evidence = (
        row["summary"] + " " + row["details"]
    )

    if pattern.search(evidence):
        return "needs_review"

    return "candidate_malicious"

df["label_status"] = df.apply(classify, axis=1)

df.to_csv(
    OUTPUT,
    index=False,
    encoding="utf-8-sig"
)

print("=" * 55)
print("OPENSSF LABEL QUALITY SCREENING")
print("=" * 55)

print(f"\nTotal records: {len(df):,}")

print("\n--- Label status breakdown ---")
print(df["label_status"].value_counts())

print("\n--- Unique packages by status ---")
print(
    df.groupby("label_status")["package_name"].nunique()
)

print("\n--- Output ---")
print(OUTPUT)

print("\nScreening completed.")
