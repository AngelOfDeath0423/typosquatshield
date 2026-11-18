
"""
Audit PyPI dataset records whose distribution names match
Python standard-library module names.

Read-only: does not modify the original datasets.

Run:
    python scripts/audit_stdlib_dataset_names.py
"""

import csv
import re
import sys
from pathlib import Path

import pandas as pd


DATASETS = [
    Path("data/full/year_matched_ml_candidates.csv"),
    Path("data/full/package_level_ml_candidates.csv"),
    Path("data/full/version_aware_assessment_pool.csv"),
    Path("data/legitimate/legitimate_selected_10000.csv"),
    Path("data/labels/openssf_pypi_labels_reviewed.csv"),
]

OUTPUT = Path("data/audit/stdlib_name_matches.csv")

STDLIB_NAMES = getattr(sys, "stdlib_module_names", frozenset())


def normalize_name(name):
    return re.sub(r"[-_.]+", "-", str(name).strip().lower())


NORMALIZED_STDLIB = {
    normalize_name(name): name
    for name in STDLIB_NAMES
}


def audit_dataset(path):
    if not path.exists():
        print(f"[SKIP] Missing: {path}")
        return [], None

    df = pd.read_csv(path, low_memory=False)

    name_column = (
        "normalized_name"
        if "normalized_name" in df.columns
        else "package_name"
    )

    if name_column not in df.columns:
        print(f"[SKIP] No package-name column: {path}")
        return [], None

    normalized = df[name_column].fillna("").map(normalize_name)

    matches = df.loc[
        normalized.isin(NORMALIZED_STDLIB)
    ].copy()

    matches["stdlib_module"] = normalized.loc[
        matches.index
    ].map(NORMALIZED_STDLIB)

    matches["source_dataset"] = str(path)

    matches["review_status"] = "requires_context_review"

    print(
        f"{path.name}: "
        f"{len(matches):,} matching records / "
        f"{matches['stdlib_module'].nunique():,} unique names "
        f"(total records: {len(df):,})"
    )

    return matches.to_dict(orient="records"), {
        "dataset": str(path),
        "total_records": len(df),
        "matching_records": len(matches),
        "unique_stdlib_names": matches["stdlib_module"].nunique(),
    }


def main():
    if not STDLIB_NAMES:
        raise RuntimeError(
            "Python stdlib_module_names is unavailable. "
            "Use Python 3.10 or newer."
        )

    print(f"Python: {sys.version.split()[0]}")
    print(f"Standard-library names: {len(STDLIB_NAMES)}")
    print()

    all_matches = []
    summaries = []

    for path in DATASETS:
        matches, summary = audit_dataset(path)
        all_matches.extend(matches)

        if summary:
            summaries.append(summary)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    if all_matches:
        columns = sorted({
            key
            for record in all_matches
            for key in record
        })

        with OUTPUT.open(
            "w", newline="", encoding="utf-8-sig"
        ) as file:
            writer = csv.DictWriter(
                file, fieldnames=columns, extrasaction="ignore"
            )
            writer.writeheader()
            writer.writerows(all_matches)
    else:
        pd.DataFrame(
            columns=[
                "source_dataset",
                "stdlib_module",
                "review_status",
            ]
        ).to_csv(OUTPUT, index=False)

    print("\n" + "=" * 60)
    print("AUDIT SUMMARY")
    print("=" * 60)

    print(f"Datasets checked: {len(summaries)}")
    print(f"Matching records: {len(all_matches):,}")

    unique_names = sorted({
        record["stdlib_module"]
        for record in all_matches
    })

    print(f"Unique standard-library names: {len(unique_names)}")

    if unique_names:
        print("\nMatching module names:")
        for name in unique_names:
            print(f"  - {name}")

    print(f"\nReport saved: {OUTPUT}")
    print(
        "\nNo original dataset records were modified. "
        "Name matches alone do not establish incorrect labels."
    )


if __name__ == "__main__":
    main()
