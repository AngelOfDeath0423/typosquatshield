
import pandas as pd
import json
from collections import Counter
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

file_path = BASE / "data/labels/openssf_pypi_labels_reviewed.csv"

df = pd.read_csv(
    file_path,
    dtype=str,
    keep_default_na=False
)

range_types = Counter()
event_keys = Counter()
examples = {}

total_ranges = 0
parsing_errors = 0

for value in df["affected_ranges"]:

    try:
        ranges = json.loads(value) if value.strip() else []

        for item in ranges:
            total_ranges += 1

            range_type = item.get("type", "UNKNOWN")
            range_types[range_type] += 1

            for event in item.get("events", []):
                for key in event:
                    event_keys[key] += 1

                    if key not in examples:
                        examples[key] = event

    except (ValueError, TypeError, AttributeError):
        parsing_errors += 1

print("=" * 60)
print("TYPOSQUATSHIELD - OPENSSF RANGE AUDIT")
print("=" * 60)

print("Parsed range objects:", total_ranges)
print("Range types:", dict(range_types))
print("Event keys:", dict(event_keys))
print("Parsing errors:", parsing_errors)
print("Event examples:", examples)

print()
print("[SUCCESS] Range audit completed.")
