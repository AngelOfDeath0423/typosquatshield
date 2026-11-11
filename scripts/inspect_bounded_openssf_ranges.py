
from pathlib import Path
import json
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
SOURCE = BASE / "data/labels/openssf_pypi_labels_reviewed.csv"

df = pd.read_csv(
    SOURCE,
    dtype=str,
    keep_default_na=False,
    encoding="utf-8-sig",
)

rows = []

for _, record in df.iterrows():
    ranges = json.loads(record["affected_ranges"] or "[]")

    for item in ranges:
        events = item.get("events", [])

        if any(
            "fixed" in event or "last_affected" in event
            for event in events
        ):
            rows.append({
                "package_name": record["package_name"],
                "package_version": record["package_version"],
                "report_id": record["report_id"],
                "label_status": record["label_status"],
                "range_type": item.get("type", ""),
                "events": json.dumps(events),
            })

result = pd.DataFrame(rows)

print("=" * 60)
print("TYPOSQUATSHIELD - BOUNDED RANGE INSPECTION")
print("=" * 60)

print("Bounded range records:", len(result))
print()

if not result.empty:
    print(result.to_string(index=False, max_colwidth=120))

print()
print("[SUCCESS] Inspection completed.")
