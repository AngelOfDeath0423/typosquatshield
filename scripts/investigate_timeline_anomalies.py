
from pathlib import Path
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

INPUT = (
    BASE / "data" / "audit" /
    "historical_timeline_validation_100.csv"
)

OUTPUT = (
    BASE / "data" / "audit" /
    "timeline_anomalies_100.csv"
)

REPORT = (
    BASE / "reports" /
    "timeline_anomalies_summary.txt"
)

df = pd.read_csv(
    INPUT,
    dtype=str,
    keep_default_na=False,
    encoding="utf-8-sig",
)

anomalies = df[
    df["timeline_status"] == "uploaded_after_all_reports"
].copy()

anomalies["days_after_report"] = (
    -pd.to_numeric(
        anomalies["days_before_earliest_report"],
        errors="coerce",
    )
)

anomalies = anomalies.sort_values(
    "days_after_report",
    ascending=False,
)

anomalies.to_csv(
    OUTPUT,
    index=False,
    encoding="utf-8-sig",
)

print("=" * 65)
print("TYPOSQUATSHIELD - TIMELINE ANOMALY INVESTIGATION")
print("=" * 65)
print("Anomalous records:", len(anomalies))

columns = [
    "package_name",
    "version",
    "evidence_status",
    "supporting_report_ids",
    "days_after_report",
]

print(
    anomalies[columns].to_string(
        index=False,
    )
)

summary = [
    "TYPOSQUATSHIELD - TIMELINE ANOMALIES",
    "=" * 60,
    f"Records requiring review: {len(anomalies)}",
    "",
    "These records were uploaded after their supporting",
    "OpenSSF reports were published.",
    "",
    "They must not be automatically treated as invalid",
    "or automatically included in ML training.",
]

REPORT.parent.mkdir(parents=True, exist_ok=True)

REPORT.write_text(
    "\n".join(summary),
    encoding="utf-8",
)

print("\nSaved CSV:", OUTPUT)
print("Saved report:", REPORT)
