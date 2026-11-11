
from pathlib import Path
import json
import time
import urllib.error
import urllib.parse
import urllib.request

import pandas as pd

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/artifacts/batch_resolution_results.csv"
OUTPUT = BASE / "reports/alternative_pypi_versions_audit.csv"
REPORT = BASE / "reports/alternative_pypi_versions_report.txt"

HEADERS = {
    "User-Agent": "TyposquatShield-FYP/1.0 (research metadata audit)",
    "Accept": "application/json",
}


def fetch_project_metadata(package_name):
    encoded = urllib.parse.quote(package_name, safe="")
    url = f"https://pypi.org/pypi/{encoded}/json"

    request = urllib.request.Request(
        url,
        headers=HEADERS,
    )

    try:
        with urllib.request.urlopen(
            request, timeout=15
        ) as response:
            data = json.load(response)

        return "available", data

    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return "project_not_found", None
        return f"http_{exc.code}", None

    except (
        urllib.error.URLError,
        TimeoutError,
        ValueError,
    ):
        return "request_error", None


def main():
    print("=" * 65)
    print("TYPOSQUATSHIELD - ALTERNATIVE PYPI VERSION AUDIT")
    print("=" * 65)

    df = pd.read_csv(INPUT, dtype={"version": str})

    required = {
        "normalized_name",
        "version",
        "candidate_group",
        "resolution_status",
    }

    missing = required - set(df.columns)

    if missing:
        raise ValueError(f"Missing columns: {missing}")

    targets = df[
        df["resolution_status"].isin(
            ["not_found", "no_supported_artifacts"]
        )
    ].copy()

    print(f"Unavailable candidate versions: {len(targets)}")

    records = []
    cache = {}

    for index, row in enumerate(
        targets.itertuples(index=False), start=1
    ):
        name = str(row.normalized_name)
        version = str(row.version)

        if name not in cache:
            cache[name] = fetch_project_metadata(name)
            time.sleep(0.15)

        status, metadata = cache[name]

        versions = []
        selected_version_listed = False
        selected_version_has_files = False

        if metadata is not None:
            releases = metadata.get("releases", {})
            versions = list(releases.keys())

            selected_version_listed = version in releases

            if selected_version_listed:
                selected_version_has_files = bool(
                    releases.get(version, [])
                )

        records.append({
            "normalized_name": name,
            "version": version,
            "candidate_group": row.candidate_group,
            "original_resolution_status": row.resolution_status,
            "project_status": status,
            "available_version_count": len(versions),
            "selected_version_listed": selected_version_listed,
            "selected_version_has_files": selected_version_has_files,
            "alternative_versions_available": any(
                v != version for v in versions
            ),
        })

        print(
            f"[{index}/{len(targets)}] "
            f"{name}=={version} | "
            f"{status} | "
            f"versions={len(versions)}"
        )

    result = pd.DataFrame(records)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(OUTPUT, index=False)

    lines = [
        "TYPOSQUATSHIELD - ALTERNATIVE PYPI VERSION AUDIT",
        "=" * 65,
        f"Unavailable candidate versions checked: {len(result)}",
        "",
        "PROJECT STATUS BY GROUP",
        pd.crosstab(
            result["candidate_group"],
            result["project_status"],
        ).to_string(),
        "",
        "ALTERNATIVE VERSION AVAILABILITY",
        pd.crosstab(
            result["candidate_group"],
            result["alternative_versions_available"],
        ).to_string(),
        "",
        "LIMITATIONS",
        "This audit queries the current public PyPI JSON API.",
        "Alternative versions are not equivalent to selected versions.",
        "Missing projects do not prove maliciousness.",
        "Deleted or unavailable releases may be absent from the API.",
        "No package archives were downloaded or executed.",
        "No ML features or labels were modified.",
    ]

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print()
    print("\n".join(lines))
    print()
    print("Saved:", OUTPUT)
    print("Saved:", REPORT)
    print("[SUCCESS] Alternative-version audit completed.")


if __name__ == "__main__":
    main()
