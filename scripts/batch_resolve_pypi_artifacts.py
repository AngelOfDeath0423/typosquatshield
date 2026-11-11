
"""
TyposquatShield - Batch PyPI Artifact Resolution

Resolves current PyPI artifact availability for selected
historical package versions without downloading package files.

Usage:
    python scripts/batch_resolve_pypi_artifacts.py --limit 20
    python scripts/batch_resolve_pypi_artifacts.py --limit 100
    python scripts/batch_resolve_pypi_artifacts.py --all
"""

from pathlib import Path
import argparse
import json
import time

import pandas as pd

from resolve_pypi_artifacts import resolve_artifacts


BASE = Path(__file__).resolve().parent.parent

INPUT_CANDIDATES = [
    BASE / "data/full/version_aware_matched_candidates.csv",
    BASE / "data/features/version_aware_combined_features.csv",
]

OUTPUT_DIR = BASE / "data/artifacts"
REPORT_DIR = BASE / "reports"

RESULTS = OUTPUT_DIR / "batch_resolution_results.csv"
INVENTORY = OUTPUT_DIR / "batch_artifact_inventory.csv"
REPORT = REPORT_DIR / "batch_artifact_availability_report.txt"

KEY_COLUMNS = ["normalized_name", "version"]

RESULT_COLUMNS = [
    "normalized_name",
    "version",
    "candidate_group",
    "resolution_status",
    "artifact_count",
    "wheel_count",
    "sdist_count",
    "has_sha256",
    "resolved_at_utc",
    "error",
]

INVENTORY_COLUMNS = [
    "normalized_name",
    "version",
    "candidate_group",
    "filename",
    "artifact_type",
    "download_url",
    "size_bytes",
    "sha256",
    "upload_time_iso_8601",
    "yanked",
]


def load_candidates():
    source = next(
        (p for p in INPUT_CANDIDATES if p.exists()),
        None,
    )

    if source is None:
        raise FileNotFoundError(
            "No candidate dataset found. Checked:\n"
            + "\n".join(str(p) for p in INPUT_CANDIDATES)
        )

    df = pd.read_csv(
        source,
        dtype={"normalized_name": str, "version": str},
        keep_default_na=False,
    )

    required = set(KEY_COLUMNS + ["candidate_group"])
    missing = required - set(df.columns)

    if missing:
        raise ValueError(
            f"Missing candidate columns: {sorted(missing)}"
        )

    df = df[KEY_COLUMNS + ["candidate_group"]].copy()

    if df[KEY_COLUMNS].isna().any().any():
        raise ValueError("Missing package/version keys.")

    if (
        df["normalized_name"].eq("").any()
        or df["version"].eq("").any()
    ):
        raise ValueError("Empty package names or versions.")

    if df.duplicated(KEY_COLUMNS).any():
        raise ValueError("Duplicate package-version keys.")

    print("Candidate source:", source)
    print("Candidate records:", len(df))

    return df


def read_existing(path, columns):
    if not path.exists():
        return pd.DataFrame(columns=columns)

    df = pd.read_csv(
        path,
        dtype={"normalized_name": str, "version": str},
        keep_default_na=False,
    )

    missing = set(columns) - set(df.columns)
    if missing:
        raise ValueError(
            f"{path.name} missing columns: {sorted(missing)}"
        )

    return df[columns].copy()


def save_tables(results, inventory):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    results.to_csv(RESULTS, index=False)
    inventory.to_csv(INVENTORY, index=False)


def build_report(candidates, results, inventory):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    merged = candidates.merge(
        results[KEY_COLUMNS + [
            "resolution_status", "artifact_count"
        ]],
        on=KEY_COLUMNS,
        how="left",
        validate="one_to_one",
    )

    merged["resolution_status"] = (
        merged["resolution_status"].fillna("not_checked")
    )

    status_table = pd.crosstab(
        merged["candidate_group"],
        merged["resolution_status"],
    )

    artifact_table = (
        inventory.groupby(
            ["candidate_group", "artifact_type"]
        )
        .size()
        .unstack(fill_value=0)
    )

    lines = [
        "TYPOSQUATSHIELD - BATCH ARTIFACT AVAILABILITY",
        "=" * 65,
        f"Candidate records: {len(candidates)}",
        f"Checked records: "
        f"{int((merged['resolution_status'] != 'not_checked').sum())}",
        f"Resolved records: "
        f"{int((merged['resolution_status'] == 'resolved').sum())}",
        f"Not checked: "
        f"{int((merged['resolution_status'] == 'not_checked').sum())}",
        f"Artifact inventory records: {len(inventory)}",
        "",
        "STATUS BY CANDIDATE GROUP",
        status_table.to_string(),
        "",
        "ARTIFACT TYPES BY GROUP",
        artifact_table.to_string()
        if not artifact_table.empty else "No artifacts yet.",
        "",
        "LIMITATIONS",
        "Availability reflects the current PyPI API.",
        "Unavailable artifacts are not proof of maliciousness.",
        "Current availability does not prove historical availability.",
        "Artifact metadata is not package-code analysis.",
        "Candidate-group labels remain provisional.",
        "No malware detection or model training performed.",
    ]

    REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print()
    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser()

    mode = parser.add_mutually_exclusive_group(required=True)

    mode.add_argument(
        "--limit",
        type=int,
        help="Maximum new package versions to check",
    )

    mode.add_argument(
        "--all",
        action="store_true",
        help="Check all remaining candidates",
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between requests in seconds",
    )

    args = parser.parse_args()

    if args.limit is not None and args.limit <= 0:
        parser.error("--limit must be positive")

    if args.delay < 0:
        parser.error("--delay cannot be negative")

    print("=" * 65)
    print("TYPOSQUATSHIELD - BATCH ARTIFACT RESOLVER")
    print("=" * 65)

    candidates = load_candidates()

    results = read_existing(RESULTS, RESULT_COLUMNS)
    inventory = read_existing(INVENTORY, INVENTORY_COLUMNS)

    if results.duplicated(KEY_COLUMNS).any():
        raise ValueError(
            "Duplicate records in existing resolution results."
        )

    # Only terminal outcomes are skipped. Temporary network
    # failures can be retried in later runs.
    terminal_statuses = {
        "resolved",
        "not_found",
        "no_supported_artifacts",
    }

    completed = set(
        map(
            tuple,
            results.loc[
                results["resolution_status"].isin(
                    terminal_statuses
                ),
                KEY_COLUMNS,
            ].itertuples(index=False, name=None),
        )
    )

    remaining = candidates.loc[
        ~candidates[KEY_COLUMNS].apply(
            tuple, axis=1
        ).isin(completed)
    ]

    if not args.all:
        remaining = remaining.head(args.limit)

    print("Already completed:", len(completed))
    print("Selected for this run:", len(remaining))

    for index, row in enumerate(
        remaining.itertuples(index=False), start=1
    ):
        name = row.normalized_name
        version = row.version
        group = row.candidate_group

        try:
            resolved = resolve_artifacts(name, version)

        except Exception as exc:
            resolved = {
                "resolution_status": "resolver_error",
                "artifacts": [],
                "resolved_at_utc": "",
                "error": str(exc),
            }

        artifacts = resolved.get("artifacts", [])
        status = resolved.get(
            "resolution_status", "unknown"
        )

        record = {
            "normalized_name": name,
            "version": version,
            "candidate_group": group,
            "resolution_status": status,
            "artifact_count": len(artifacts),
            "wheel_count": sum(
                a.get("artifact_type") == "wheel"
                for a in artifacts
            ),
            "sdist_count": sum(
                a.get("artifact_type") == "sdist_tar_gz"
                for a in artifacts
            ),
            "has_sha256": bool(artifacts) and all(
                a.get("has_sha256", False)
                for a in artifacts
            ),
            "resolved_at_utc": resolved.get(
                "resolved_at_utc", ""
            ),
            "error": resolved.get("error") or "",
        }

        # Replace previous failed attempt for this key.
        mask = (
            (results["normalized_name"] == name)
            & (results["version"] == version)
        )

        results = results.loc[~mask].copy()

        results = pd.concat(
            [results, pd.DataFrame([record])],
            ignore_index=True,
        )

        inventory_mask = (
            (inventory["normalized_name"] == name)
            & (inventory["version"] == version)
        )

        inventory = inventory.loc[
            ~inventory_mask
        ].copy()

        new_artifacts = [
            {
                "normalized_name": name,
                "version": version,
                "candidate_group": group,
                **{
                    field: a.get(field)
                    for field in INVENTORY_COLUMNS[3:]
                },
            }
            for a in artifacts
        ]

        if new_artifacts:
            inventory = pd.concat(
                [
                    inventory,
                    pd.DataFrame(new_artifacts),
                ],
                ignore_index=True,
            )

        # Persist every package so interrupted runs can resume.
        save_tables(results, inventory)

        print(
            f"[{index}/{len(remaining)}] "
            f"{name}=={version} | "
            f"{status} | artifacts={len(artifacts)}"
        )

        if index < len(remaining):
            time.sleep(args.delay)

    build_report(candidates, results, inventory)

    print()
    print("Saved:", RESULTS)
    print("Saved:", INVENTORY)
    print("Saved:", REPORT)
    print("[SUCCESS] Batch resolution run completed.")


if __name__ == "__main__":
    main()
