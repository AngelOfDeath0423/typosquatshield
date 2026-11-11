
from pathlib import Path
import argparse
import json
import tarfile
import time
import zipfile

from static_feature_extractor import analyze_source, FEATURES

MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 20 * 1024 * 1024
MAX_PYTHON_FILES = 1000

MAX_MEMBERS = 5000
MAX_TOTAL_DECLARED_BYTES = 200 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_SCAN_SECONDS = 30


class ScanLimitError(Exception):
    pass


def empty_features():
    return {feature: 0 for feature in FEATURES}


def add_features(totals, features):
    for feature in FEATURES:
        totals[feature] += features[feature]


def scan_archive(path):
    path = Path(path)

    result = {
        "archive_name": path.name,
        "scan_status": "failed",
        "processed_python_files": 0,
        "skipped_python_files": 0,
        "processed_source_bytes": 0,
        "features": empty_features(),
        "errors": [],
        "limitations": [
            "Static analysis only; no package code is executed.",
            "Only Python source files are inspected.",
            "Native binaries and non-Python files are not analyzed.",
            "Indicators are not proof of maliciousness.",
            "This scanner is not a security sandbox.",
        ],
    }

    started = time.monotonic()
    member_count = 0
    total_declared = 0

    def check_time():
        if time.monotonic() - started > MAX_SCAN_SECONDS:
            raise ScanLimitError(
                "Cooperative scan time limit exceeded."
            )

    def register_member(size):
        nonlocal member_count, total_declared

        check_time()
        member_count += 1

        if member_count > MAX_MEMBERS:
            raise ScanLimitError(
                "Archive member count limit exceeded."
            )

        if size < 0:
            raise ScanLimitError("Negative member size.")

        total_declared += size

        if total_declared > MAX_TOTAL_DECLARED_BYTES:
            raise ScanLimitError(
                "Total declared archive size limit exceeded."
            )

    def process_source(name, stream, declared_size):
        if not name.lower().endswith(".py"):
            return

        if declared_size > MAX_SOURCE_BYTES:
            result["skipped_python_files"] += 1
            result["errors"].append(
                f"Source file exceeds limit: {name}"
            )
            return

        if (
            result["processed_python_files"]
            >= MAX_PYTHON_FILES
        ):
            raise ScanLimitError(
                "Python file count limit exceeded."
            )

        if (
            result["processed_source_bytes"] + declared_size
            > MAX_TOTAL_SOURCE_BYTES
        ):
            raise ScanLimitError(
                "Total Python source limit exceeded."
            )

        check_time()

        try:
            data = stream.read(MAX_SOURCE_BYTES + 1)

            if len(data) > MAX_SOURCE_BYTES:
                raise ValueError(
                    "Source exceeded its read limit."
                )

            if len(data) != declared_size:
                raise ValueError(
                    "Source size does not match archive metadata."
                )

            source = data.decode(
                "utf-8",
                errors="replace",
            )

            features = analyze_source(source)

            add_features(result["features"], features)

            result["processed_python_files"] += 1
            result["processed_source_bytes"] += len(data)

            if features["static_parse_errors"]:
                result["errors"].append(
                    f"Python parsing failed: {name}"
                )

        except (OSError, EOFError, ValueError, RuntimeError) as exc:
            result["skipped_python_files"] += 1
            result["errors"].append(
                f"Could not inspect {name}: {exc}"
            )

        check_time()

    try:
        if not path.is_file():
            raise FileNotFoundError(path)

        if path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ScanLimitError(
                "Compressed archive size limit exceeded."
            )

        if path.name.lower().endswith(".whl"):

            with zipfile.ZipFile(path) as archive:

                for item in archive.infolist():
                    register_member(item.file_size)

                    if item.is_dir():
                        continue

                    # Reject encrypted entries rather than
                    # attempting to read them.
                    if item.flag_bits & 0x1:
                        raise ScanLimitError(
                            "Encrypted ZIP member detected."
                        )

                    if item.file_size:
                        if item.compress_size == 0:
                            raise ScanLimitError(
                                "Invalid compressed member size."
                            )

                        ratio = (
                            item.file_size / item.compress_size
                        )

                        if ratio > MAX_COMPRESSION_RATIO:
                            raise ScanLimitError(
                                "ZIP compression ratio limit exceeded."
                            )

                    if not item.filename.lower().endswith(".py"):
                        continue

                    if item.file_size > MAX_SOURCE_BYTES:
                        result["skipped_python_files"] += 1
                        result["errors"].append(
                            f"Source file exceeds limit: "
                            f"{item.filename}"
                        )
                        continue

                    with archive.open(item) as stream:
                        process_source(
                            item.filename,
                            stream,
                            item.file_size,
                        )

        elif path.name.lower().endswith(".tar.gz"):

            with tarfile.open(path, mode="r:gz") as archive:

                for item in archive:
                    register_member(item.size)

                    # Never extract archive members to disk.
                    # Ignore links, devices, directories,
                    # and other non-regular members.
                    if not item.isfile():
                        continue

                    if not item.name.lower().endswith(".py"):
                        continue

                    if item.size > MAX_SOURCE_BYTES:
                        result["skipped_python_files"] += 1
                        result["errors"].append(
                            f"Source file exceeds limit: "
                            f"{item.name}"
                        )
                        continue

                    stream = archive.extractfile(item)

                    if stream is None:
                        result["skipped_python_files"] += 1
                        result["errors"].append(
                            f"Could not open: {item.name}"
                        )
                        continue

                    with stream:
                        process_source(
                            item.name,
                            stream,
                            item.size,
                        )

        else:
            raise ValueError(
                "Unsupported archive format. "
                "Expected .whl or .tar.gz."
            )

        if result["errors"]:
            result["scan_status"] = "partial"
        else:
            result["scan_status"] = "complete"

    except (
        FileNotFoundError,
        ScanLimitError,
        zipfile.BadZipFile,
        tarfile.TarError,
        EOFError,
        OSError,
        ValueError,
        RuntimeError,
    ) as exc:
        result["scan_status"] = "failed"
        result["errors"].append(
            f"{type(exc).__name__}: {exc}"
        )

    result["elapsed_seconds"] = round(
        time.monotonic() - started,
        4,
    )

    return result


def main():
    parser = argparse.ArgumentParser(
        description="TyposquatShield static archive scanner"
    )

    parser.add_argument(
        "archive",
        help="Path to a wheel or tar.gz archive",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("TYPOSQUATSHIELD - STATIC ARCHIVE SCANNER")
    print("=" * 60)

    result = scan_archive(args.archive)

    print(json.dumps(result, indent=2))

    if result["scan_status"] == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
