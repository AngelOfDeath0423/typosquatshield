
"""
TyposquatShield - Static Archive Scanner Tests

Tests:
1. Valid wheel
2. Valid TAR.GZ
3. Malformed wheel
4. Oversized Python file
5. Archive containing no Python files

Run:
    python .\\scripts\\test_static_archive_scanner.py
"""

from pathlib import Path
import sys
import tarfile
import tempfile
import zipfile
import io

from static_archive_scanner import (
    scan_archive,
    MAX_SOURCE_BYTES,
)


TOTAL_TESTS = 0
PASSED_TESTS = 0


def check(condition, message):
    if condition:
        print(f"[PASS] {message}")
    else:
        print(f"[FAIL] {message}")
        raise AssertionError(message)


def run_test(name, function, folder):
    global TOTAL_TESTS, PASSED_TESTS

    TOTAL_TESTS += 1

    print()
    print(f"Running: {name}")

    try:
        function(folder)
        PASSED_TESTS += 1

    except Exception as exc:
        print(f"[FAIL] {name}: {exc}")


def sample_source():
    return """
import requests
import subprocess
import os
import base64

def example():
    requests.get("https://example.com")
    subprocess.run(["echo", "hello"])
    open("example.txt", "w")
    base64.b64decode("SGVsbG8=")
"""


def test_valid_wheel(folder):
    archive_path = (
        folder / "test_package-0.1-py3-none-any.whl"
    )

    with zipfile.ZipFile(
        archive_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr(
            "test_package/sample.py",
            sample_source(),
        )

    result = scan_archive(archive_path)

    check(
        result["scan_status"] == "complete",
        "Valid wheel: scan completed",
    )

    check(
        result["processed_python_files"] == 1,
        "Valid wheel: one Python file processed",
    )

    check(
        result["features"]["static_network_calls"] >= 1,
        "Valid wheel: network call detected",
    )

    check(
        result["features"]["static_process_calls"] >= 1,
        "Valid wheel: process call detected",
    )

    check(
        result["features"]["static_parse_errors"] == 0,
        "Valid wheel: no parse errors",
    )


def test_valid_tar(folder):
    archive_path = folder / "test_package-0.1.tar.gz"

    source = sample_source().encode("utf-8")

    with tarfile.open(
        archive_path,
        "w:gz",
    ) as archive:

        info = tarfile.TarInfo(
            name="test_package/sample.py"
        )

        info.size = len(source)

        archive.addfile(
            info,
            io.BytesIO(source),
        )

    result = scan_archive(archive_path)

    check(
        result["scan_status"] == "complete",
        "Valid TAR.GZ: scan completed",
    )

    check(
        result["processed_python_files"] == 1,
        "Valid TAR.GZ: one Python file processed",
    )

    check(
        result["features"]["static_decode_calls"] >= 1,
        "Valid TAR.GZ: decode call detected",
    )


def test_malformed_wheel(folder):
    archive_path = (
        folder / "broken-0.1-py3-none-any.whl"
    )

    archive_path.write_bytes(
        b"This is not a valid ZIP archive."
    )

    result = scan_archive(archive_path)

    check(
        result["scan_status"] == "failed",
        "Malformed wheel: invalid archive rejected",
    )

    check(
        len(result["errors"]) > 0,
        "Malformed wheel: error details recorded",
    )

    check(
        result["processed_python_files"] == 0,
        "Malformed wheel: no Python files processed",
    )


def test_oversized_python_file(folder):
    archive_path = (
        folder / "oversized-0.1-py3-none-any.whl"
    )

    oversized_source = (
        b"#" + b"x" * MAX_SOURCE_BYTES
    )

    with zipfile.ZipFile(
        archive_path,
        "w",
        compression=zipfile.ZIP_STORED,
    ) as archive:

        archive.writestr(
            "oversized/large.py",
            oversized_source,
        )

    result = scan_archive(archive_path)

    check(
        result["scan_status"] == "partial",
        "Oversized file: partial scan recorded",
    )

    check(
        result["processed_python_files"] == 0,
        "Oversized file: not processed",
    )

    check(
        result["skipped_python_files"] == 1,
        "Oversized file: skip recorded",
    )


def test_non_python_content(folder):
    archive_path = (
        folder / "non_python-0.1-py3-none-any.whl"
    )

    with zipfile.ZipFile(
        archive_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:

        archive.writestr(
            "non_python/readme.txt",
            "This package has no Python source files.",
        )

        archive.writestr(
            "non_python/data.json",
            '{"example": true}',
        )

    result = scan_archive(archive_path)

    check(
        result["scan_status"] == "complete",
        "Non-Python archive: scan completed",
    )

    check(
        result["processed_python_files"] == 0,
        "Non-Python archive: no Python files processed",
    )

    check(
        result["features"]["static_python_files"] == 0,
        "Non-Python archive: no Python source counted",
    )


def main():
    global TOTAL_TESTS, PASSED_TESTS

    print("=" * 60)
    print("TYPOSQUATSHIELD - STATIC ARCHIVE SCANNER TESTS")
    print("=" * 60)

    tests = [
        ("test_valid_wheel", test_valid_wheel),
        ("test_valid_tar", test_valid_tar),
        ("test_malformed_wheel", test_malformed_wheel),
        (
            "test_oversized_python_file",
            test_oversized_python_file,
        ),
        (
            "test_non_python_content",
            test_non_python_content,
        ),
    ]

    with tempfile.TemporaryDirectory() as temp_dir:
        folder = Path(temp_dir)

        for name, function in tests:
            run_test(
                name,
                function,
                folder,
            )

    print()
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    print(
        f"Passed: {PASSED_TESTS}/{TOTAL_TESTS}"
    )

    if PASSED_TESTS == TOTAL_TESTS:
        print(
            "[SUCCESS] All archive scanner tests passed."
        )
        return 0

    print(
        "[FAILURE] Some archive scanner tests failed."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
