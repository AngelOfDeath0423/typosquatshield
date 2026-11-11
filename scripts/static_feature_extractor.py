
from pathlib import Path
import ast
import argparse
import json
import re

FEATURES = [
    "static_python_files",
    "static_network_imports",
    "static_process_imports",
    "static_file_imports",
    "static_network_calls",
    "static_process_calls",
    "static_file_calls",
    "static_decode_calls",
    "static_long_encoded_strings",
    "static_parse_errors",
]

NETWORK_MODULES = {
    "requests", "urllib", "http", "socket",
    "aiohttp", "httpx", "ftplib",
}

PROCESS_MODULES = {
    "subprocess", "multiprocessing",
}

FILE_MODULES = {
    "pathlib", "shutil", "tempfile",
}

NETWORK_CALLS = {
    "requests.get", "requests.post",
    "requests.request", "urllib.request.urlopen",
    "socket.socket", "socket.create_connection",
    "httpx.get", "httpx.post",
}

PROCESS_CALLS = {
    "os.system", "os.popen",
    "subprocess.run", "subprocess.call",
    "subprocess.Popen", "subprocess.check_output",
    "eval", "exec",
}

FILE_CALLS = {
    "open", "pathlib.Path.open",
    "os.remove", "os.unlink",
    "shutil.copy", "shutil.move",
}

DECODE_CALLS = {
    "base64.b64decode", "base64.b85decode",
    "bytes.fromhex", "codecs.decode",
    "zlib.decompress", "marshal.loads",
}

ENCODED_PATTERN = re.compile(
    r"[A-Za-z0-9+/=]{100,}"
)


def get_call_name(node):
    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        parent = get_call_name(node.value)

        if parent:
            return parent + "." + node.attr

        return node.attr

    return ""


def analyze_source(source):
    result = {
        name: 0 for name in FEATURES
    }

    result["static_python_files"] = 1

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        result["static_parse_errors"] = 1
        return result

    for node in ast.walk(tree):

        if isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name.split(".")[0]

                if module in NETWORK_MODULES:
                    result["static_network_imports"] += 1

                if module in PROCESS_MODULES:
                    result["static_process_imports"] += 1

                if module in FILE_MODULES:
                    result["static_file_imports"] += 1

        elif isinstance(node, ast.ImportFrom):
            module = (node.module or "").split(".")[0]

            if module in NETWORK_MODULES:
                result["static_network_imports"] += 1

            if module in PROCESS_MODULES:
                result["static_process_imports"] += 1

            if module in FILE_MODULES:
                result["static_file_imports"] += 1

        elif isinstance(node, ast.Call):
            call_name = get_call_name(node.func)

            if call_name in NETWORK_CALLS:
                result["static_network_calls"] += 1

            if call_name in PROCESS_CALLS:
                result["static_process_calls"] += 1

            if call_name in FILE_CALLS:
                result["static_file_calls"] += 1

            if call_name in DECODE_CALLS:
                result["static_decode_calls"] += 1

    result["static_long_encoded_strings"] = len(
        ENCODED_PATTERN.findall(source)
    )

    return result


def analyze_directory(directory):
    directory = Path(directory)

    if not directory.exists():
        raise FileNotFoundError(directory)

    totals = {
        name: 0 for name in FEATURES
    }

    for path in directory.rglob("*.py"):
        try:
            source = path.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            continue

        features = analyze_source(source)

        for name in FEATURES:
            totals[name] += features[name]

    return totals


def main():
    parser = argparse.ArgumentParser(
        description="TyposquatShield static feature extractor"
    )

    parser.add_argument(
        "directory",
        help="Directory containing Python source files",
    )

    args = parser.parse_args()

    result = analyze_directory(args.directory)

    print("=" * 60)
    print("TYPOSQUATSHIELD - LIGHTWEIGHT STATIC ANALYSIS")
    print("=" * 60)

    print(json.dumps(result, indent=2))

    print()
    print(
        "NOTE: These are behavioural indicators, "
        "not verified malware evidence."
    )


if __name__ == "__main__":
    main()
