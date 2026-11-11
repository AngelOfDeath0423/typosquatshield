
import json
import time
import csv
import subprocess
import urllib.request
import urllib.error

from pathlib import Path
from datetime import datetime, timezone
from packaging.utils import canonicalize_name

import pandas as pd


# ============================================================
# TYPOSQUATSHIELD - LEGITIMATE PYPI PILOT COLLECTION
# ============================================================

# 1. PROJECT PATHS

BASE = Path(__file__).resolve().parent.parent

LABEL_DIR = BASE / "data" / "labels"
OUTPUT_DIR = BASE / "data" / "legitimate"
REPO = BASE / "malicious-packages"

MANIFEST = LABEL_DIR / "openssf_pypi_label_manifest.csv"

OUTPUT = OUTPUT_DIR / "legitimate_pypi_pilot_100.csv"
LOG = OUTPUT_DIR / "legitimate_pypi_pilot_log.csv"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

TARGET = 100

print("=" * 60)
print("TYPOSQUATSHIELD - LEGITIMATE PYPI PILOT")
print("=" * 60)

print("Project folder:", BASE)


# ============================================================
# 2. CURATED PACKAGE CANDIDATES
# ============================================================

# These are established-project candidates.
# They are NOT verified benign ground truth.

CANDIDATES = """
requests urllib3 certifi idna charset-normalizer
httpx httpcore aiohttp yarl multidict frozenlist
flask django fastapi starlette uvicorn gunicorn werkzeug
jinja2 markupsafe itsdangerous click typer rich
pydantic pydantic-core attrs typing-extensions
numpy pandas scipy scikit-learn matplotlib seaborn
plotly bokeh statsmodels sympy pillow imageio
opencv-python scikit-image networkx numba llvmlite
xarray dask distributed pyarrow polars openpyxl
xlsxwriter python-dateutil pytz tzdata babel
beautifulsoup4 soupsieve lxml html5lib bleach
scrapy selenium playwright webdriver-manager
sqlalchemy alembic psycopg2-binary pymysql redis
pymongo motor asyncpg aiosqlite peewee
pytest pluggy iniconfig coverage pytest-cov
hypothesis tox nox black ruff flake8 mypy
isort pre-commit virtualenv pip setuptools wheel
build twine packaging platformdirs filelock
tomli toml pyyaml ruamel.yaml python-dotenv
cryptography pyopenssl cffi pycparser bcrypt
argon2-cffi paramiko fabric invoke
boto3 botocore s3transfer google-cloud-storage
google-auth google-api-core azure-core azure-identity
celery kombu billiard flower apscheduler
tqdm joblib cloudpickle dill tenacity
loguru structlog sentry-sdk psutil
jupyterlab notebook ipykernel ipython traitlets
nbformat nbconvert pygments jedi prompt-toolkit
sphinx docutils mkdocs mkdocs-material
markdown markdown-it-py mistune
transformers tokenizers datasets accelerate
torch torchvision torchaudio tensorflow keras
lightgbm xgboost catboost shap lime
streamlit gradio dash panel
""".split()

candidate_names = []
seen = set()

for name in CANDIDATES:
    normalized = canonicalize_name(name)

    if normalized not in seen:
        candidate_names.append(name)
        seen.add(normalized)

print("Candidate pool:", len(candidate_names))


# ============================================================
# 3. LOAD OPENSSF ACTIVE PACKAGE NAMES
# ============================================================

if not MANIFEST.is_file():
    raise FileNotFoundError(
        f"OpenSSF manifest not found:\n{MANIFEST}"
    )

manifest = pd.read_csv(
    MANIFEST,
    dtype=str,
    keep_default_na=False,
    encoding="utf-8-sig"
)

if "normalized_name" not in manifest.columns:
    raise ValueError(
        "Manifest is missing normalized_name column."
    )

active_names = set(
    manifest["normalized_name"]
    .str.strip()
    .map(canonicalize_name)
)

print("Active OpenSSF names:", len(active_names))


# ============================================================
# 4. FAST WITHDRAWN-PACKAGE CHECK
# ============================================================

print("\nChecking withdrawn PyPI packages...")

if not REPO.is_dir():
    raise FileNotFoundError(
        f"OpenSSF repository not found:\n{REPO}"
    )

def git_command(*args):
    result = subprocess.run(
        ["git", "-C", str(REPO), *args],
        capture_output=True,
        check=True,
        timeout=60
    )
    return result.stdout


# Only inspect the withdrawn PyPI directory.
# Do not run Git separately for every report.

withdrawn_paths = git_command(
    "ls-tree",
    "-r",
    "--name-only",
    "HEAD",
    "--",
    "osv/withdrawn/pypi"
).decode("utf-8").splitlines()

withdrawn_names = set()

for path in withdrawn_paths:
    if not path.endswith(".json"):
        continue

    parts = path.replace("\\", "/").split("/")

    # Expected structure:
    # osv/withdrawn/pypi/<package>/<report>.json

    if len(parts) >= 5:
        package_name = parts[3]

        withdrawn_names.add(
            canonicalize_name(package_name)
        )

excluded_names = active_names | withdrawn_names

print("Withdrawn PyPI names:", len(withdrawn_names))
print("Total exclusion names:", len(excluded_names))


# ============================================================
# 5. PYPI API REQUEST
# ============================================================

def fetch_pypi(name):

    url = f"https://pypi.org/pypi/{name}/json"

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": (
                "TyposquatShield-FYP/0.1 "
                "(academic metadata collection)"
            ),
            "Accept": "application/json"
        }
    )

    with urllib.request.urlopen(
        request,
        timeout=20
    ) as response:

        return json.load(response)


# ============================================================
# 6. TIMESTAMP PARSING
# ============================================================

def parse_upload_time(value):

    if not value:
        return ""

    try:
        dt = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(
            timezone.utc
        ).isoformat()

    except (ValueError, TypeError):
        return ""


# ============================================================
# 7. EXTRACT PYPI METADATA
# ============================================================

def extract_metadata(data, requested_name):

    info = data.get("info") or {}
    releases = data.get("releases") or {}
    urls = data.get("urls") or []

    actual_name = info.get("name") or requested_name

    upload_times = []
    distribution_count = 0

    for files in releases.values():

        for item in files or []:

            distribution_count += 1

            timestamp = parse_upload_time(
                item.get("upload_time_iso_8601")
                or item.get("upload_time")
            )

            if timestamp:
                upload_times.append(timestamp)

    latest_version = info.get("version") or ""
    requires_dist = info.get("requires_dist") or []

    return {

        "package_name": actual_name,

        "normalized_name": canonicalize_name(
            actual_name
        ),

        "latest_version": latest_version,

        "summary": info.get("summary") or "",

        "description": info.get("description") or "",

        "author": info.get("author") or "",

        "author_email": info.get("author_email") or "",

        "maintainer": info.get("maintainer") or "",

        "maintainer_email": (
            info.get("maintainer_email") or ""
        ),

        "license": info.get("license") or "",

        "keywords": info.get("keywords") or "",

        "home_page": info.get("home_page") or "",

        "project_urls": json.dumps(
            info.get("project_urls") or {}
        ),

        "requires_python": (
            info.get("requires_python") or ""
        ),

        "requires_dist": json.dumps(
            requires_dist
        ),

        "first_upload_time": (
            min(upload_times) if upload_times else ""
        ),

        "latest_upload_time": (
            max(upload_times) if upload_times else ""
        ),

        "version_count": len(releases),

        "distribution_file_count": distribution_count,

        "latest_release_file_count": len(urls),

        "collection_timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "label_source": (
            "curated_established_project_pilot"
        ),

        "label_status": "presumed_legitimate",

        "label_verified": False,

        "selection_reason": (
            "Curated established-project candidate; "
            "requires provenance and label review"
        ),

        "pypi_url": (
            f"https://pypi.org/project/{actual_name}/"
        )
    }


# ============================================================
# 8. COLLECT 100 PACKAGE RECORDS
# ============================================================

records = []
logs = []
collected_names = set()

print("\nStarting PyPI metadata collection...\n")

for name in candidate_names:

    if len(records) >= TARGET:
        break

    normalized = canonicalize_name(name)

    if normalized in excluded_names:

        print(f"SKIP OpenSSF overlap: {name}")

        logs.append({
            "name": name,
            "status": "excluded_openssf",
            "reason": "Active or withdrawn OpenSSF overlap"
        })

        continue

    try:

        data = fetch_pypi(name)

        record = extract_metadata(
            data,
            name
        )

        actual_normalized = record["normalized_name"]

        if actual_normalized in excluded_names:

            raise ValueError(
                "Resolved package name overlaps OpenSSF"
            )

        if actual_normalized in collected_names:
            continue

        records.append(record)

        collected_names.add(
            actual_normalized
        )

        logs.append({
            "name": name,
            "status": "collected",
            "reason": ""
        })

        print(
            f"[{len(records)}/{TARGET}] "
            f"Collected: {record['package_name']}",
            flush=True
        )

    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
        ValueError,
        json.JSONDecodeError
    ) as error:

        print(f"SKIP {name}: {error}", flush=True)

        logs.append({
            "name": name,
            "status": "failed_or_excluded",
            "reason": str(error)
        })

    time.sleep(0.25)


# ============================================================
# 9. SAVE DATASET AND COLLECTION LOG
# ============================================================

df = pd.DataFrame(records)

if not df.empty:

    df.to_csv(
        OUTPUT,
        index=False,
        encoding="utf-8-sig"
    )

pd.DataFrame(logs).to_csv(
    LOG,
    index=False,
    encoding="utf-8-sig"
)


# ============================================================
# 10. VALIDATION
# ============================================================

print("\n" + "=" * 60)
print("LEGITIMATE PYPI PILOT - COLLECTION SUMMARY")
print("=" * 60)

print("Target packages:", TARGET)

print("Successfully collected:", len(records))

if not df.empty:

    print(
        "Unique normalized names:",
        df["normalized_name"].nunique()
    )

    overlap = (
        set(df["normalized_name"]) & excluded_names
    )

    print("OpenSSF name overlaps:", len(overlap))

    print("\nMissing important metadata:")

    for column in [
        "summary",
        "first_upload_time",
        "latest_upload_time"
    ]:

        missing = (
            df[column].astype(str).eq("").sum()
        )

        print(f"{column}: {missing}")

print("\nSaved dataset:")
print(OUTPUT)

print("\nSaved collection log:")
print(LOG)

print("\nPilot collection completed.")
