"""Shared repository paths for the standalone data-preparation scripts."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEV_DATA_DIR = ROOT / "data" / "dev"
LABELS_DATA_DIR = ROOT / "data" / "labels"
OPENSSF_REPO = ROOT / "malicious-packages"
FIGURES_DIR = ROOT / "reports" / "figures"
