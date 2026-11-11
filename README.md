# TyposquatShield

Final year cybersecurity project exploring explainable, pre-installation risk assessment for Python Package Index (PyPI) packages.

The planned prototype combines package-name similarity, metadata, reputation, dependency information, and lightweight static analysis to provide **Low Risk**, **Caution**, or **High Risk** advice. These categories support a developer's decision; they are not guarantees that a package is safe or malicious.

## Current implementation

This repository currently contains **dataset preparation and investigation scripts**: a 5,000-package development sample, cleaning and exploratory analysis, and extraction and screening of OpenSSF PyPI advisory labels. The final experimental dataset, feature pipeline, trained classifier, CLI checker, FastAPI service, database, and Streamlit dashboard are planned work.

## Repository layout

```text
data/
  dev/                  Raw and cleaned 5,000-package development snapshots
  labels/               Raw and automatically screened OpenSSF label snapshots
docs/
  reports/              Local investigation report (ignored by Git)
  specifications/       Existing dataset design specification
  project-context.md    Scope, implementation status, and open research decisions
  workflow.md           Setup, execution order, and known limitations
  repository-cleanup.md File moves and Git review notes
malicious-packages/     External OpenSSF Git checkout, pinned by the parent repo
reports/figures/        Saved exploratory-analysis figure
scripts/               Standalone Python data preparation and inspection scripts
requirements.txt       Direct dependencies pinned to the cleanup environment
```

See [dataset documentation](data/README.md), the [script catalog](scripts/README.md), and the [workflow](docs/workflow.md).

## Quick start

Use Python 3.11 and Git. Run these commands from the repository root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe scripts/eda.py
.\.venv\Scripts\python.exe scripts/validate_openssf_labels.py
```

These two scripts inspect the committed CSV snapshots without changing them. The OpenSSF checkout is only required for scripts that read the source advisories; see [source setup](docs/workflow.md#openssf-source-checkout).

Cleaning, extraction, screening, and plotting commands overwrite their corresponding derived outputs. Read the workflow before regenerating a snapshot.

## Research context

The investigation report follows CRISP-DM with iterative development. The development sample is for rehearsing preprocessing, not the final labelled experiment. The dataset specification targets approximately 10,000 reliably labelled records, subject to source quality and availability.

OpenSSF reports are evidence for label investigation. `candidate_malicious` is an automatic screening result, and `needs_review` requires further investigation. Neither status is a final model target. The development sample has no verified class labels and must not be assumed benign.

The original [dataset design specification](docs/specifications/TyposquatShield_Real_Dataset_Design_Specification.docx) remains available. The investigation report is retained locally under `docs/reports/` and excluded from Git.

## Sources

The external advisory checkout identifies its origin as the [OpenSSF malicious-packages repository](https://github.com/ossf/malicious-packages). Preserve advisory IDs, paths, references, and source attribution when using extracted records. The checkout includes its upstream license; this cleanup does not assign a license to the student's project or datasets.
