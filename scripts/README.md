# Script catalog

Run scripts directly with `python scripts/<filename>.py` from the repository root. Paths are resolved by `_paths.py` relative to the repository, so an absolute script path also works from another working directory. These are standalone scripts; importing them runs their analysis. No command-line options are currently implemented.

## Development sample

| Script | Purpose | Input | Output |
| --- | --- | --- | --- |
| `clean_pypi_dev.py` | Canonicalize names, remove duplicate normalized names, trim text, parse dates, and recalculate four metadata flags | `data/dev/pypi_raw_dev_5000.csv` | Overwrites `data/dev/pypi_cleaned_dev_5000.csv`; prints invalid-date count |
| `validate_data.py` | Inspect numeric extremes, negatives, dates, and possible package-age reference dates | Cleaned development CSV | Console diagnostics |
| `eda.py` | Show shape, column types, missingness, duplicates, numeric summaries, and package age | Cleaned development CSV | Console summary |
| `eda_visualization.py` | Plot package age, version count, size, and metadata completeness | Cleaned development CSV | Overwrites `reports/figures/eda_visualizations.png` and opens a plot window |

`clean_pypi_dev.py` was previously named `test clean on 5000.py`; it is a preprocessing script, not an automated test.

## OpenSSF labels

CSV paths below are relative to `data/labels/`. Source-dependent scripts read Git objects at `malicious-packages`' current `HEAD`, rather than advisory files from its working tree.

| Script | Purpose | Inputs | Output |
| --- | --- | --- | --- |
| `extract_openssf_pypi.py` | Expand PyPI affected entries and explicit versions from active advisories | Source Git checkout, `osv/malicious/pypi` | Overwrites `openssf_pypi_labels_raw.csv` |
| `validate_openssf_labels.py` | Count records, names, versions, reports, missing fields, duplicates, withdrawal fields, and statuses | Raw labels CSV | Console diagnostics |
| `review_openssf_labels.py` | Apply withdrawal checks and text review signals | Raw labels CSV | Overwrites `openssf_pypi_labels_reviewed.csv` |
| `analyze_openssf_review.py` | Count review signals and display examples | Reviewed labels CSV | Console summary |
| `inspect_openssf_versions.py` | Investigate blank versions and presence of affected ranges | Raw labels CSV and source Git checkout | Console diagnostics |
| `check_openssf_withdrawn.py` | Count withdrawn reports and identify PyPI examples | Source Git checkout, `osv/withdrawn` | Console diagnostics |
| `compare_openssf_withdrawn.py` | Compare reviewed records with withdrawn IDs and normalized names | Reviewed labels CSV and source Git checkout | Console diagnostics |
| `check_openssf_disputed_versions.py` | Search affected-entry `database_specific` keys containing `false` or `positive` | Source Git checkout, active PyPI advisories | Console diagnostics |

The disputed-version check is a heuristic key search. It does not adjudicate individual versions or prove that all disputed records have been found. The withdrawal comparison reports matches without changing the reviewed dataset.

The Git inspection scripts can be slow: several start a separate `git show` process for each report. Extraction reports per-report failures and continues, so review the error count before using regenerated data.
