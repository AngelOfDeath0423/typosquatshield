# Setup and dataset workflow

## Environment

The cleanup environment has Python 3.11.9, pandas 3.0.6, packaging 26.3, matplotlib 3.11.2, and seaborn 0.13.2. `requirements.txt` pins these direct dependencies; it is not a full transitive dependency lockfile. Git must be on `PATH` for source-advisory scripts.

From the repository root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The commands below use that virtual environment without requiring shell activation. `_paths.py` resolves all project inputs and outputs relative to the repository location.

## Inspect the existing snapshots

```powershell
.\.venv\Scripts\python.exe scripts/eda.py
.\.venv\Scripts\python.exe scripts/validate_data.py
.\.venv\Scripts\python.exe scripts/validate_openssf_labels.py
.\.venv\Scripts\python.exe scripts/analyze_openssf_review.py
```

These commands print diagnostics without writing datasets. Validation scripts are exploratory checks: they do not implement a test suite, enforce thresholds, or fail automatically when counts indicate a data-quality problem.

## Development sample

The supplied raw development CSV is the input; its original collection script is not included. To regenerate the cleaned sample and plots:

```powershell
.\.venv\Scripts\python.exe scripts/clean_pypi_dev.py
.\.venv\Scripts\python.exe scripts/validate_data.py
.\.venv\Scripts\python.exe scripts/eda.py
.\.venv\Scripts\python.exe scripts/eda_visualization.py
```

The cleaner overwrites the cleaned development CSV; plotting overwrites the saved PNG and displays a window. For a noninteractive plot, set `$env:MPLBACKEND = 'Agg'` before running the plotting script in that shell.

Known development limitations retained from the original implementation:

- Invalid dates are counted but are not removed or repaired by cleaning.
- The cleaner uses pandas timestamp inference, while the diagnostic script explicitly uses mixed-format parsing. Mixed timestamp formats may therefore parse differently. Regeneration can differ from the saved snapshot under a different library version.
- `validate_data.py` contains exploratory reference dates, including 2026-09-27, 2026-08-30, and 2026-09-13 at noon UTC. These are hypotheses used to investigate stored ages, not confirmed collection provenance.
- Cleaning does not recalculate `package_age_days` or redesign `total_uploads`, and does not generate a final training label.

Use the dataset specification to address these issues in the final pipeline. Raw snapshots remain separate from derived outputs.

## OpenSSF source checkout

The parent repository already tracks `malicious-packages` as a Git link at commit `3812671bee8aa766a40bcdf9ee322d7c6456cf29`. `.gitmodules` now supplies its upstream URL so a **fresh clone** can initialize it:

```powershell
git submodule update --init malicious-packages
git -C malicious-packages rev-parse HEAD
```

An alternative for a fresh checkout is `git clone --recurse-submodules <your-repository-url>`.

The existing local checkout has substantial pre-existing staged deletions and untracked files, with sparse checkout enabled. Cleanup preserves its working tree, index, configuration, and `HEAD`. Do not reset or reinitialize that existing checkout to follow fresh-clone instructions. The parent may continue to show it as dirty.

Extraction and inspection use `git ls-tree` and `git show HEAD:<path>`, so they read committed objects despite local working-tree changes. They do not need to restore advisory files on disk. Confirm `HEAD` before extracting: reading a different commit changes the source snapshot. The recorded commit is the checkout observed during cleanup; the original CSVs do not record which commit generated them.

## OpenSSF extraction and screening

The existing CSVs can be inspected without initializing the source checkout. Regeneration requires it and can take time because extraction reads each advisory through Git:

```powershell
.\.venv\Scripts\python.exe scripts/extract_openssf_pypi.py
.\.venv\Scripts\python.exe scripts/validate_openssf_labels.py
.\.venv\Scripts\python.exe scripts/review_openssf_labels.py
.\.venv\Scripts\python.exe scripts/analyze_openssf_review.py
```

Extraction overwrites the raw labels CSV. Screening overwrites the reviewed labels CSV. Preserve an intentional snapshot before regenerating, and inspect the extraction error count. The extractor continues after individual report failures, so a successful process exit alone is not sufficient evidence of complete extraction.

Optional source investigations:

```powershell
.\.venv\Scripts\python.exe scripts/inspect_openssf_versions.py
.\.venv\Scripts\python.exe scripts/check_openssf_withdrawn.py
.\.venv\Scripts\python.exe scripts/compare_openssf_withdrawn.py
.\.venv\Scripts\python.exe scripts/check_openssf_disputed_versions.py
```

Active advisories come from `osv/malicious/pypi`; withdrawn-report investigations use `osv/withdrawn`. A match against a withdrawn package name can relate to a different version or report and needs investigation. These scripts print findings without updating label decisions.

Only metadata and advisory records are processed here. The current scripts do not install or execute the packages named in the datasets.
