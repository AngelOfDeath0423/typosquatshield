# Repository cleanup notes

## File organization

| Previous location | Current location |
| --- | --- |
| Root Python scripts | `scripts/`, retaining names except the cleaner |
| `test clean on 5000.py` | `scripts/clean_pypi_dev.py` |
| `pypi_raw_dev_5000.csv` | `data/dev/pypi_raw_dev_5000.csv` |
| `pypi_cleaned_dev_5000.csv` | `data/dev/pypi_cleaned_dev_5000.csv` |
| `openssf_pypi_labels_raw.csv` | `data/labels/openssf_pypi_labels_raw.csv` |
| `openssf_pypi_labels_reviewed.csv` | `data/labels/openssf_pypi_labels_reviewed.csv` |
| `eda_visualizations.png` | `reports/figures/eda_visualizations.png` |
| `TyposquatShield_Real_Dataset_Design_Specification.docx` | `docs/specifications/TyposquatShield_Real_Dataset_Design_Specification.docx` |
| Investigation report at repository root | `docs/reports/`, kept locally and ignored by Git |
| `malicious-packages/` | Same location, preserving the existing nested checkout |

Script changes resolve inputs and outputs through `scripts/_paths.py`. Data-cleaning and screening rules remain as originally implemented. CSVs, Word documents, and the figure were moved with SHA-256 checks before and after each move.

`.gitattributes` preserves exact CSV bytes across Git checkouts and marks Word documents and PNGs as binary. `.gitignore` excludes local environments, Python caches, temporary files, and the private investigation report. `requirements.txt` records the direct dependency versions available during cleanup.

## Verification performed

- Verified the four dataset hashes, byte sizes, column lists, and CSV record counts against `data/manifest.json`.
- Confirmed the moved dataset specification and saved PNG match their initial-commit bytes, and the local investigation report matches its pre-move checksum.
- Ran development EDA, development diagnostics, raw-label validation, and review-signal analysis against the preserved snapshots.
- Compared all 12 relocated scripts with their initial-commit versions in temporary folders. Console output and written outputs matched; source-dependent checks used three sampled advisories per directory, and missing-version inspection used three blank-version records.
- Verified headless plotting, Python syntax, local Markdown link targets, the submodule URL/revision mapping, and the investigation report's ignore rule.
- Confirmed cleaner regeneration in the available environment reproduces the saved cleaned snapshot byte for byte.

Verification did not rerun extraction over the full advisory collection, change label decisions, install a fresh environment, or initialize a fresh network clone. The checks validate reorganization and preserved behavior, not final research quality or application readiness.

## Git and external source

The initial commit already records `malicious-packages` as a Git link, but had no `.gitmodules` URL mapping. The new mapping makes the existing pinned dependency discoverable in fresh clones. The local nested checkout has pre-existing staged deletions and untracked files, with sparse checkout enabled; its index and working tree are preserved. Its dirty state is independent of the parent cleanup.

No commit, push, history rewrite, source checkout reset, or upstream update is part of this cleanup. Moving files does not remove their earlier versions from Git history. The investigation report was untracked at the start and is now ignored as requested.

## Review before the second commit

From the repository root:

```powershell
git status --short --ignore-submodules=dirty
git diff --stat --ignore-submodules=dirty
git diff -- .gitignore .gitmodules README.md requirements.txt
```

New files are untracked until you stage them, so the unstaged diff alone does not show the complete cleanup. After reviewing the new documentation and scripts, stage the parent changes and inspect rename detection:

```powershell
git add -A
git diff --cached --stat --find-renames --ignore-submodules=dirty
git diff --cached --name-status --find-renames
git diff --cached --check
git ls-files docs/reports
```

Only `docs/reports/README.md` should be listed by the last command. Parent-level `git add -A` does not stage files inside the nested repository. Do not run staging/reset commands inside `malicious-packages` as part of reviewing this cleanup. If its `HEAD` has changed independently, review any parent Git-link change before committing.

Commit and push when your review is complete. The documentation deliberately distinguishes existing scripts and research snapshots from future prototype work.
