# Dataset inventory

These CSV files are retained research snapshots. Counts below were measured during cleanup and refer to CSV records, not physical lines; advisory text can contain embedded newlines. All four files retain their original bytes.

| Path | Records | Unique package names | Role |
| --- | ---: | ---: | --- |
| `dev/pypi_raw_dev_5000.csv` | 5,000 | 5,000 | Supplied development input |
| `dev/pypi_cleaned_dev_5000.csv` | 5,000 | 5,000 | Saved cleaned development output |
| `labels/openssf_pypi_labels_raw.csv` | 17,121 | 11,798 | Extracted advisory records, initially all `needs_review` |
| `labels/openssf_pypi_labels_reviewed.csv` | 17,121 | 11,798 | Automatic screening output |

Development uniqueness uses `normalized_name`; advisory uniqueness uses the exact `package_name`. These are not equivalent deduplication rules. See [manifest.json](manifest.json) for SHA-256 digests, sizes, columns, and measured snapshot statistics.

`.gitattributes` disables Git newline conversion for CSV files so their byte-level checksums remain stable across operating systems.

## Development CSV schema

Both development files have the same 24 columns:

| Group | Columns | Notes |
| --- | --- | --- |
| Identity | `name`, `normalized_name`, `latest_version` | Cleaner uses `packaging.utils.canonicalize_name` and deduplicates normalized names |
| Declared metadata | `summary`, `author`, `author_email`, `maintainer`, `maintainer_email`, `license`, `keywords`, `home_page`, `requires_python` | Text absence is preserved rather than filled with invented metadata |
| History | `first_upload_time`, `latest_upload_time`, `package_age_days`, `total_uploads`, `version_count` | Stored age reference and `total_uploads` meaning require provenance confirmation |
| Artifact | `filename`, `size`, `packagetype` | A single artifact representation; the future specification proposes a separate files table |
| Completeness | `has_summary`, `has_author`, `has_maintainer`, `has_homepage` | Cleaner recalculates four binary indicators |

The original collector, collection command, and confirmed collection timestamp are absent. These samples have no verified class labels. The 5,000-package sample is not the final experimental dataset and does not establish a benign class.

## Advisory CSV schema

Both advisory CSVs have the same 15 columns:

| Column | Meaning |
| --- | --- |
| `package_name` | Package name from the affected PyPI entry |
| `package_version` | One explicit affected version; blank when none is listed |
| `affected_ranges` | JSON-encoded affected ranges, preserved without expanding them |
| `ecosystem` | `PyPI` |
| `report_id` | Advisory identifier |
| `published`, `modified`, `withdrawn` | Source advisory timestamps or blank values |
| `summary`, `details` | Source advisory text |
| `references` | JSON-encoded reference URL list |
| `origin_sources` | JSON-encoded upstream origin-source names |
| `report_path` | Advisory path within the source Git repository |
| `label_source` | `OpenSSF` |
| `label_status` | Extraction/screening workflow state |

A row represents an affected entry and explicit version within an advisory. Different reports may reference the same package/version. A blank version with ranges is not an unknown version to fill arbitrarily, and ranges are not expanded by the extractor.

The saved raw snapshot contains 6,372 records with blank explicit versions, 11,798 distinct report IDs, and no duplicate package/version/report combinations. Inspect the preserved ranges and source advisories before deciding how these records enter the experimental dataset.

## Screening semantics

`review_openssf_labels.py` applies these rules in order:

1. A populated `withdrawn` field becomes `excluded_withdrawn`.
2. Summary/details matching review signals become `needs_review`. Signals include pentest, researcher, proof-of-concept, false-positive, test-package, demonstration, and localhost wording.
3. Remaining records become `candidate_malicious`.

The saved reviewed snapshot contains 14,966 `candidate_malicious` records and 2,155 `needs_review` records; no records have `excluded_withdrawn` status. This does not establish that all withdrawn or disputed evidence has been resolved. Separate withdrawal comparisons inspect another advisory directory and do not modify this file.

The word "reviewed" in the filename means automatic screening here. It does not indicate completed manual adjudication. Do not map these states directly to final binary labels or the planned advisory risk categories.

## Provenance and future snapshots

The extractor reads committed objects from the OpenSSF `malicious-packages` checkout. The checkout observed during cleanup is at `3812671bee8aa766a40bcdf9ee322d7c6456cf29`; the CSVs themselves do not record their extraction commit or extraction time. The manifest records this limitation rather than claiming historical provenance that cannot be established.

For future collections, record the source URL, exact commit, collection timestamp, command, environment, hashes, and label review decisions. Preserve the original raw input separately from each derived dataset. Package-level grouping and version handling should be settled before creating train/validation/test splits.

These snapshots remain tracked for review. No broad CSV ignore rule is applied. The upstream checkout retains its own license; preserve source attribution and review applicable dataset terms when distributing derived data.
