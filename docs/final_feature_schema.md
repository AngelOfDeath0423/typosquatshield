
# TyposquatShield — Final Feature Schema

## 1. Purpose

This document defines the proposed features for TyposquatShield,
a cloud-based machine learning system for pre-installation PyPI
package risk assessment.

The system will evaluate package names, historical metadata,
reputation signals, and lightweight static-analysis indicators.

The model will produce a risk assessment supporting three
advisory levels:

- Low Risk
- Caution
- High Risk

These are risk advisories, not definitive malware verdicts.

## 2. Unit of Analysis

Each dataset row represents a specific PyPI package version.

Primary key:

- `normalized_name`
- `version`

Package names will be normalized according to PyPI naming rules.

An `assessment_time` must be defined for each observation.

Features must reflect information available at or before that
assessment time.

## 3. Package Identity Features

| Feature | Type | Description |
|---|---|---|
| normalized_name | string | Normalized package name |
| version | string | Requested package version |
| name_length | integer | Number of characters in package name |
| digit_count | integer | Number of numeric characters |
| hyphen_count | integer | Number of hyphens |
| name_entropy | float | Shannon entropy of package name |
| has_digits | boolean | Whether the name contains digits |
| name_token_count | integer | Number of name tokens |

Package name and version are identifiers and feature sources.
They should not be directly used as arbitrary categorical IDs
by the classifier.

## 4. Name Similarity Features

| Feature | Type | Description |
|---|---|---|
| max_name_similarity | float | Highest similarity to a reference package |
| min_edit_distance | integer | Minimum edit distance to a reference package |
| damerau_distance | integer | Minimum Damerau-Levenshtein distance |
| closest_reference_name | string | Closest established package name |
| is_exact_reference_match | boolean | Whether name exactly matches a reference |
| potential_typosquat | boolean | Whether name meets a defined similarity threshold |

Similarity will be calculated using a reference list of
established legitimate PyPI package names.

The reference list must be versioned and should reflect
packages known at the assessment time.

`closest_reference_name` is primarily an explanation field,
not a raw categorical ML input.

## 5. Package Metadata Features

| Feature | Type | Description |
|---|---|---|
| summary_length | integer | Number of characters in package summary |
| summary_missing | boolean | Whether summary is missing |
| requires_python_missing | boolean | Whether Python requirement is missing |
| has_project_url | boolean | Whether project URL is provided |
| has_homepage | boolean | Whether homepage is provided |
| has_license_metadata | boolean | Whether license information is provided |
| dependency_count | integer | Number of declared dependencies |
| dependency_metadata_missing | boolean | Whether dependency data is unavailable |

Missing metadata should not automatically be treated
as malicious.

Historical availability must be verified before using
these fields in model training.

## 6. Version and Release Features

| Feature | Type | Description |
|---|---|---|
| package_age_days | float | Days since first known package release |
| version_age_days | float | Days since requested version was uploaded |
| prior_release_count | integer | Number of earlier releases |
| release_frequency | float | Historical releases per unit of time |
| distribution_file_count | integer | Number of files for requested version |
| has_wheel | boolean | Whether a wheel was published |
| has_sdist | boolean | Whether a source distribution was published |

Age and release history must be calculated relative
to `assessment_time`.

Do not use releases or metadata published after that time.

## 7. Reputation Features

| Feature | Type | Description |
|---|---|---|
| maintainer_prior_package_count | integer | Number of earlier packages associated with maintainer |
| maintainer_account_age_days | float | Age of maintainer account, if obtainable |
| known_reference_package | boolean | Whether name belongs to established reference set |
| project_repository_present | boolean | Whether a repository URL is present |

Reputation features require additional source and
historical availability validation.

Unavailable reputation data must remain missing rather
than being replaced with invented values.

## 8. Lightweight Static-Analysis Features

These features are planned for a later implementation stage.

| Feature | Type | Description |
|---|---|---|
| suspicious_api_count | integer | Count of selected suspicious API patterns |
| encoded_payload_indicator | boolean | Whether suspicious encoded payload patterns are detected |
| install_hook_indicator | boolean | Whether installation-related execution hooks are detected |
| network_operation_indicator | boolean | Whether selected network-operation patterns are detected |
| subprocess_indicator | boolean | Whether process-execution patterns are detected |

Static indicators require safely obtaining and inspecting
the exact requested distribution artifact.

They must not require executing or installing the package.

A suspicious API alone does not establish malicious intent.

## 9. Labels and Audit Fields

These columns must be stored separately from predictive features.

| Column | Purpose |
|---|---|
| evidence_status | OpenSSF version-level evidence classification |
| timeline_status | Relationship between upload and report publication |
| training_eligibility | Whether record is suitable for further review |
| supporting_report_ids | Supporting OpenSSF report identifiers |
| label_source | Source of label evidence |
| label_verified | Whether label verification is complete |
| ml_label | Final training target, only when justified |
| assessment_time | Historical cutoff used to construct features |
| metadata_source | Provenance of historical metadata |

No binary ML labels will be assigned automatically
based solely on a package-name match.

## 10. Feature Availability Status

Based on the 219-record historical pilot:

| Field | Available | Availability |
|---|---:|---:|
| package_name | 219/219 | 100% |
| version | 219/219 | 100% |
| summary | 153/219 | 69.86% |
| requires_python | 181/219 | 82.65% |
| distribution_file_count | 219/219 | 100% |
| first_upload_time | 219/219 | 100% |

Availability in the CSV does not guarantee availability
at the historical assessment time.

## 11. Feature Development Priority

### Phase A — Initial baseline

Implement:

- Name length and character patterns
- Name entropy
- Name similarity and edit distance
- Summary length and missing-summary indicator
- Python requirement missing indicator

Use only features whose provenance and timing are defensible.

### Phase B — Metadata and reputation

Add:

- Historical package age
- Historical version age
- Prior release count
- Dependency metadata
- Project URL indicators
- Verified reputation signals

### Phase C — Lightweight static indicators

Add static-analysis indicators where exact version
artifacts can be safely obtained and inspected.

## 12. Data Quality Rules

1. No duplicate normalized package-version records.
2. Preserve raw package names and versions.
3. Record source and collection timestamp.
4. Preserve evidence and audit provenance.
5. Keep unknown labels separate from benign labels.
6. Do not use OpenSSF report details as predictive features.
7. Prevent information from future releases entering
   historical feature calculations.
8. Handle missing values explicitly.
9. Split training and testing data to minimize package-family,
   campaign, and temporal leakage.
10. Keep raw, processed, and training-ready datasets separate.

## 13. Current Project Status

Completed:

- OpenSSF malicious-package report extraction
- Legitimate PyPI metadata collection pilot
- Historical metadata feasibility assessment
- BigQuery historical package metadata recovery
- OpenSSF version-level evidence matching
- Original report consistency verification
- Historical timeline validation
- 219-record pilot dataset construction
- Pilot feature availability audit

Next:

1. Implement Phase A feature engineering.
2. Validate derived features on the pilot dataset.
3. Establish a defensible legitimate comparison dataset.
4. Expand historical collection.
5. Build training-ready labels and splits.
6. Train and evaluate ML classifiers.
7. Integrate risk assessment into the FastAPI backend,
   Python CLI, and cloud dashboard.
