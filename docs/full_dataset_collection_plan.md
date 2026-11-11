
# TyposquatShield — Full Dataset Collection Plan

## 1. Purpose

This document defines the collection, labeling, validation,
and evaluation strategy for the full TyposquatShield dataset.

Project title:
Developing a Cloud-Based Machine Learning System for
Pre-Installation PyPI Package Risk Assessment.

The dataset will support:

- Package-name similarity analysis
- Package metadata and reputation analysis
- Lightweight static-analysis indicators
- Random Forest, SVM, XGBoost, and stacking models
- Explainable pre-installation risk assessment

## 2. Current Progress

The following work has been completed:

- Extracted 11,798 unique PyPI package names from OpenSSF.
- Extracted 17,121 OpenSSF package/version/range records.
- Collected and validated 100 presumed-legitimate packages.
- Audited 100 OpenSSF package names against the live PyPI API.
- Found that 97 returned HTTP 404.
- Recovered 219 historical package-version records using BigQuery.
- Matched historical versions with OpenSSF evidence.
- Investigated 17 historical timeline anomalies.
- Built the 219-record pilot dataset.
- Engineered and validated 14 Phase A features.

The pilot has not yet produced verified binary ML labels.

## 3. Target Dataset Size

Initial target:

Approximately 10,000 package-version observations.

Provisional composition:

- Up to 5,000 malicious or malicious-candidate observations
- Up to 5,000 legitimate observations

This is a collection target, not a guaranteed class balance.

The final number will depend on:

- Historical metadata availability
- Version-level evidence quality
- Temporal validity
- Legitimate sample quality
- Duplicate removal
- Feature completeness

Do not fabricate records or duplicate observations to reach
the target.

## 4. Unit of Analysis

Each observation represents a specific package version.

Primary identifier:

- normalized_name
- version

Required provenance fields:

- package_name
- normalized_name
- version
- first_upload_time
- assessment_time
- metadata_source
- metadata_collection_time
- source_snapshot
- label_source
- label_status
- label_verified

Package names will be normalized using PyPI conventions.

For historical observations, assessment_time must be chosen
so that features reflect information available before
installation.

## 5. Malicious Evidence Sources

Primary evidence source:

OpenSSF malicious-packages repository.

Use the pinned repository snapshot:

3812671bee8aa766a40bcdf9ee322d7c6456cf29

Evidence requirements:

- Original OpenSSF report ID
- Exact package ecosystem
- Normalized package name
- Explicit affected version or supported affected range
- Report publication timestamp
- Report withdrawal status
- Source provenance

Only PyPI ecosystem reports are eligible.

A package-name match alone is insufficient for a
version-level malicious training label.

Affected-version ranges must be evaluated using their
documented semantics.

Unresolved or contradictory evidence must be flagged.

## 6. Historical Metadata Collection

Primary historical metadata source:

Google BigQuery historical PyPI metadata.

The existing pilot confirmed that BigQuery can recover
metadata for packages no longer available through the
current PyPI API.

Historical fields may include:

- Package name
- Version
- Upload timestamp
- Summary
- Python version requirement
- Distribution filename
- Distribution file count

Collection must preserve the original upload timestamps.

Historical metadata must be grouped carefully to avoid
treating multiple distribution files as duplicate versions.

Raw exports must remain unchanged.

The exact BigQuery source table, query, query date, and
export settings must be documented for reproducibility.

## 7. Legitimate Dataset Strategy

Legitimate observations must be collected from a broader
population than the original 100 well-known packages.

Potential sources:

- Historical PyPI releases in BigQuery
- PyPI project metadata
- Established package reference lists

Requirements:

- Version exists in the historical source
- Package/version identity is unambiguous
- No known conflicting malicious evidence at the chosen
  assessment cutoff
- Comparable metadata definitions to malicious examples
- Sampling across popularity, age, and release history

Absence from OpenSSF is not proof of benign behavior.

Legitimate examples must carry an explicit evidence-quality
or confidence designation.

The original 100-package collection remains a pipeline pilot.

## 8. Labeling Rules

Proposed target values:

- 1 = malicious
- 0 = legitimate

However, these values must only be assigned after a
separate label-quality review.

Possible statuses:

- malicious_candidate
- legitimate_candidate
- temporal_review_required
- insufficient_version_evidence
- disputed_or_withdrawn
- label_review_required

Records with unresolved evidence must not be silently
assigned a binary training label.

Keep label provenance and verification status separate
from predictive features.

## 9. Feature Collection

### Phase A — Name-Based Features

- Name length
- Digit count
- Hyphen count
- Name entropy
- Name token count
- Levenshtein distance
- Damerau-Levenshtein distance
- RapidFuzz similarity
- Potential typosquatting indicator

### Phase B — Metadata and Reputation

- Summary length
- Summary missing indicator
- Python requirement missing indicator
- Package age at assessment
- Version age at assessment
- Prior release count
- Release frequency
- Dependency metadata
- Project URL indicators
- Available maintainer reputation signals

### Phase C — Lightweight Static Analysis

- Suspicious API patterns
- Installation-related execution hooks
- Encoded payload indicators
- Network-operation indicators
- Process-execution indicators

Static analysis must inspect the exact distribution
artifact without executing or installing it.

Missing static features must remain explicitly unavailable.

Do not assign zero suspicious patterns merely because
the artifact could not be obtained.

## 10. Temporal Validity

For each observation:

- Define assessment_time.
- Exclude metadata introduced after assessment_time.
- Exclude future package releases.
- Use a historically appropriate reference-name list.
- Keep OpenSSF publication dates out of predictive features.
- Preserve temporal evidence for audit purposes.

A version uploaded before an OpenSSF report is not
automatically confirmed malicious.

Historical publication dates are evidence timestamps,
not predictive model inputs.

## 11. Data Leakage Prevention

The following must not be used as model features:

- OpenSSF report IDs
- Report publication dates
- Evidence status
- Label source
- Label verification status
- Training eligibility
- Future release information
- Whether a package was removed from PyPI after reporting

Metadata missingness must be compared across classes to
detect collection-source bias.

Package names must not be treated as arbitrary categorical
identifiers for memorization.

## 12. Dataset Splitting

Do not perform a naive random row-level split.

Multiple versions of the same package must not be spread
across training and test sets.

Use package-grouped splitting as a minimum.

Where practical, also evaluate:

- Temporal holdout
- Unseen package families
- Campaign-level separation

All preprocessing, scaling, imputation, and feature
selection must be fitted on training data only.

## 13. ML Evaluation

Planned models:

- Random Forest
- Support Vector Machine
- XGBoost
- Stacking ensemble

Evaluation metrics:

- Precision
- Recall
- F1-score
- Confusion matrix
- False-positive rate
- ROC-AUC and PR-AUC where appropriate
- Inference latency

Report class-specific results and uncertainty.

Do not claim target performance before testing.

## 14. Explainability

Use SHAP and/or LIME to explain model outputs.

Explanations should identify which risk signals
contributed to the assessment.

Risk levels:

- Low Risk
- Caution
- High Risk

Risk thresholds must be defined and validated using
held-out data.

The system provides advisories, not guaranteed
malware detection.

## 15. Collection Workflow

1. Freeze the OpenSSF source snapshot.
2. Prepare the full malicious package/version manifest.
3. Export historical PyPI metadata from BigQuery.
4. Normalize package and version identifiers.
5. Match exact versions and affected ranges.
6. Apply evidence and timeline review rules.
7. Collect diverse legitimate comparison examples.
8. Construct comparable assessment-time features.
9. Audit missingness and source bias.
10. Collect safe static-analysis features where available.
11. Finalize training labels and eligibility.
12. Create leakage-resistant train/validation/test splits.
13. Train, compare, and evaluate ML models.
14. Integrate the selected model into the application.

## 16. Required Outputs

Planned datasets:

data/full/
    malicious_manifest.csv
    historical_metadata_raw.csv
    historical_metadata_versions.csv
    legitimate_candidates.csv
    combined_candidates.csv
    label_review.csv
    training_ready.csv

Planned reports:

reports/
    full_collection_summary.txt
    full_label_quality_summary.txt
    full_feature_quality_summary.txt
    full_dataset_split_summary.txt

These files are planned deliverables and do not
necessarily exist yet.

## 17. Immediate Next Action

Prepare the full malicious-package collection manifest
from the validated OpenSSF source.

Then determine historical BigQuery coverage before
committing to the final dataset composition.

The next script will be:

scripts/prepare_full_malicious_manifest.py
