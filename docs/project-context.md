# Project context and implementation status

## Purpose

TyposquatShield is a final year cybersecurity project investigating advisory risk assessment before a developer installs a PyPI package. The investigation proposes combining name similarity, metadata and reputation, dependency information, and lightweight static features, with understandable reasons and possible package-name suggestions.

The intended advisory categories are Low Risk, Caution, and High Risk. A name resemblance or absent metadata alone does not establish malicious intent. The implementation should preserve this distinction when labels, model outputs, and user-facing explanations are designed.

## Investigation and implementation

The investigation report selects CRISP-DM with iterative development. The planned prototype consists of a Python command-line checker, FastAPI backend, machine-learning engine, database, and Streamlit dashboard, deployed in a cloud environment. Its intended evaluation includes classification performance, false positives, and response time. These are project plans rather than implemented capabilities or measured results.

The repository currently supports data understanding and preparation:

- A raw 5,000-package development sample and a separately saved cleaned version.
- Development cleaning, diagnostics, exploratory summaries, and a saved figure.
- OpenSSF advisory extraction into package/version/report records.
- Automatic screening for withdrawn reports and text signals requiring label review.
- Supporting investigations of missing versions, withdrawn advisories, and possible disputed annotations.

There is no implemented feature-engineering pipeline, trained model, final experiment, application service, dashboard, or deployment in this snapshot.

## Dataset specification

The existing [dataset design specification](specifications/TyposquatShield_Real_Dataset_Design_Specification.docx) distinguishes the development sample from a proposed experimental dataset of approximately 10,000 records. It proposes separate package and package-file tables, fixed collection timestamps, preserved label evidence, and derived features created after raw collection.

Its proposed directories and filenames describe future work. The current repository uses `data/dev/` and `data/labels/` for artifacts that already exist. Add raw, cleaned, processed, models, or notebook directories when their contents are implemented.

## Decisions and work still required

1. Establish credible legitimate and suspicious label sources and review criteria. Absence from an advisory collection does not establish a legitimate label.
2. Resolve uncertain, withdrawn, and potentially disputed records, preserving decisions and supporting references. Automatic screening is not manual verification.
3. Confirm original collection provenance and timestamp semantics for the development sample. Its collector is not present.
4. Define a trusted package-name reference list and an achievable class distribution for the experimental dataset.
5. Finalize storage format and implement the real-data collector, package-file table, cleaning, and feature engineering.
6. Choose package/version grouping and any temporal separation before training/evaluation splits, to avoid related records leaking between splits.
7. Define and evaluate how model outputs map to the three advisory categories. The present label statuses are review workflow states, not those categories.
8. Implement and evaluate the planned prototype after the dataset and model are ready.

The investigation report is retained locally in `docs/reports/`. Its contents were used as project context; the document itself is not changed or published by this cleanup.
