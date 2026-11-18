# TyposquatShield

**A pre-installation PyPI package risk advisory CLI.**

TyposquatShield helps Python developers assess package names before installing packages from PyPI.

It provides advisory risk levels, package-name similarity checks, and explanations to support informed installation decisions.

## Installation

```bash
pip install typosquatshield
```

## Usage

Assess a package and optionally install it after confirmation:

```bash
tps requests
```

Assess without an installation prompt:

```bash
tps requests --no-install
```

Check a potentially misspelled package name:

```bash
tps reqeusts --no-install
```

Explicitly assess a PyPI distribution that shares its name with a standard-library module:

```bash
tps argparse --pypi --no-install
```

## Risk advisories

TyposquatShield reports Low Risk, Caution, or High Risk advisories where applicable. Standard-library modules may receive a Not Applicable result.

These results are advisory only. They do not establish whether a package contains malware or guarantee that a package is safe.

## Cloud service

The CLI communicates with the TyposquatShield cloud assessment API. An internet connection is required.

Web dashboard: https://typosquatshield.streamlit.app

## Requirements

Python 3.11 or later.
