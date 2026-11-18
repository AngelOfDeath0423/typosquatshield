
import argparse
import os
import re
import subprocess
import sys


import httpx
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text

DEFAULT_API_URL = os.getenv(
    "TPS_API_URL",
    "https://typosquatshield.onrender.com",
)

console = Console()

# A PyPI distribution name and a Python import name are not
# necessarily the same. Standard-library handling is only
# applied when the backend reports that PyPI did not find
# the requested distribution.
STDLIB_MODULES = getattr(sys, "stdlib_module_names", frozenset())

PACKAGE_NAME_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$"
)


def is_standard_library_name(package_name):
    """
    Recognise a standard-library module name for the
    Python interpreter running this CLI.

    Do not use this alone to determine whether a
    corresponding PyPI distribution exists.
    """
    return (
        package_name.strip() in STDLIB_MODULES
    )


def is_stdlib_only_result(result):
    """
    Only classify a name as standard-library-only when
    the backend has reported that PyPI did not find it.
    """
    return (
        result.get("metadata_status") == "not_found"
        and is_standard_library_name(
            str(result.get("package", ""))
        )
    )


def display_standard_library(package_name):
    console.print()

    console.print(
        Panel.fit(
            "[bold cyan]TYPOSQUATSHIELD[/bold cyan]\n"
            "Pre-installation PyPI Package Risk Advisory",
            border_style="cyan",
        )
    )

    summary = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
    )

    summary.add_column("Field", style="bold")
    summary.add_column("Value")

    summary.add_row("Module", package_name)
    summary.add_row(
        "Status",
        Text("Python Standard Library", style="bold green"),
    )
    summary.add_row(
        "Risk Level",
        "Not Applicable",
    )
    summary.add_row(
        "Installation",
        "Not required",
    )

    console.print(summary)

    console.print()
    console.print(
        "[bold cyan]WHY NO INSTALLATION IS REQUIRED[/bold cyan]"
    )
    console.print(
        "  [cyan]-[/cyan] "
        f"'{package_name}' is a Python standard-library module."
    )
    console.print(
        "  [cyan]-[/cyan] "
        "It is included with this Python interpreter."
    )
    console.print(
        "  [cyan]-[/cyan] "
        "You can normally import it directly without pip."
    )

    console.print()
    console.print(
        "[dim]Standard-library detection is based on the "
        "Python interpreter running TyposquatShield.[/dim]"
    )
    console.print()


def display_assessment(result):
    package = result.get("package", "Unknown")
    version = result.get("version")
    risk = result.get("risk_level")
    status = result.get("assessment_status", "Unknown")

    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]TYPOSQUATSHIELD[/bold cyan]\n"
            "Pre-installation PyPI Package Risk Advisory",
            border_style="cyan",
        )
    )

    risk_styles = {
        "Low Risk": "bold green",
        "Caution": "bold yellow",
        "High Risk": "bold red",
    }

    risk_label = risk or "Not Assessed"
    risk_style = risk_styles.get(risk, "white")

    summary = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
    )

    summary.add_column("Field", style="bold")
    summary.add_column("Value")

    summary.add_row("Package", str(package))

    if version:
        summary.add_row("Version", str(version))

    summary.add_row(
        "Risk Level",
        Text(risk_label, style=risk_style),
    )

    summary.add_row(
        "Assessment Status",
        str(status),
    )

    console.print(summary)

    typo = result.get("typosquatting") or {}
    suggestions = typo.get("suggestions") or []

    if suggestions:
        console.print()
        console.print(
            "[bold yellow]SIMILAR PACKAGE NAMES[/bold yellow]"
        )

        table = Table(show_header=True)
        table.add_column(
            "Suggested Package",
            style="cyan",
        )
        table.add_column(
            "Edit Distance",
            justify="center",
        )
        table.add_column(
            "Similarity",
            justify="right",
        )

        for item in suggestions:
            similarity = item.get("similarity")

            similarity_text = (
                f"{float(similarity) * 100:.1f}%"
                if similarity is not None
                else "N/A"
            )

            table.add_row(
                str(
                    item.get(
                        "reference_package",
                        "Unknown",
                    )
                ),
                str(item.get("edit_distance", "?")),
                similarity_text,
            )

        console.print(table)

    reasons = (
        result.get("advisory_reasons")
        or result.get("reasons")
        or []
    )

    if reasons:
        console.print()
        console.print(
            "[bold]WHY THIS PACKAGE WAS FLAGGED[/bold]"
        )

        for reason in reasons:
            console.print(
                f"  [cyan]-[/cyan] {reason}"
            )

    ml = result.get("ml_prediction")

    if ml:
        console.print()
        console.print(
            "[bold]EXPERIMENTAL ML INFORMATION[/bold]"
        )

        console.print(
            "Candidate group: "
            f"{ml.get('predicted_candidate_group', 'Unknown')}"
        )

        score = ml.get("openssf_association_score")

        if score is not None:
            console.print(
                "OpenSSF association score: "
                f"{float(score):.4f}"
            )

        console.print(
            "[dim]This is not a verified "
            "malware probability.[/dim]"
        )

    console.print()
    console.print(
        "[dim]Advisory only. Results do not prove "
        "whether a package contains malware.[/dim]"
    )
    console.print()


def get_install_target(result):
    """
    Return an exact package==version requirement only
    when the backend assessment is eligible.

    This function does not perform installation.
    """
    if result.get("risk_level") != "Low Risk":
        return None

    if result.get("metadata_status") != "available":
        return None

    package = result.get("package")
    version = result.get("version")

    if not isinstance(package, str):
        return None

    if not isinstance(version, str):
        return None

    package = package.strip()
    version = version.strip()

    if not PACKAGE_NAME_PATTERN.fullmatch(package):
        return None

    try:
        parsed_version = Version(version)
    except InvalidVersion:
        return None

    # Only install a normal, stable release.
    if (
        parsed_version.is_prerelease
        or parsed_version.is_devrelease
    ):
        return None

    # Ensure the requested name and the backend's
    # returned distribution name agree.
    metadata = result.get("metadata") or {}

    metadata_name = metadata.get("package_name")

    if not isinstance(metadata_name, str):
        return None

    if canonicalize_name(package) != canonicalize_name(
        metadata_name
    ):
        return None

    return f"{package}=={version}"


def offer_installation(result, requested_name, no_install):
    """
    Offer optional installation after a Low Risk advisory.

    Never install without explicit user confirmation.
    """
    if no_install:
        return 0

    target = get_install_target(result)

    if target is None:
        return 0

    # Do not silently install a different package name.
    if canonicalize_name(requested_name) != canonicalize_name(
        result["package"]
    ):
        console.print(
            "[yellow]Installation was not offered because "
            "the returned package name differs from "
            "the requested name.[/yellow]"
        )
        return 0

    # Avoid hanging in scripts or non-interactive terminals.
    if not sys.stdin.isatty():
        console.print(
            "[dim]Installation prompt skipped: "
            "non-interactive terminal.[/dim]"
        )
        return 0

    console.print(
        "[bold green]OPTIONAL INSTALLATION[/bold green]"
    )
    console.print(
        f"Assessed distribution: [cyan]{target}[/cyan]"
    )
    console.print(
        "[yellow]Low Risk is an advisory, not a "
        "guarantee of safety. Installing a package "
        "may execute third-party code.[/yellow]"
    )

    confirmed = Confirm.ask(
        "Install this exact version using pip?",
        default=False,
    )

    if not confirmed:
        console.print(
            "[dim]Installation cancelled. "
            "No pip command was executed.[/dim]"
        )
        return 0

    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        target,
    ]

    console.print()
    console.print(
        "[cyan]Running pip installation...[/cyan]"
    )

    try:
        completed = subprocess.run(
            command,
            check=False,
            shell=False,
        )
    except OSError as exc:
        console.print(
            "[bold red]Unable to start pip installation."
            "[/bold red]"
        )
        console.print(str(exc))
        return 3

    if completed.returncode != 0:
        console.print(
            "[bold red]pip installation failed."
            "[/bold red]"
        )
        return 3

    console.print(
        "[bold green]pip installation completed "
        "successfully.[/bold green]"
    )

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="tps",
        description=(
            "TyposquatShield pre-installation "
            "PyPI package risk checker"
        ),
    )

    parser.add_argument(
        "package_name",
        help="PyPI package name to assess",
    )

    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help="TyposquatShield backend URL",
    )

    parser.add_argument(
        "--no-install",
        action="store_true",
        help="Disable the optional pip installation prompt",
    )

    

    parser.add_argument(
    "--pypi",
    action="store_true",
    help=(
        "Explicitly assess the PyPI distribution, "
        "even if its name matches a Python standard-library module"
    ),
)

    args = parser.parse_args()

    url = args.api_url.rstrip("/") + "/assess"

    try:
        with console.status(
            "[cyan]Checking PyPI package...[/cyan]"
        ):
            response = httpx.post(
    url,
    json={
        "package_name": args.package_name,
        "assessment_context": (
            "pypi" if args.pypi else "auto"
        ),
    },
    timeout=120.0,
)

        response.raise_for_status()
        result = response.json()

        if not isinstance(result, dict):
            raise ValueError("Invalid API response.")

    except httpx.HTTPStatusError as exc:
        console.print(
            "[bold red]API error: "
            f"HTTP {exc.response.status_code}[/bold red]"
        )
        return 2

    except httpx.RequestError:
        console.print(
            "[bold red]Cannot connect to TyposquatShield API."
            "[/bold red]"
        )
        console.print(
            "Ensure the FastAPI backend is running."
        )
        return 2

    except ValueError:
        console.print(
            "[bold red]Invalid API response.[/bold red]"
        )
        return 2

    if is_stdlib_only_result(result):
        display_standard_library(
            str(result["package"])
        )
        return 0

    display_assessment(result)

    return offer_installation(
    result=result,
    requested_name=args.package_name.strip(),
    no_install=args.no_install,
)


if __name__ == "__main__":
    sys.exit(main())
