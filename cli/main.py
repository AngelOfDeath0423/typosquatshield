
import argparse
import sys

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

DEFAULT_API_URL = "http://127.0.0.1:8000"

console = Console()


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
        table.add_column("Suggested Package", style="cyan")
        table.add_column("Edit Distance", justify="center")
        table.add_column("Similarity", justify="right")

        for item in suggestions:
            similarity = item.get("similarity")

            similarity_text = (
                f"{float(similarity) * 100:.1f}%"
                if similarity is not None
                else "N/A"
            )

            table.add_row(
                str(item.get("reference_package", "Unknown")),
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
            console.print(f"  [cyan]•[/cyan] {reason}")

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
                f"OpenSSF association score: {float(score):.4f}"
            )

        console.print(
            "[dim]This is not a verified malware probability.[/dim]"
        )

    console.print()
    console.print(
        "[dim]Advisory only. Results do not prove "
        "whether a package contains malware.[/dim]"
    )
    console.print()


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

    args = parser.parse_args()

    url = args.api_url.rstrip("/") + "/assess"

    try:
        with console.status(
            "[cyan]Checking PyPI package...[/cyan]"
        ):
            response = httpx.post(
                url,
                json={"package_name": args.package_name},
                timeout=30.0,
            )

        response.raise_for_status()
        result = response.json()

    except httpx.HTTPStatusError as exc:
        console.print(
            f"[bold red]API error:"
            f" HTTP {exc.response.status_code}[/bold red]"
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

    display_assessment(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
