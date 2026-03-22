"""gitdork CLI."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from .dork_engine import generate
from .extractor import enrich_from_github, parse_target
from .models import DorkCategory, DorkEngine
from .reporters import json_report, markdown
from .reporters import terminal as term_reporter

console = Console()

ENGINE_CHOICES = [e.value for e in DorkEngine]
CATEGORY_CHOICES = [c.value for c in DorkCategory]


def _parse_list(ctx, param, value) -> list | None:
    if not value:
        return None
    return [v.strip() for v in value.split(",")]


@click.group()
@click.version_option(version="1.1.0", prog_name="gitdork")
def main():
    """
    \b
    gitdork — Google, Shodan & GitHub dork generator
    Feed it a target, get ready-to-use dork queries.

    \b
    Examples:
      gitdork generate ExploitCraft/ReconNinja
      gitdork generate example.com
      gitdork generate github.com/ExploitCraft --engine google,shodan
      gitdork generate example.com --category secrets,misconfigs
      gitdork generate example.com --format json --output dorks.json
      gitdork generate example.com --format markdown --output dorks.md
      gitdork list-categories
      gitdork list-engines
    """
    pass


@click.command()
@click.argument("target")
@click.option(
    "--engine", "-e", default=None, callback=_parse_list,
    metavar="ENGINES",
    help="Comma-separated engines: google,shodan,github (default: all)",
)
@click.option(
    "--category", "-c", default=None, callback=_parse_list,
    metavar="CATEGORIES",
    help="Comma-separated categories (default: all). See list-categories.",
)
@click.option(
    "--format", "fmt", default="terminal",
    type=click.Choice(["terminal", "json", "markdown"]),
    help="Output format.",
)
@click.option(
    "--output", "-o", type=click.Path(path_type=Path),
    default=None, help="Write output to file.",
)
@click.option(
    "--group-by", default="engine",
    type=click.Choice(["engine", "category"]),
    help="Group terminal output by engine or category.",
)
@click.option(
    "--enrich", is_flag=True, default=False,
    help="Fetch GitHub metadata to detect tech stack.",
)
@click.option(
    "--token", default=None, envvar="GITHUB_TOKEN",
    help="GitHub token for enrichment (or set GITHUB_TOKEN env var).",
)
def generate_cmd(
    target, engine, category, fmt, output, group_by, enrich, token
):
    """Generate dorks for TARGET (domain, GitHub org/repo, or URL)."""

    if fmt == "terminal":
        term_reporter.print_banner()

    # Parse target
    with console.status("[dim]Parsing target...[/dim]"):
        t = parse_target(target)

    # Optionally enrich via GitHub API
    if enrich and t.is_github:
        with console.status("[dim]Fetching GitHub metadata...[/dim]"):
            t = enrich_from_github(t, token=token)

    # Resolve engine / category filters
    engines = None
    if engine:
        try:
            engines = [DorkEngine(e) for e in engine]
        except ValueError as ex:
            raise click.BadParameter(str(ex), param_hint="--engine")

    categories = None
    if category:
        try:
            categories = [DorkCategory(c) for c in category]
        except ValueError as ex:
            raise click.BadParameter(str(ex), param_hint="--category")

    # Generate
    with console.status("[dim]Generating dorks...[/dim]"):
        result = generate(t, engines=engines, categories=categories)

    # Output
    if fmt == "terminal":
        term_reporter.print_results(result, group_by=group_by)

    elif fmt == "json":
        if output:
            json_report.write(result, output)
            console.print(f"[green]✓ JSON written to {output}[/green]")
        else:
            json_report.print_json(result)

    elif fmt == "markdown":
        if not output:
            output = Path(f"gitdork_{t.display.replace('/', '_')}.md")
        markdown.write(result, output)
        console.print(f"[green]✓ Markdown written to {output}[/green]")


# Register the command under the name 'generate'
main.add_command(generate_cmd, name="generate")


@main.command("list-categories")
def list_categories():
    """List all available dork categories."""
    from rich import box
    from rich.table import Table

    from .models import CATEGORY_LABELS

    table = Table(box=box.SIMPLE_HEAD, header_style="bold dim")
    table.add_column("ID", style="cyan", width=20)
    table.add_column("LABEL")

    for cat in DorkCategory:
        table.add_row(cat.value, CATEGORY_LABELS.get(cat, cat.value))

    console.print(table)


@main.command("list-engines")
def list_engines():
    """List all supported dork engines."""
    from rich import box
    from rich.table import Table

    table = Table(box=box.SIMPLE_HEAD, header_style="bold dim")
    table.add_column("ENGINE", style="cyan", width=10)
    table.add_column("DESCRIPTION")

    table.add_row("google", "Google search dorks (site:, filetype:, intitle:, inurl:)")
    table.add_row("shodan", "Shodan queries (hostname:, port:, product:, ssl:)")
    table.add_row("github", "GitHub code search (org:, filename:, extension:)")

    console.print(table)
