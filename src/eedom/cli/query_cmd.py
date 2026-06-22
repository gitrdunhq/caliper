"""Code graph query CLI command."""

from __future__ import annotations

import sys
from pathlib import Path

import click


@click.command()
@click.argument("question")
@click.option(
    "--db",
    "db_path",
    type=click.Path(),
    default=None,
    help=(
        "Path to the CodeGraph SQLite database. Defaults to the db "
        "'eedom review' maintains for the current directory (user cache dir, "
        "or a legacy ./.eedom/code_graph.sqlite if present)."
    ),
)
def query(question: str, db_path: str | None) -> None:
    """Query the code graph using natural language.

    Examples:

    \b
      eedom query "which functions have the highest fan-out?"
      eedom query "show me dead code"
      eedom query "what depends on ReviewPipeline"
      eedom query "are there circular imports?"
    """
    from eedom.core.nl_query import TEMPLATES, query_code
    from eedom.plugins._runners.graph_builder import resolve_graph_db_path

    if db_path is None:
        candidates = [resolve_graph_db_path(Path.cwd()), Path(".eedom/graph.db")]
        db = next((c for c in candidates if c.exists()), candidates[0])
    else:
        db = Path(db_path)
    if not db.exists():
        click.echo(f"Database not found: {db}", err=True)
        click.echo(
            "Run 'eedom review --repo-path .' first to build the code graph.",
            err=True,
        )
        sys.exit(1)

    result = query_code(question, db)

    if not result.query:
        click.echo("No matching query found.\n")
        click.echo(f"Available queries ({len(TEMPLATES)} templates):")
        click.echo()
        for row in result.rows:
            desc = row.get("template", "")
            kws = row.get("keywords", "")
            click.echo(f"  {desc}")
            if kws:
                click.echo(f"    Keywords: {kws}")
        sys.exit(0)

    click.echo(f"Query: {result.description}\n")

    if not result.rows:
        click.echo("No results found.")
        sys.exit(0)

    _print_table(result.columns, result.rows)


def _print_table(columns: list[str], rows: list[dict]) -> None:
    """Print rows as an aligned table, using rich when available."""
    try:
        from rich.console import Console
        from rich.table import Table

        table = Table(show_header=True, header_style="bold")
        for col in columns:
            table.add_column(col)
        for row in rows:
            table.add_row(*[str(row.get(col, "")) for col in columns])
        Console().print(table)
    except ImportError:
        col_widths = {col: len(col) for col in columns}
        for row in rows:
            for col in columns:
                col_widths[col] = max(col_widths[col], len(str(row.get(col, ""))))
        header = "  ".join(col.ljust(col_widths[col]) for col in columns)
        separator = "  ".join("-" * col_widths[col] for col in columns)
        click.echo(header)
        click.echo(separator)
        for row in rows:
            line = "  ".join(str(row.get(col, "")).ljust(col_widths[col]) for col in columns)
            click.echo(line)
