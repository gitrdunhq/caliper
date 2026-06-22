"""Bootstrap an alternatives catalog from lockfiles and requirements files.

Usage:
    uv run python scripts/bootstrap_alternatives.py \
        requirements.txt pyproject.toml -o alternatives.json
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
import orjson

from caliper.data.alternatives import (
    build_catalog,
    parse_pyproject_toml,
    parse_requirements_txt,
)


@click.command()
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option(
    "-o",
    "--output",
    "output_path",
    default="alternatives.json",
    type=click.Path(path_type=Path),
    help="Output JSON file path (default: alternatives.json)",
)
def main(files: tuple[Path, ...], output_path: Path) -> None:
    """Parse dependency files and generate a package alternatives catalog."""
    all_packages: set[str] = set()

    for filepath in files:
        suffix = filepath.suffix.lower()
        name = filepath.name.lower()

        if name == "pyproject.toml" or suffix == ".toml":
            packages = parse_pyproject_toml(filepath)
        elif suffix == ".txt" or name.startswith("requirements"):
            packages = parse_requirements_txt(filepath)
        else:
            click.echo(f"Warning: Skipping unrecognized file format: {filepath}", err=True)
            continue

        click.echo(f"Parsed {filepath}: {len(packages)} package(s)", err=True)
        all_packages |= packages

    if not all_packages:
        click.echo("Error: No packages found in any input file.", err=True)
        sys.exit(1)

    catalog = build_catalog(all_packages)
    json_bytes = orjson.dumps(catalog.model_dump(mode="json"), option=orjson.OPT_INDENT_2)

    output_path.write_bytes(json_bytes)
    click.echo(
        f"Wrote {len(catalog.packages)} package(s) to {output_path}",
        err=True,
    )


if __name__ == "__main__":
    main()
