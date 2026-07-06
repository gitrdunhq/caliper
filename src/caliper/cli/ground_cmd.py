"""``caliper ground`` — deterministic grounding bundle (fact sheet + type context)."""

# tested-by: tests/unit/test_grounding_cli.py

from __future__ import annotations

import sys

import click

from caliper.cli.cli_shared import _write_output


def _render_grounding_markdown(bundle: dict) -> str:
    """Render a grounding bundle (fact sheet + type context) as markdown."""
    fact_sheet = bundle.get("fact_sheet") or []
    type_context = bundle.get("type_context") or []
    lines = [
        "# Grounding bundle",
        "",
        (
            f"_provider: {bundle.get('provider', 'null')}; "
            f"{len(fact_sheet)} in-file defs, {len(type_context)} referenced type defs._"
        ),
        "",
        "## Fact sheet — symbols defined in the files under review",
        "Trust these signatures over assumptions about the code's shape.",
        "",
    ]
    if fact_sheet:
        for s in fact_sheet:
            sig = f" {s['signature']}" if s.get("signature") else ""
            lines.append(
                f"- `{s.get('kind', '')}` **{s.get('name', '')}**{sig} — "
                f"{s.get('file', '')}:{s.get('line', 0)}"
            )
    else:
        lines.append("_(no symbols resolved — fact sheet empty)_")
    lines.append("")
    lines.append("## Type context — contracts referenced from elsewhere")
    lines.append(
        "Before flagging a 'raw string', 'missing timeout', 'wrong type', or "
        "'unvalidated value', check whether the contract below already constrains it."
    )
    lines.append("")
    if type_context:
        for s in type_context:
            sig = f" {s['signature']}" if s.get("signature") else ""
            lines.append(
                f"- `{s.get('kind', '')}` **{s.get('name', '')}**{sig} — "
                f"{s.get('file', '')}:{s.get('line', 0)}"
            )
    else:
        lines.append("_(no cross-file type contracts resolved)_")
    lines.append("")
    return "\n".join(lines)


@click.command(name="ground")
@click.option(
    "--files",
    "files",
    multiple=True,
    required=True,
    help="File(s) under review to ground (repeatable).",
)
@click.option(
    "--out",
    type=click.Path(),
    default=None,
    help="Write the bundle JSON here; if omitted, print to stdout.",
)
def ground(files: tuple[str, ...], out: str | None) -> None:
    """Produce a deterministic grounding bundle (separate, feature-flag-gated step).

    Emits a fact sheet (symbols defined in the given files) plus type context
    (type-like contracts referenced from elsewhere) so a downstream consumer
    starts grounded. NOT part of the normal scan; requires
    CALIPER_GROUNDING_ENABLED=1.
    """
    import json

    from caliper.core.config import CaliperSettings

    settings = CaliperSettings()  # type: ignore[call-arg]

    if not settings.grounding_enabled:
        click.echo(
            "grounding is gated off. Enable with CALIPER_GROUNDING_ENABLED=1 to run this step.",
            err=True,
        )
        sys.exit(0)

    from caliper.composition.bootstrap import run_grounding

    bundle = run_grounding(list(files), settings)
    payload = json.dumps(bundle, indent=2)

    if out:
        _write_output(out, payload)
        if out.endswith(".json"):
            md_path = out[: -len(".json")] + ".md"
            _write_output(md_path, _render_grounding_markdown(bundle))
        click.echo(
            f"Grounding bundle written to {out} "
            f"({len(bundle.get('fact_sheet') or [])} defs, "
            f"{len(bundle.get('type_context') or [])} type contexts)"
        )
    else:
        click.echo(payload)
    sys.exit(0)
