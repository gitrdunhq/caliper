"""Jinja2 markdown templates for PR comment rendering."""

from pathlib import Path


def get_templates_dir() -> Path:
    """Return the absolute path to the templates directory."""
    return Path(__file__).parent


def list_templates() -> list[str]:
    """Return a sorted list of template filenames in the templates directory."""
    templates_dir = get_templates_dir()
    names: list[str] = []
    for pattern in ("*.j2", "*.jinja2", "*.html", "*.txt"):
        names.extend(f.name for f in templates_dir.glob(pattern))
    return sorted(names)


__all__ = ["get_templates_dir", "list_templates"]
