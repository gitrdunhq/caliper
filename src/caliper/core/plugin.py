"""Scanner plugin contract.
# tested-by: tests/unit/test_plugin_registry.py
# tested-by: tests/unit/test_plugin_templates.py
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import Field

from caliper._base import Contract

# Default templates directory — co-located with caliper.templates package.
_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


class PluginCategory(StrEnum):
    dependency = "dependency"
    code = "code"
    infra = "infra"
    quality = "quality"
    supply_chain = "supply_chain"


class Actionability(StrEnum):
    fix = "fix"
    blocked_upstream = "blocked_upstream"
    blocked_os = "blocked_os"
    blocked_eol = "blocked_eol"
    accept = "accept"


_FINDING_KNOWN_KEYS = {
    "id",
    "severity",
    "message",
    "file",
    "line",
    "url",
    "category",
    "package",
    "version",
    "fixed_version",
    "rule_id",
    "summary",
    "description",
    "fix_suggestion",
}


class PluginFinding(Contract):
    """A single normalized finding — a frozen, strict value object.

    Consumers read fields by attribute and custom keys via ``metadata`` (use
    ``finding_get`` for the transitional dict-or-model case). The presentation
    layer renders ``to_dict()`` output, never the model directly.
    """

    id: str
    severity: str
    message: str
    file: str = ""
    line: int = 0
    url: str = ""
    category: str = ""
    package: str = ""
    version: str = ""
    fixed_version: str = ""
    rule_id: str = ""
    fix_suggestion: str = ""
    metadata: dict = Field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "id": self.id,
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "url": self.url,
            "category": self.category,
            "package": self.package,
            "version": self.version,
            "fixed_version": self.fixed_version,
            "rule_id": self.rule_id,
            "fix_suggestion": self.fix_suggestion,
        }
        d.update(self.metadata)
        return d


def finding_get(finding, key: str, default=None):
    """Read *key* from a ``PluginFinding`` or a raw ``dict`` finding.

    The single typed accessor that replaces the old dict-masquerade shims on
    ``PluginFinding``. For a frozen ``PluginFinding`` it returns the matching
    field, then falls back to ``metadata``; for a raw dict (semgrep/blast-radius
    style findings that have not been normalized) it uses ``dict.get``.
    """
    if isinstance(finding, dict):
        return finding.get(key, default)
    if hasattr(finding, key):
        return getattr(finding, key)
    return finding.metadata.get(key, default)


def finding_as_dict(finding) -> dict:
    """Return a plain dict for a finding (identity for dicts; to_dict otherwise)."""
    return finding if isinstance(finding, dict) else finding.to_dict()


def result_with_dict_findings(result: PluginResult) -> PluginResult:
    """Return a copy of *result* with every finding serialized to a plain dict.

    Plugin ``render`` methods (and the Jinja templates) operate on dicts; the
    frozen typed ``PluginFinding`` is for the core paths. Call this at the top
    of any ``render`` override so it works whether fed dicts or PluginFindings.
    """
    return replace(result, findings=[finding_as_dict(f) for f in result.findings])


def normalize_finding(raw: dict) -> PluginFinding:
    known = {}
    metadata = {}
    for k, v in raw.items():
        if k in _FINDING_KNOWN_KEYS:
            known[k] = v
        else:
            metadata[k] = v
    return PluginFinding(
        id=str(known.get("id", known.get("rule_id", ""))),
        severity=str(known.get("severity", "info")),
        message=str(known.get("message", known.get("description", known.get("summary", "")))),
        file=str(known.get("file", "")),
        line=int(known.get("line", 0)),
        url=str(known.get("url", "")),
        category=str(known.get("category", "")),
        package=str(known.get("package", "")),
        version=str(known.get("version", "")),
        fixed_version=str(known.get("fixed_version", "")),
        rule_id=str(known.get("rule_id", "")),
        fix_suggestion=str(known.get("fix_suggestion", "")),
        metadata=metadata,
    )


@dataclass(frozen=True)
class PluginResult:
    plugin_name: str
    findings: list[PluginFinding | dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    error: str = ""
    package_root: str | None = None
    category: str = ""
    skip_reason: str = ""
    skip_remediation: str = ""


@runtime_checkable
class AnalyzerPort(Protocol):
    """Structural contract for an analyzer plugin.

    Restates the public ``ScannerPlugin`` surface so callers can depend on the
    port rather than the concrete base class.  ``ScannerPlugin`` remains the
    shared concrete base (it supplies the Jinja2 ``render`` machinery and the
    ``depends_on``/``skip_reason`` defaults); every plugin instance satisfies
    this Protocol structurally.
    """

    @property
    def name(self) -> str: ...

    @property
    def category(self) -> PluginCategory: ...

    @property
    def depends_on(self) -> list[str]: ...

    def can_run(self, files: list[str], repo_path: Path) -> bool: ...

    def run(self, files: list[str], repo_path: Path) -> PluginResult: ...

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str: ...


class ScannerPlugin(abc.ABC):
    @property
    @abc.abstractmethod
    def name(self) -> str: ...

    @property
    @abc.abstractmethod
    def description(self) -> str: ...

    @property
    @abc.abstractmethod
    def category(self) -> PluginCategory: ...

    @property
    def depends_on(self) -> list[str]:
        """Plugin names this plugin must run after.

        Return ``["*"]`` to run after *all* other plugins (policy-plugin
        convention — equivalent to the former hard-coded ``plugin.name == "opa"``
        check in the registry).  Return ``["plugin-a", "plugin-b"]`` to run
        after those specific plugins.  An empty list (the default) imposes no
        ordering constraint.
        """
        return []

    def skip_reason(self) -> tuple[str, str]:
        return ("Scanner prerequisites not met", "Check scanner documentation")

    @abc.abstractmethod
    def can_run(self, files: list[str], repo_path: Path) -> bool: ...

    @abc.abstractmethod
    def run(self, files: list[str], repo_path: Path) -> PluginResult: ...

    def render(
        self,
        result: PluginResult,
        template_dir: Path | None = None,
    ) -> str:
        """Render plugin result to markdown.

        Looks for ``{template_dir}/{plugin_name}.md.j2``.  If found the
        template is rendered via Jinja2 with the context produced by
        :meth:`_template_context`.  When no template file exists the call
        falls through to :meth:`_render_inline`.

        Findings are serialized to plain dicts here so the Jinja templates and
        the ``_template_context`` builders operate on dicts (the frozen typed
        ``PluginFinding`` is for the core paths, not the presentation layer).
        """
        result = result_with_dict_findings(result)
        tdir = template_dir if template_dir is not None else _TEMPLATES_DIR
        template_name = f"{self.name}.md.j2"
        tpath = tdir / template_name
        if tpath.exists():
            from jinja2 import Environment, FileSystemLoader

            env = Environment(
                loader=FileSystemLoader(str(tdir)),
                autoescape=False,  # nosemgrep: jinja2-autoescape-disabled
                keep_trailing_newline=True,
                trim_blocks=True,
                lstrip_blocks=True,
            )
            tmpl = env.get_template(template_name)
            ctx = self._template_context(result)
            return tmpl.render(**ctx)
        return self._render_inline(result)

    def _template_context(self, result: PluginResult) -> dict:
        """Return the Jinja2 template variable dict.

        Override in subclasses to inject plugin-specific pre-processed data
        (e.g. grouped findings, computed totals) alongside the base keys.
        """
        return {
            "result": result,
            "findings": result.findings,
            "summary": result.summary,
            "error": result.error,
            "plugin_name": result.plugin_name,
        }

    def _render_inline(self, result: PluginResult) -> str:
        """Inline fallback renderer used when no template file is found.

        Subclasses that ship Jinja2 templates rename their old ``render()``
        body to this method so it still serves as a fallback during development
        and testing.  Plugins without templates continue to override
        :meth:`render` directly.
        """
        return ""
