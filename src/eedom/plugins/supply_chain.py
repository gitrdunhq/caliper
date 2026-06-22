"""Supply chain plugin — unpinned deps + lockfile integrity + Docker latest-tag detection.
# tested-by: tests/unit/test_supply_chain_latest.py

Pure Python — no external binary needed.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import structlog
import yaml

from eedom.core.file_source import select_file_source
from eedom.core.plugin import PluginCategory, PluginResult, ScannerPlugin

logger = structlog.get_logger(__name__)

_LOCKFILE_TO_MANIFEST: dict[str, list[str]] = {
    "package-lock.json": ["package.json"],
    "yarn.lock": ["package.json"],
    "pnpm-lock.yaml": ["package.json"],
    "uv.lock": ["pyproject.toml"],
    "poetry.lock": ["pyproject.toml"],
    "Pipfile.lock": ["Pipfile"],
    "Cargo.lock": ["Cargo.toml"],
    "go.sum": ["go.mod"],
    "Gemfile.lock": ["Gemfile"],
    "composer.lock": ["composer.json"],
}

# Matches: FROM [--platform=...] <image> [AS <stage>]
# Group 1: image reference (everything between FROM/platform flag and optional AS clause)
_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--\S+\s+)?(\S+)(?:\s+AS\s+\S+)?\s*$",
    re.IGNORECASE,
)


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _is_dockerfile(name: str) -> bool:
    """Return True for Dockerfile* or *.dockerfile file names."""
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".dockerfile")


def _is_compose(name: str) -> bool:
    """Return True for docker-compose*.yml / docker-compose*.yaml file names."""
    return (
        name.startswith("docker-compose") or name == "compose.yml" or name == "compose.yaml"
    ) and (name.endswith(".yml") or name.endswith(".yaml"))


def _image_is_floating(image: str) -> bool:
    """Return True if *image* resolves to an uncontrolled (latest-equivalent) tag.

    Pinned forms that are NOT floating:
      - foo:1.2.3          explicit semver-like tag
      - foo@sha256:<hex>   digest pin

    Floating forms:
      - foo                no tag at all (implicit latest)
      - foo:latest         explicit latest
    """
    if "@" in image:
        # digest-pinned — always safe
        return False
    if ":" in image:
        tag = image.split(":", 1)[1]
        return tag == "latest"
    # no tag separator → implicit latest
    return True


class SupplyChainPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "supply-chain"

    @property
    def description(self) -> str:
        return "Unpinned dependency detection + lockfile integrity + Docker latest-tag detection"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.supply_chain

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        names = {Path(f).name for f in files}
        manifests = {
            "package.json",
            "requirements.txt",
            "pyproject.toml",
            "Cargo.toml",
            "go.mod",
            "Gemfile",
            "composer.json",
        }
        locks = set(_LOCKFILE_TO_MANIFEST.keys())
        if names & (manifests | locks):
            return True
        return any(_is_dockerfile(n) or _is_compose(n) for n in names)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        findings: list[dict] = []
        findings.extend(self._check_unpinned(repo_path))
        findings.extend(self._check_lockfiles(files, repo_path))

        for f in files:
            p = Path(f)
            full = repo_path / p if not p.is_absolute() else p
            try:
                full.resolve().relative_to(repo_path.resolve())
            except ValueError:
                logger.warning("supply_chain.path_traversal_blocked", file=f)
                continue
            if _is_dockerfile(p.name):
                findings.extend(self._check_dockerfile_latest(str(full)))
            elif _is_compose(p.name):
                findings.extend(self._check_compose_latest(str(full)))

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={
                "unpinned": sum(1 for f in findings if f.get("type") == "unpinned"),
                "lockfile_issues": sum(1 for f in findings if f.get("type") == "lockfile"),
                "docker_latest": sum(1 for f in findings if f.get("type") == "docker_latest"),
            },
        )

    # ── Dockerfile ────────────────────────────────────────────────────────────

    def _check_dockerfile_latest(self, file_path: str) -> list[dict]:
        """Scan a Dockerfile for FROM lines that resolve to an implicit or explicit latest tag."""
        findings: list[dict] = []
        try:
            lines = Path(file_path).read_text().splitlines()
        except OSError:
            return findings

        for lineno, raw in enumerate(lines, start=1):
            m = _FROM_RE.match(raw)
            if not m:
                continue
            image = m.group(1)
            # Skip scratch (no meaningful tag concept) and ARG-based references
            if image.lower() == "scratch" or image.startswith("$"):
                continue
            if _image_is_floating(image):
                findings.append(
                    {
                        "type": "docker_latest",
                        "file": file_path,
                        "line": lineno,
                        "severity": "medium",
                        "description": (
                            f"Dockerfile FROM uses floating image `{image}` — "
                            "pin to a specific digest or version tag"
                        ),
                    }
                )

        return findings

    # ── Docker Compose ────────────────────────────────────────────────────────

    def _check_compose_latest(self, file_path: str) -> list[dict]:
        """Scan a Docker Compose file for service images that resolve to latest."""
        findings: list[dict] = []
        try:
            raw = Path(file_path).read_text()
            data = yaml.safe_load(raw)
        except (OSError, yaml.YAMLError):
            return findings

        if not isinstance(data, dict):
            return findings

        services = data.get("services") or {}
        if not isinstance(services, dict):
            return findings

        for _svc_name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            image = svc.get("image")
            if not image or not isinstance(image, str):
                continue
            if _image_is_floating(image):
                findings.append(
                    {
                        "type": "docker_latest",
                        "file": file_path,
                        "service": _svc_name,
                        "severity": "medium",
                        "description": (
                            f"Compose service `{_svc_name}` uses floating image `{image}` — "
                            "pin to a specific digest or version tag"
                        ),
                    }
                )

        return findings

    # ── Unpinned deps ─────────────────────────────────────────────────────────

    def _check_unpinned(self, repo: Path) -> list[dict]:
        findings: list[dict] = []

        # Enumerate once through the file source; ignore rules (node_modules,
        # .venv, .eedomignore, …) replace the old ad-hoc segment filter.
        all_files = select_file_source(repo).list_files(repo)
        package_jsons = [p for p in all_files if p.name == "package.json"]
        requirement_files = [
            p for p in all_files if p.name.startswith("requirements") and p.suffix == ".txt"
        ]

        for pkg in package_jsons:
            rel = str(pkg.relative_to(repo))
            try:
                data = json.loads(pkg.read_text())
                for section in ("dependencies", "devDependencies"):
                    for name, ver in data.get(section, {}).items():
                        if self._is_floating_npm(ver):
                            findings.append(
                                {
                                    "type": "unpinned",
                                    "file": rel,
                                    "package": name,
                                    "version": ver,
                                    "ecosystem": "npm",
                                    "reason": self._npm_reason(ver),
                                    "severity": self._unpinned_severity_npm(ver),
                                }
                            )
            except (OSError, ValueError) as exc:
                logger.debug("supply_chain.manifest_parse_error", error=str(exc))

        for req in requirement_files:
            try:
                for line in req.read_text().split("\n"):
                    line = line.strip()
                    if not line or line.startswith(("#", "-")):
                        continue
                    m = re.match(r"^([A-Za-z0-9][\w.-]*)(.*)?$", line)
                    if not m:
                        continue
                    spec = (m.group(2) or "").strip()
                    if self._is_floating_py(spec):
                        findings.append(
                            {
                                "type": "unpinned",
                                "file": req.name,
                                "package": m.group(1),
                                "version": spec or "(no version)",
                                "ecosystem": "pypi",
                                "reason": self._py_reason(spec),
                                "severity": self._unpinned_severity_py(spec),
                            }
                        )
            except OSError as exc:
                logger.debug("supply_chain.requirements_read_error", file=str(req), error=str(exc))

        return findings

    def _check_lockfiles(
        self,
        files: list[str],
        repo: Path,
    ) -> list[dict]:
        findings: list[dict] = []
        changed_names = {Path(f).name for f in files}
        changed_dirs: dict[str, set[str]] = {}
        for f in files:
            p = Path(f)
            parent = str(p.parent)
            changed_dirs.setdefault(parent, set()).add(p.name)

        for lock, manifests in _LOCKFILE_TO_MANIFEST.items():
            if lock not in changed_names:
                continue
            lock_dirs = [d for d, names in changed_dirs.items() if lock in names]
            for lock_dir in lock_dirs:
                dir_files = changed_dirs.get(lock_dir, set())
                manifest_changed = any(m in dir_files for m in manifests)
                # Per-directory check: this must stay INSIDE the loop, else only the
                # last lock_dir is evaluated and monorepo findings are silently lost.
                if not manifest_changed:
                    findings.append(
                        {
                            "type": "lockfile",
                            "lockfile": lock,
                            "severity": "high",
                            "sha256": _sha256(Path(lock_dir) / lock),
                            "message": (f"`{lock}` changed but {'/'.join(manifests)} did NOT"),
                        }
                    )

        for manifest in [
            "package.json",
            "pyproject.toml",
            "Cargo.toml",
            "go.mod",
        ]:
            if manifest not in changed_names:
                continue
            expected = [lf for lf, ms in _LOCKFILE_TO_MANIFEST.items() if manifest in ms]
            manifest_dirs = [d for d, names in changed_dirs.items() if manifest in names]
            for lf in expected:
                for manifest_dir in manifest_dirs:
                    if (
                        lf not in changed_dirs.get(manifest_dir, set())
                        and (Path(manifest_dir) / lf).exists()
                    ):
                        findings.append(
                            {
                                "type": "lockfile",
                                "lockfile": lf,
                                "severity": "medium",
                                "sha256": _sha256(Path(manifest_dir) / lf),
                                "message": (f"`{manifest}` changed but `{lf}` was NOT updated"),
                            }
                        )

        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _is_floating_npm(v: str) -> bool:
        return bool(v.startswith(("^", "~", ">=", ">")) or v in ("*", "latest", "") or " || " in v)

    @staticmethod
    def _npm_reason(v: str) -> str:
        if v.startswith("^"):
            return "caret range — allows minor+patch"
        if v.startswith("~"):
            return "tilde range — allows patch"
        if v.startswith((">=", ">")):
            return "open range — any newer version"
        if v in ("*", "latest", ""):
            return "completely unpinned"
        return "floating range"

    @staticmethod
    def _unpinned_severity_npm(v: str) -> str:
        if v in ("*", "latest", ""):
            return "critical"
        return "high"

    @staticmethod
    def _unpinned_severity_py(spec: str) -> str:
        if not spec:
            return "critical"
        return "high"

    @staticmethod
    def _is_floating_py(spec: str) -> bool:
        if not spec:
            return True
        if spec.startswith((">=", "~=")):
            return True
        return "==" in spec and "*" in spec

    @staticmethod
    def _py_reason(spec: str) -> str:
        if not spec:
            return "no version — installs latest"
        if spec.startswith(">="):
            return "minimum bound only — no upper cap"
        if spec.startswith("~="):
            return "compatible release — allows patch"
        return "floating range"

    # ── Render ────────────────────────────────────────────────────────────────

    def _template_context(self, result: PluginResult) -> dict:
        ctx = super()._template_context(result)
        ctx["unpinned"] = [f for f in result.findings if f.get("type") == "unpinned"]
        ctx["locks"] = [f for f in result.findings if f.get("type") == "lockfile"]
        ctx["docker"] = [f for f in result.findings if f.get("type") == "docker_latest"]
        return ctx

    def _render_inline(
        self,
        result: PluginResult,
    ) -> str:
        if result.error:
            return f"**supply-chain**: {result.error}"

        unpinned = [f for f in result.findings if f.get("type") == "unpinned"]
        locks = [f for f in result.findings if f.get("type") == "lockfile"]
        docker = [f for f in result.findings if f.get("type") == "docker_latest"]
        lines: list[str] = []

        if unpinned:
            lines.append("<details open>")
            lines.append(f"<summary>📌 <b>Unpinned Dependencies ({len(unpinned)})</b></summary>\n")
            lines.append("| Package | Version | Ecosystem | Risk |")
            lines.append("|---------|---------|-----------|------|")
            for u in unpinned:
                lines.append(
                    f"| `{u['package']}` | `{u['version']}` | {u['ecosystem']} | {u['reason']} |"
                )
            lines.append("\n</details>\n")

        if locks:
            lines.append("<details open>")
            lines.append("<summary>🔒 <b>Lockfile Integrity</b></summary>\n")
            for lf in locks:
                icon = "🔴" if lf["severity"] == "high" else "🟡"
                lines.append(f"{icon} {lf['message']}")
                sha = lf.get("sha256", "")
                if sha:
                    lines.append(f"> SHA256: `{sha[:16]}...`\n")
            lines.append("</details>\n")

        if docker:
            lines.append("<details open>")
            lines.append(
                f"<summary>🐳 <b>Docker Floating Image Tags ({len(docker)})</b></summary>\n"
            )
            lines.append("| File | Description |")
            lines.append("|------|-------------|")
            for d in docker:
                fname = Path(d["file"]).name
                lines.append(f"| `{fname}` | {d['description']} |")
            lines.append("\n</details>\n")

        return "\n".join(lines)


from eedom.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("supply-chain")
def build_supply_chain_plugin() -> SupplyChainPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return SupplyChainPlugin()
