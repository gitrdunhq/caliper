"""CAL-022: Config-driven architecture tier-boundary detector.
# tested-by: tests/unit/detectors/security/test_tier_boundary.py

Generalizes the enforced-layering pattern that guards caliper's own tiers
(``core/tier_map.py``, ``tests/unit/test_deterministic_architecture_guards.py``)
into a detector any scanned repo can opt into via ``.caliper.yaml``:

    architecture:
      package: myapp
      src_root: src/myapp
      tiers:
        api: presentation
        core: core
        db: data
      allow:
        presentation: [presentation, core, kernel]
        core: [core, kernel]
        data: [data, core, kernel]

Unconfigured (no ``architecture.tiers``/``package``/``src_root``) means this
detector never fires -- caliper never fabricates a layering the repo did not
declare (fail-open).
"""

from __future__ import annotations

import ast
from pathlib import Path

from caliper.core.models import FindingSeverity
from caliper.core.repo_config import RepoConfig, load_repo_config
from caliper.core.tier_map import imported_caliper_modules, kernel_modules, source_tier, target_tier
from caliper.detectors._registry import register_detector
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding
from caliper.detectors.framework import BugDetector

_CONFIG_FILENAME = ".caliper.yaml"
_MAX_WALK_UP = 25  # bounded ancestor search -- never walks past a reasonable repo depth


def _find_repo_root(file_path: Path) -> Path | None:
    """Walk upward from *file_path* looking for ``.caliper.yaml``.

    Bounded and fail-open: returns ``None`` (never raises) when nothing is
    found within ``_MAX_WALK_UP`` ancestor directories.
    """
    current = file_path.resolve().parent
    for _ in range(_MAX_WALK_UP):
        if (current / _CONFIG_FILENAME).exists():
            return current
        if current.parent == current:
            break
        current = current.parent
    return None


@register_detector
class TierBoundaryDetector(BugDetector):
    """Flags imports that cross a repo-declared architecture tier boundary.

    Config-driven twin of the guard test that protects caliper's own
    src/caliper tiers -- opt-in for any scanned repo via ``architecture:`` in
    ``.caliper.yaml``. No config -> no findings (never invents a layering).
    """

    def __init__(self) -> None:
        self._config_cache: dict[Path, RepoConfig | None] = {}
        self._repo_root_cache: dict[Path, Path | None] = {}

    @property
    def detector_id(self) -> str:
        return "CAL-022"

    @property
    def name(self) -> str:
        return "Architecture Tier Boundary Violation"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.security

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.medium

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.py",)

    def _repo_root_for(self, file_path: Path) -> Path | None:
        parent = file_path.resolve().parent
        if parent not in self._repo_root_cache:
            self._repo_root_cache[parent] = _find_repo_root(file_path)
        return self._repo_root_cache[parent]

    def _load_config(self, repo_root: Path) -> RepoConfig | None:
        if repo_root not in self._config_cache:
            try:
                self._config_cache[repo_root] = load_repo_config(repo_root)
            except Exception:
                self._config_cache[repo_root] = None
        return self._config_cache[repo_root]

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Flag imports that cross a repo-declared tier boundary.

        Returns an empty list when: no ``.caliper.yaml`` is found above the
        file, ``architecture.tiers``/``package``/``src_root`` are unset, the
        file cannot be read/parsed, or it sits outside the configured
        ``src_root``.
        """
        try:
            repo_root = self._repo_root_for(file_path)
            if repo_root is None:
                return []

            config = self._load_config(repo_root)
            if config is None:
                return []

            arch = config.architecture
            if not arch.tiers or not arch.package or not arch.src_root:
                return []

            src_root = (repo_root / arch.src_root).resolve()
            resolved = file_path.resolve()
            resolved.relative_to(src_root)  # raises ValueError outside src_root

            src_tier = source_tier(resolved, src_root, arch.tiers)
            if src_tier is None:
                return []

            content = file_path.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(file_path))
        except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
            return []

        # Default-deny: a tier omitted from `allow` may only import itself, so
        # a half-configured allow-set never becomes silently permissive.
        allowed = set(arch.allow.get(src_tier, [src_tier]))
        kernel_mods = kernel_modules(src_root)

        findings: list[DetectorFinding] = []
        for module, lineno in imported_caliper_modules(
            tree, resolved, src_root, package_name=arch.package
        ):
            tgt_tier = target_tier(module, arch.tiers, kernel_mods, package_name=arch.package)
            if tgt_tier not in allowed:
                findings.append(
                    DetectorFinding(
                        detector_id=self.detector_id,
                        detector_name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=str(file_path),
                        line_number=lineno,
                        message=(
                            f"Import crosses a declared architecture boundary: "
                            f"{src_tier} tier importing {tgt_tier} tier ({module})."
                        ),
                    )
                )
        return findings
