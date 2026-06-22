# tested-by: tests/unit/detectors/test_registry.py
"""Detector discovery on the generic Registry (folds the 3rd registry in).

Replaces the bespoke ``DetectorRegistry`` singleton with the shared
``eedom.registry.Registry[T]`` primitive plus thin domain helpers. Detectors
self-register with the ``@register_detector`` decorator (deriving their
``detector_id``); ``discover_detectors`` recursively imports the
``eedom.detectors`` subpackages so those decorators run.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

from eedom.registry import Registry

if TYPE_CHECKING:
    from eedom.core.models import FindingSeverity
    from eedom.detectors.categories import DetectorCategory
    from eedom.detectors.framework import BugDetector

# The single registry of detector factories, keyed by detector_id.
DETECTORS: Registry[BugDetector] = Registry("detector")

_DISCOVERY_ROOT = "eedom.detectors"
_discovered = False

# Detectors are stateless, so instances are cached and shared (parity with the
# previous singleton registry; the scanner resolves the full set per file).
_instances: dict[str, BugDetector] = {}


def _derive_detector_id(detector_class: type) -> str:
    """Resolve a detector's id without a full instantiation when possible."""
    try:
        return detector_class.detector_id.fget(None)  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        try:
            return detector_class().detector_id
        except Exception:
            return detector_class.__name__


def register_detector(detector_class: type) -> type:
    """Class decorator: register *detector_class* under its detector_id."""
    detector_id = _derive_detector_id(detector_class)
    DETECTORS.register(detector_id)(lambda: detector_class())
    _instances.pop(detector_id, None)  # drop any stale cached instance
    return detector_class


def _resolve(detector_id: str) -> BugDetector | None:
    """Create (and cache) a single detector instance by id."""
    cached = _instances.get(detector_id)
    if cached is not None:
        return cached
    try:
        instance = DETECTORS.create(detector_id)
    except Exception:
        return None
    _instances[detector_id] = instance
    return instance


def discover_detectors(package_name: str = _DISCOVERY_ROOT, *, _is_root: bool = True) -> None:
    """Recursively import detector subpackages so registrations run (idempotent)."""
    global _discovered
    if _is_root and _discovered:
        return
    try:
        package = importlib.import_module(package_name)
    except ImportError:
        return
    for _, name, is_pkg in pkgutil.iter_modules(package.__path__, package_name + "."):
        try:
            importlib.import_module(name)
        except ImportError:
            continue
        if is_pkg:
            discover_detectors(name, _is_root=False)
    if _is_root:
        _discovered = True


def get_detector(detector_id: str) -> BugDetector | None:
    """Return a cached detector instance by id, or None when unknown."""
    if detector_id not in DETECTORS:
        return None
    return _resolve(detector_id)


def get_all_detectors() -> list[BugDetector]:
    """Return one (cached) instance of every registered detector."""
    out: list[BugDetector] = []
    detector_ids = DETECTORS.keys()
    for detector_id in detector_ids:
        instance = _resolve(detector_id)
        if instance is not None:
            out.append(instance)
    return out


def get_by_category(category: DetectorCategory) -> list[BugDetector]:
    return [d for d in get_all_detectors() if d.category == category]


def get_by_severity(severity: FindingSeverity) -> list[BugDetector]:
    return [d for d in get_all_detectors() if d.severity == severity]


def clear_detectors() -> None:
    """Reset the registry, instance cache, and rediscovery flag (test isolation)."""
    global _discovered
    DETECTORS.clear()
    _instances.clear()
    _discovered = False
