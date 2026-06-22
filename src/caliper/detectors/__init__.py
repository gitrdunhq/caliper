"""Bug detector framework for caliper.
# tested-by: tests/unit/detectors/test_framework.py

Provides the BugDetector base class and supporting infrastructure for
AST-based static analysis of code to detect bugs across security,
reliability, configuration, and process domains.
"""

from __future__ import annotations

from caliper.detectors._registry import (
    DETECTORS,
    clear_detectors,
    discover_detectors,
    get_all_detectors,
    get_by_category,
    get_by_severity,
    get_detector,
    register_detector,
)
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding
from caliper.detectors.framework import BugDetector
from caliper.detectors.scanner import DeterministicScanner

__all__ = [
    "DETECTORS",
    "BugDetector",
    "DetectorCategory",
    "DetectorFinding",
    "DeterministicScanner",
    "clear_detectors",
    "discover_detectors",
    "get_all_detectors",
    "get_by_category",
    "get_by_severity",
    "get_detector",
    "register_detector",
]
