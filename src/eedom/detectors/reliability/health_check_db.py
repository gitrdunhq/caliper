"""Detector for health checks without DB verification (#184, #218).
# tested-by: tests/unit/detectors/reliability/test_health_check_db.py
"""

from __future__ import annotations

import ast
from pathlib import Path

from eedom.core.models import FindingSeverity
from eedom.detectors._registry import register_detector
from eedom.detectors.ast_utils import (
    parse_file_safe,
)
from eedom.detectors.categories import DetectorCategory
from eedom.detectors.findings import DetectorFinding
from eedom.detectors.framework import BugDetector


@register_detector
class HealthCheckDBDetector(BugDetector):
    """Detects health check endpoints without database connectivity verification.

    Reliability issue: Health checks that don't verify database connectivity
    can report "healthy" when the DB is actually down, leading to failed requests.

    GitHub: #184, #218
    """

    # Patterns indicating health check endpoints
    HEALTH_ENDPOINT_PATTERNS = (
        "health",
        "*health*",
        "ready",
        "*ready*",
        "alive",
        "*alive*",
        "status",
    )

    # Patterns indicating DB checks
    DB_CHECK_PATTERNS = (
        "SELECT 1",
        "select 1",
        "ping",
        "*.ping",
        "is_connected",
    )

    @property
    def detector_id(self) -> str:
        return "EED-011"

    @property
    def name(self) -> str:
        return "Health Check Without Database Verification"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.reliability

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.medium

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.py",)

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file for health check endpoints without DB verification."""
        tree = parse_file_safe(file_path)
        if not tree:
            return []

        findings = []

        # Find all function definitions
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # Check if it's a health check endpoint
            if not self._is_health_endpoint(node):
                continue

            # Check if it has DB verification
            if not self._has_db_verification(node):
                lineno = node.lineno
                if node.decorator_list:
                    lineno = node.decorator_list[0].lineno

                if self._should_report_finding(file_path, lineno):
                    findings.append(
                        DetectorFinding(
                            detector_id=self.detector_id,
                            detector_name=self.name,
                            category=self.category,
                            severity=self.severity,
                            file_path=str(file_path),
                            line_number=lineno,
                            message=f"Health check '{node.name}' missing database connectivity verification",
                            issue_reference="#184, #218",
                            fix_hint="Add DB connectivity check: cursor.execute('SELECT 1') or conn.ping()",
                        )
                    )

        return findings

    def _is_health_endpoint(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Check if function is a health check endpoint."""
        # Check decorators for health-related routes
        for decorator in node.decorator_list:
            dec_name = self._get_decorator_name(decorator)
            if dec_name:
                dec_lower = dec_name.lower()
                for pattern in ("health", "ready", "alive", "status"):
                    if pattern in dec_lower:
                        return True

            # Check for @app.get("/health") or @app.route("/health") patterns
            route_path = self._get_route_path(decorator)
            if route_path:
                path_lower = route_path.lower()
                for pattern in ("health", "ready", "alive", "status"):
                    if pattern in path_lower:
                        return True

        # Check function name
        func_name_lower = node.name.lower()
        for pattern in ("health", "ready", "alive", "status"):
            if pattern in func_name_lower:
                # Check if it has route decorator
                for decorator in node.decorator_list:
                    dec_name = self._get_decorator_name(decorator)
                    if dec_name and (
                        "route" in dec_name.lower()
                        or dec_name.lower() in ("get", "post", "put", "patch")
                    ):
                        return True

        return False

    def _get_route_path(self, decorator: ast.expr) -> str | None:
        """Extract route path from decorator like @app.get('/health')."""
        # Handle @decorator("/path") or @decorator(path="/path")
        if isinstance(decorator, ast.Call):
            # Check positional args
            for arg in decorator.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    return arg.value
            # Check keyword args
            for kw in decorator.keywords:
                if kw.arg in ("path", "rule"):
                    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        return kw.value.value
        return None

    def _has_db_verification(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Check if health check has database verification."""
        for child in ast.walk(node):
            # Look for DB execute calls with "SELECT 1"
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name:
                    if "execute" in call_name.lower():
                        # Check if first arg contains SELECT 1
                        if child.args:
                            arg_str = self._get_string_content(child.args[0])
                            if arg_str and ("select 1" in arg_str.lower() or "SELECT 1" in arg_str):
                                return True

                    # Check for ping or is_connected calls
                    if any(x in call_name.lower() for x in ("ping", "is_connected")):
                        return True

        return False

    def _get_decorator_name(self, decorator: ast.expr) -> str | None:
        """Extract name from decorator node."""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            parts = []
            node = decorator
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
                return ".".join(reversed(parts))
        elif isinstance(decorator, ast.Call):
            return self._get_decorator_name(decorator.func)
        return None

    def _get_call_name(self, call: ast.Call) -> str | None:
        """Extract full call name."""
        if isinstance(call.func, ast.Attribute):
            if isinstance(call.func.value, ast.Name):
                return f"{call.func.value.id}.{call.func.attr}"
            return call.func.attr
        elif isinstance(call.func, ast.Name):
            return call.func.id
        return None

    def _get_string_content(self, node: ast.AST) -> str | None:
        """Extract string content from AST node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None
