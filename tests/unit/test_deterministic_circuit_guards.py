"""Deterministic guards for circuit breaker implementation — Issue #201 / Parent #167.

These tests verify that the circuit breaker pattern has a proper half-open state,
allowing the system to recover gracefully after failures.

#201: Add deterministic rule for #167: Circuit breaker doesn't have half-open state
#167: Circuit breaker missing half-open state for recovery
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import ClassVar

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SOLVER_PATH = _ROOT / "src" / "caliper" / "core" / "solver.py"


class CircuitBreakerVisitor(ast.NodeVisitor):
    """AST visitor to detect circuit breaker patterns and check for half-open state."""

    CIRCUIT_BREAKER_INDICATORS: ClassVar[list[str]] = [
        "retry",
        "backoff",
        "failure",
        "error",
        "state",
        "open",
        "closed",
        "breaker",
    ]

    HALF_OPEN_INDICATORS: ClassVar[list[str]] = [
        "half",
        "half_open",
        "HALF",
        "HALF_OPEN",
        "probe",
        "recovery",
        "canary",
        "test_request",
    ]

    def __init__(self) -> None:
        self.has_circuit_breaker_pattern = False
        self.has_half_open_state = False
        self.state_enum_found = False
        self.state_class_found = False
        self.failure_tracking_found = False
        self.retry_with_state_found = False
        self.half_open_evidence: list[str] = []
        self.circuit_breaker_evidence: list[str] = []

    def _is_indicator(self, name: str, indicators: list[str]) -> bool:
        """Check if a name contains any of the indicators."""
        name_lower = name.lower()
        return any(indicator.lower() in name_lower for indicator in indicators)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        """Look for state classes or enums that might indicate circuit breaker."""
        class_name = node.name

        # Check for state machine classes
        if self._is_indicator(class_name, ["state", "breaker", "circuit"]):
            self.circuit_breaker_evidence.append(f"Class: {class_name}")
            self._check_class_for_half_open(node, class_name)

        self.generic_visit(node)

    def _check_class_for_half_open(self, node: ast.ClassDef, class_name: str) -> None:
        """Check if a class/enum has half-open state indicators."""
        for item in node.body:
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name):
                        name = target.id
                        if self._is_indicator(name, self.HALF_OPEN_INDICATORS):
                            self.has_half_open_state = True
                            self.half_open_evidence.append(f"{class_name}.{name}")

            elif isinstance(item, ast.AnnAssign):
                if isinstance(item.target, ast.Name):
                    name = item.target.id
                    if self._is_indicator(name, self.HALF_OPEN_INDICATORS):
                        self.has_half_open_state = True
                        self.half_open_evidence.append(f"{class_name}.{name}")

            # Check for enum-style class attributes
            elif isinstance(item, ast.Expr):
                if isinstance(item.value, ast.Constant) and isinstance(item.value.value, str):
                    val = item.value.value
                    if self._is_indicator(val, self.HALF_OPEN_INDICATORS):
                        self.has_half_open_state = True
                        self.half_open_evidence.append(f"{class_name}.{val}")

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        """Look for functions with circuit breaker patterns."""
        func_name = node.name

        # Check for retry/circuit breaker function names
        if self._is_indicator(func_name, ["retry", "breaker", "circuit", "backoff"]):
            self.circuit_breaker_evidence.append(f"Function: {func_name}")
            self._check_function_for_state_handling(node)

        self.generic_visit(node)

    def _check_function_for_state_handling(self, node: ast.FunctionDef) -> None:
        """Check if function handles different states including half-open."""
        source = ast.unparse(node)

        # Check for circuit breaker pattern indicators
        if any(ind in source.lower() for ind in ["state", "failure", "count", "open", "close"]):
            self.failure_tracking_found = True

        # Check for half-open handling
        for indicator in self.HALF_OPEN_INDICATORS:
            if indicator.lower() in source.lower():
                self.has_half_open_state = True
                self.half_open_evidence.append(f"Function {node.name}: {indicator}")

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
        """Track variable names that indicate circuit breaker patterns."""
        name = node.id

        if self._is_indicator(name, self.CIRCUIT_BREAKER_INDICATORS):
            if name not in [e.split(": ")[-1] for e in self.circuit_breaker_evidence]:
                self.circuit_breaker_evidence.append(f"Name: {name}")

        if self._is_indicator(name, self.HALF_OPEN_INDICATORS):
            if name not in [e.split(": ")[-1] for e in self.half_open_evidence]:
                self.half_open_evidence.append(f"Name: {name}")
                self.has_half_open_state = True

        self.generic_visit(node)


class TestCircuitBreakerHalfOpenState:
    """Tests for Issue #167: Circuit breaker missing half-open state.

    The solver module implements retry logic with exponential backoff, but
    lacks a proper circuit breaker pattern with half-open state. Without
    half-open state, the system cannot gracefully recover after failures.
    """

    @pytest.mark.xfail(reason="deterministic bug detector for #167", strict=False)
    def test_solver_has_circuit_breaker_with_half_open_state(self) -> None:
        """Detect missing half-open state in circuit breaker implementation.

        Expected behavior: A proper circuit breaker has three states:
        - CLOSED: Normal operation, requests pass through
        - OPEN: Failure threshold exceeded, requests fail fast
        - HALF_OPEN: Testing if service has recovered (probe requests)

        Bug #167: The retry logic in solver.py lacks a half-open state,
        meaning after max_retries failures, there's no graceful recovery path.
        The system either keeps retrying forever or fails permanently.

        This test uses AST analysis to verify that the circuit breaker
        implementation includes half-open state handling.
        """
        if not _SOLVER_PATH.exists():
            pytest.skip(f"Solver file not found: {_SOLVER_PATH}")

        source = _SOLVER_PATH.read_text(encoding="utf-8")

        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            pytest.fail(f"Failed to parse solver.py: {e}")

        visitor = CircuitBreakerVisitor()
        visitor.visit(tree)

        # Check if we found circuit breaker patterns
        has_retry_logic = "retry" in source.lower() or "backoff" in source.lower()
        has_max_retries = "max_retries" in source.lower()

        # The solver has retry/backoff logic that constitutes a circuit breaker pattern
        if has_retry_logic and has_max_retries:
            visitor.has_circuit_breaker_pattern = True

        # Now verify it has half-open state
        evidence_str = "\n".join(f"  - {e}" for e in visitor.circuit_breaker_evidence[:5])
        assert visitor.has_half_open_state, (
            "Circuit breaker implementation missing half-open state.\n\n"
            "Found circuit breaker pattern (retry/backoff with max_retries), "
            "but no half-open state detected.\n\n"
            "Evidence of circuit breaker:\n" + evidence_str + "\n\n"
            "Missing: Half-open state (HALF_OPEN, probe, recovery, canary, test_request)\n\n"
            "Bug #167: The solver retries with exponential backoff but lacks a "
            "half-open state for graceful recovery. After failures, the system "
            "cannot probe whether the service has recovered."
        )

    @pytest.mark.xfail(reason="deterministic bug detector for #167", strict=False)
    def test_circuit_breaker_has_state_enum_or_class(self) -> None:
        """Detect if circuit breaker uses proper state machine pattern.

        A robust circuit breaker should use a state machine (enum or class)
        to track its state through CLOSED → OPEN → HALF_OPEN transitions.
        """
        if not _SOLVER_PATH.exists():
            pytest.skip(f"Solver file not found: {_SOLVER_PATH}")

        source = _SOLVER_PATH.read_text(encoding="utf-8")

        # Look for state-related constructs
        has_state_enum = "Enum" in source and any(
            state in source for state in ["CLOSED", "OPEN", "HALF"]
        )
        has_state_class = "class" in source and any(
            state in source for state in ["State", "Breaker"]
        )

        # Look specifically for half-open in state definitions
        has_half_open_in_enum = any(
            pattern in source
            for pattern in [
                "HALF_OPEN",
                "HalfOpen",
                '"half"',
                "'half'",
                "State.HALF",
            ]
        )

        # If we have state machine constructs, they should include half-open
        if has_state_enum or has_state_class:
            assert has_half_open_in_enum, (
                "State machine found but missing HALF_OPEN state.\n\n"
                "Circuit breaker state machine should have:\n"
                "  - CLOSED: Normal operation\n"
                "  - OPEN: Fail-fast mode\n"
                "  - HALF_OPEN: Testing recovery (MISSING)\n\n"
                "Bug #167: Without HALF_OPEN, the breaker cannot transition "
                "back to CLOSED gracefully."
            )

    @pytest.mark.xfail(reason="deterministic bug detector for #167", strict=False)
    def test_retry_function_checks_half_open_before_retrying(self) -> None:
        """Detect if retry logic checks half-open state before attempting.

        In a proper circuit breaker, before making a request, the code should
        check if the breaker is in half-open state and handle it specially.
        """
        if not _SOLVER_PATH.exists():
            pytest.skip(f"Solver file not found: {_SOLVER_PATH}")

        source = _SOLVER_PATH.read_text(encoding="utf-8")

        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            pytest.fail(f"Failed to parse solver.py: {e}")

        # Find the _try_model function which has the retry loop
        has_half_open_check = False
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_try_model":
                func_source = ast.unparse(node)
                # Check for half-open state handling
                half_open_checks = [
                    "half",
                    "probe",
                    "canary",
                    "test_request",
                    "recovery",
                ]
                has_half_open_check = any(
                    check in func_source.lower() for check in half_open_checks
                )
                break

        # The _try_model function should have half-open handling
        assert has_half_open_check, (
            "The _try_model retry function lacks half-open state checking.\n\n"
            "Expected: Before retrying, check if in half-open state and:\n"
            "  - Send a probe/canary request\n"
            "  - On success: transition to CLOSED\n"
            "  - On failure: stay in OPEN and reset timeout\n\n"
            "Bug #167: Without half-open checks, the retry logic cannot "
            "gracefully recover from failure states."
        )
