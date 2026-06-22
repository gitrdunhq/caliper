"""Tests for AST utility functions and visitor pattern batching.
# tested-by: tests/unit/detectors/test_ast_utils.py

RED phase tests for Task 1.3: AST Utilities.
"""

from __future__ import annotations

import ast
import tempfile
from pathlib import Path

# These imports will fail during RED phase
from eedom.detectors.ast_utils import (
    ASTCache,
    BatchVisitor,
    contains_string_formatting,
    find_assignments,
    find_function_calls,
    get_annotation_text,
    get_call_name,
    get_decorators,
    get_import_aliases,
    has_decorator,
    has_function_call,
    has_import,
    is_cache_related_name,
    is_path_related_name,
    is_plain_type,
    is_secret_field_name,
    matches_pattern,
    parse_file_safe,
)

# =============================================================================
# parse_file_safe Tests
# =============================================================================


class TestParseFileSafe:
    """Tests for parse_file_safe function."""

    def test_parses_valid_python(self):
        """parse_file_safe returns AST for valid Python file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("x = 1\n")
            f.flush()

            result = parse_file_safe(Path(f.name))
            assert result is not None
            assert isinstance(result, ast.Module)

    def test_returns_none_for_invalid_python(self):
        """parse_file_safe returns None for invalid Python syntax."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("invalid syntax {{{\n")
            f.flush()

            result = parse_file_safe(Path(f.name))
            assert result is None

    def test_returns_none_for_nonexistent_file(self):
        """parse_file_safe returns None for non-existent file."""
        result = parse_file_safe(Path("/nonexistent/file.py"))
        assert result is None


# =============================================================================
# Function Call Detection Tests
# =============================================================================


class TestFindFunctionCalls:
    """Tests for find_function_calls function."""

    def test_finds_simple_function_call(self):
        """find_function_calls finds simple function calls."""
        code = "foo()"
        tree = ast.parse(code)

        results = find_function_calls(tree, "foo")
        assert len(results) == 1
        assert isinstance(results[0][0], ast.Call)
        assert results[0][1] == 1  # line number

    def test_finds_dotted_function_call(self):
        """find_function_calls finds dotted function calls like jwt.encode."""
        code = "jwt.encode({}, 'secret')"
        tree = ast.parse(code)

        results = find_function_calls(tree, "jwt.encode")
        assert len(results) == 1

    def test_finds_wildcard_pattern(self):
        """find_function_calls supports wildcard patterns like '*.execute'."""
        code = """
cursor.execute("SELECT * FROM t")
conn.execute("INSERT INTO t VALUES (1)")
"""
        tree = ast.parse(code)

        results = find_function_calls(tree, "*.execute")
        assert len(results) == 2

    def test_returns_line_numbers(self):
        """find_function_calls returns correct line numbers."""
        code = """x = 1
jwt.encode({}, 'secret')
y = 2
"""
        tree = ast.parse(code)

        results = find_function_calls(tree, "jwt.encode")
        assert len(results) == 1
        assert results[0][1] == 2  # Line 2

    def test_returns_empty_list_when_no_matches(self):
        """find_function_calls returns empty list when no matches."""
        code = "foo()"
        tree = ast.parse(code)

        results = find_function_calls(tree, "bar")
        assert results == []


class TestHasFunctionCall:
    """Tests for has_function_call function."""

    def test_returns_true_when_call_present(self):
        """has_function_call returns True when call is present."""
        code = "jwt.encode({}, 'secret')"
        tree = ast.parse(code)

        assert has_function_call(tree, "jwt.encode") is True

    def test_returns_false_when_call_absent(self):
        """has_function_call returns False when call is absent."""
        code = "foo()"
        tree = ast.parse(code)

        assert has_function_call(tree, "jwt.encode") is False


class TestGetCallName:
    """Tests for get_call_name function."""

    def test_gets_simple_name(self):
        """get_call_name returns simple name for direct calls."""
        code = "foo()"
        tree = ast.parse(code)
        call_node = tree.body[0].value  # type: ignore

        assert get_call_name(call_node) == "foo"

    def test_gets_dotted_name(self):
        """get_call_name returns full dotted name for attribute calls."""
        code = "jwt.encode({}, 'secret')"
        tree = ast.parse(code)
        call_node = tree.body[0].value  # type: ignore

        assert get_call_name(call_node) == "jwt.encode"

    def test_returns_none_for_non_call(self):
        """get_call_name returns None for non-Call nodes."""
        code = "x = 1"
        tree = ast.parse(code)

        assert get_call_name(tree) is None


# =============================================================================
# Decorator Detection Tests
# =============================================================================


class TestHasDecorator:
    """Tests for has_decorator function."""

    def test_detects_simple_decorator(self):
        """has_decorator detects simple decorator by name."""
        code = """
@cache
def foo():
    pass
"""
        tree = ast.parse(code)
        func_def = tree.body[0]

        assert has_decorator(func_def, "cache") is True

    def test_detects_decorator_with_pattern(self):
        """has_decorator supports wildcard patterns."""
        code = """
@lru_cache(maxsize=128)
def foo():
    pass
"""
        tree = ast.parse(code)
        func_def = tree.body[0]

        assert has_decorator(func_def, "*cache*") is True

    def test_returns_false_when_decorator_absent(self):
        """has_decorator returns False when decorator not present."""
        code = """
def foo():
    pass
"""
        tree = ast.parse(code)
        func_def = tree.body[0]

        assert has_decorator(func_def, "cache") is False


class TestGetDecorators:
    """Tests for get_decorators function."""

    def test_returns_all_decorator_names(self):
        """get_decorators returns list of all decorator names."""
        code = """
@decorator1
@decorator2
def foo():
    pass
"""
        tree = ast.parse(code)
        func_def = tree.body[0]

        decorators = get_decorators(func_def)
        assert "decorator1" in decorators
        assert "decorator2" in decorators


# =============================================================================
# Assignment Detection Tests
# =============================================================================


class TestFindAssignments:
    """Tests for find_assignments function."""

    def test_finds_simple_assignment(self):
        """find_assignments finds simple variable assignments."""
        code = "api_key = 'secret'"
        tree = ast.parse(code)

        results = find_assignments(tree, "api_key")
        assert len(results) == 1

    def test_finds_pattern_assignment(self):
        """find_assignments supports pattern matching."""
        code = """
api_key = 'secret'
api_secret = 'another'
other = 'value'
"""
        tree = ast.parse(code)

        results = find_assignments(tree, "api_*")
        assert len(results) == 2


class TestGetAnnotationText:
    """Tests for get_annotation_text function."""

    def test_gets_simple_annotation(self):
        """get_annotation_text returns text for simple annotations."""
        code = "x: str"
        tree = ast.parse(code)
        ann_assign = tree.body[0]

        assert get_annotation_text(ann_assign.annotation) == "str"

    def test_gets_imported_annotation(self):
        """get_annotation_text returns text for imported annotations."""
        code = "x: SecretStr"
        tree = ast.parse(code)
        ann_assign = tree.body[0]

        assert get_annotation_text(ann_assign.annotation) == "SecretStr"

    def test_subscript_tuple_with_unresolvable_element_does_not_raise(self):
        """get_annotation_text must not raise TypeError when a Tuple subscript contains
        an element that resolves to None (regression for P11-1: None elements must be
        coerced to '' so the join never sees None)."""
        # Build an AST node for Dict[str, *args] which contains an ast.Starred
        # element inside the subscript Tuple — that resolves to None in get_annotation_text.
        import ast as _ast

        # Manually construct: Subscript(value=Name('Dict'), slice=Tuple([Name('str'), Starred(...)]))
        subscript = _ast.Subscript(
            value=_ast.Name(id="Dict", ctx=_ast.Load()),
            slice=_ast.Tuple(
                elts=[
                    _ast.Name(id="str", ctx=_ast.Load()),
                    # ast.Starred is not handled by get_annotation_text → returns None
                    _ast.Starred(value=_ast.Name(id="args", ctx=_ast.Load()), ctx=_ast.Load()),
                ],
                ctx=_ast.Load(),
            ),
            ctx=_ast.Load(),
        )
        try:
            result = get_annotation_text(subscript)
        except TypeError as exc:
            import pytest

            pytest.fail(
                f"get_annotation_text raised TypeError on a Tuple subscript with a None element: {exc}"
            )
        # Result must be a string (None elements coerced to "")
        assert isinstance(result, str), f"Expected str, got {type(result)!r}: {result!r}"
        assert "Dict" in result, f"Expected 'Dict' in result, got {result!r}"


class TestIsPlainType:
    """Tests for is_plain_type function."""

    def test_detects_str_as_plain(self):
        """is_plain_type returns True for plain str."""
        code = "x: str"
        tree = ast.parse(code)

        assert is_plain_type(tree.body[0].annotation, "str") is True

    def test_detects_secretstr_as_not_plain_str(self):
        """is_plain_type returns False for SecretStr when checking str."""
        code = "x: SecretStr"
        tree = ast.parse(code)

        assert is_plain_type(tree.body[0].annotation, "str") is False


# =============================================================================
# Import Detection Tests
# =============================================================================


class TestHasImport:
    """Tests for has_import function."""

    def test_detects_import(self):
        """has_import returns True when module is imported."""
        code = "import jwt"
        tree = ast.parse(code)

        assert has_import(tree, "jwt") is True

    def test_detects_from_import(self):
        """has_import detects 'from X import Y' style."""
        code = "from jwt import encode"
        tree = ast.parse(code)

        assert has_import(tree, "jwt") is True

    def test_returns_false_when_not_imported(self):
        """has_import returns False when module not imported."""
        code = "import os"
        tree = ast.parse(code)

        assert has_import(tree, "jwt") is False


class TestGetImportAliases:
    """Tests for get_import_aliases function."""

    def test_gets_import_aliases(self):
        """get_import_aliases returns mapping of imports."""
        code = """
import jwt
from pydantic import SecretStr as SS
"""
        tree = ast.parse(code)

        aliases = get_import_aliases(tree)
        assert "jwt" in aliases
        assert "SS" in aliases


# =============================================================================
# String Formatting Detection Tests
# =============================================================================


class TestContainsStringFormatting:
    """Tests for contains_string_formatting function."""

    def test_detects_f_string(self):
        """contains_string_formatting detects f-strings."""
        code = 'f"hello {name}"'
        tree = ast.parse(code)
        f_string_node = tree.body[0].value  # type: ignore

        assert contains_string_formatting(f_string_node) is True

    def test_detects_percent_formatting(self):
        """contains_string_formatting detects % formatting."""
        code = '"hello %s" % name'
        tree = ast.parse(code)
        bin_op_node = tree.body[0].value  # type: ignore

        assert contains_string_formatting(bin_op_node) is True


# =============================================================================
# Pattern Matching Tests
# =============================================================================


class TestMatchesPattern:
    """Tests for matches_pattern function."""

    def test_exact_match(self):
        """matches_pattern matches exact strings."""
        assert matches_pattern("api_key", "api_key") is True

    def test_wildcard_prefix(self):
        """matches_pattern supports * prefix."""
        assert matches_pattern("api_key", "api_*") is True

    def test_wildcard_suffix(self):
        """matches_pattern supports * suffix."""
        assert matches_pattern("api_key", "*_key") is True

    def test_no_match(self):
        """matches_pattern returns False for non-matching."""
        assert matches_pattern("other", "api_*") is False


class TestNameHeuristics:
    """Tests for name heuristic functions."""

    def test_is_path_related_name(self):
        """is_path_related_name detects path-related names."""
        assert is_path_related_name("file_path") is True
        assert is_path_related_name("directory") is True
        assert is_path_related_name("api_key") is False

    def test_is_secret_field_name(self):
        """is_secret_field_name detects secret-related names."""
        assert is_secret_field_name("api_key") is True
        assert is_secret_field_name("password") is True
        assert is_secret_field_name("secret_token") is True
        assert is_secret_field_name("user_name") is False

    def test_is_cache_related_name(self):
        """is_cache_related_name detects cache-related names."""
        assert is_cache_related_name("cache") is True
        assert is_cache_related_name("lru_cache") is True
        assert is_cache_related_name("cached_value") is True
        assert is_cache_related_name("user_data") is False


# =============================================================================
# AST Cache Tests
# =============================================================================


class TestASTCache:
    """Tests for ASTCache class (ADR-DET-007)."""

    def test_caches_parsed_ast(self):
        """ASTCache stores and returns cached AST."""
        cache = ASTCache(maxsize=100)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("x = 1\n")
            f.flush()
            path = Path(f.name)

            # First parse
            ast1 = cache.get_or_parse(path)
            # Second parse (should return cached)
            ast2 = cache.get_or_parse(path)

            assert ast1 is ast2  # Same object

    def test_respects_maxsize(self):
        """ASTCache evicts old entries when maxsize exceeded."""
        cache = ASTCache(maxsize=2)

        # Create and parse 3 files
        for i in range(3):
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write(f"x = {i}\n")
                f.flush()
                cache.get_or_parse(Path(f.name))

        # Cache should have at most 2 entries
        assert len(cache._cache) <= 2

    def test_returns_none_for_invalid_file(self):
        """ASTCache returns None for files with invalid syntax."""
        cache = ASTCache()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("invalid syntax {{{\n")
            f.flush()
            result = cache.get_or_parse(Path(f.name))
            assert result is None


# =============================================================================
# BatchVisitor Tests (VAL-H1: Visitor Pattern Batching)
# =============================================================================


class TestBatchVisitor:
    """Tests for BatchVisitor class implementing visitor pattern batching."""

    def test_registers_visitor_methods(self):
        """BatchVisitor can register visitor methods for node types."""
        visitor = BatchVisitor()

        calls = []

        def visit_call(node):
            calls.append(node)

        visitor.register_visitor("Call", visit_call)
        assert "Call" in visitor._visitors

    def test_visits_registered_node_types(self):
        """BatchVisitor visits registered node types during walk."""
        code = "foo()\nbar()"
        tree = ast.parse(code)

        visitor = BatchVisitor()
        calls = []

        def visit_call(node):
            if isinstance(node, ast.Call):
                calls.append(node)

        visitor.register_visitor("Call", visit_call)
        visitor.visit(tree)

        assert len(calls) == 2

    def test_runs_multiple_visitors(self):
        """BatchVisitor can run multiple visitors in one walk."""
        code = """
x = 1
foo()
"""
        tree = ast.parse(code)

        visitor = BatchVisitor()
        calls = []
        assigns = []

        def visit_call(node):
            if isinstance(node, ast.Call):
                calls.append(node)

        def visit_assign(node):
            if isinstance(node, ast.Assign):
                assigns.append(node)

        visitor.register_visitor("Call", visit_call)
        visitor.register_visitor("Assign", visit_assign)
        visitor.visit(tree)

        assert len(calls) == 1
        assert len(assigns) == 1

    def test_detector_integration_pattern(self):
        """BatchVisitor works with detector pattern."""
        code = "jwt.encode({'user': 'alice'}, 'secret')"
        tree = ast.parse(code)

        class MockDetector:
            def __init__(self):
                self.findings = []

            def visit_call(self, node):
                if isinstance(node, ast.Call):
                    name = get_call_name(node)
                    if name == "jwt.encode":
                        self.findings.append((node.lineno, "jwt.encode found"))

        detector = MockDetector()
        visitor = BatchVisitor()
        visitor.register_visitor("Call", detector.visit_call)
        visitor.visit(tree)

        assert len(detector.findings) == 1
        assert detector.findings[0][1] == "jwt.encode found"
