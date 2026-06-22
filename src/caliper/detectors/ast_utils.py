"""AST utility functions for bug detection.
# tested-by: tests/unit/detectors/test_ast_utils.py

Provides AST parsing, pattern matching, and visitor pattern batching
for efficient multi-detector analysis (VAL-H1, ADR-DET-007).
"""

from __future__ import annotations

import ast
import fnmatch
import hashlib
import re
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path

# =============================================================================
# AST Cache (ADR-DET-007)
# =============================================================================


class ASTCache:
    """Content-addressed AST cache with LRU eviction.

    Implements the caching strategy from ADR-DET-007:
    - Cache key: file_path + content_hash (MD5)
    - Cache scope: per-scan (in-memory, not persisted)
    - Eviction: LRU with max entries limit

    This allows multiple detectors to analyze the same file without
    re-parsing it each time.
    """

    def __init__(self, maxsize: int = 100):
        """Initialize cache with size limit.

        Args:
            maxsize: Maximum number of entries to keep in cache
        """
        self.maxsize = maxsize
        self._cache: OrderedDict[str, ast.Module] = OrderedDict()

    def _get_cache_key(self, file_path: Path) -> str | None:
        """Generate cache key from file path and content hash.

        Returns:
            Cache key string or None if file cannot be read
        """
        try:
            content = file_path.read_bytes()
            content_hash = hashlib.md5(content).hexdigest()  # noqa: S324
            return f"{file_path}:{content_hash}"
        except OSError:
            return None

    def get_or_parse(self, file_path: Path) -> ast.Module | None:
        """Get cached AST or parse file.

        Args:
            file_path: Path to the Python file to parse

        Returns:
            Parsed AST module or None if parsing fails
        """
        cache_key = self._get_cache_key(file_path)
        if cache_key is None:
            return parse_file_safe(file_path)

        # Check cache
        if cache_key in self._cache:
            # Move to end (most recently used)
            self._cache.move_to_end(cache_key)
            return self._cache[cache_key]

        # Parse and cache
        tree = parse_file_safe(file_path)
        if tree is not None:
            # Add to cache
            self._cache[cache_key] = tree
            self._cache.move_to_end(cache_key)

            # Evict oldest if over limit
            while len(self._cache) > self.maxsize:
                self._cache.popitem(last=False)

        return tree


# =============================================================================
# File Analysis Utilities
# =============================================================================


def parse_file_safe(file_path: Path) -> ast.Module | None:
    """Parse file with error handling.

    Args:
        file_path: Path to the Python file to parse

    Returns:
        Parsed AST module or None if file doesn't exist or has invalid syntax
    """
    try:
        content = file_path.read_text(encoding="utf-8")
        return ast.parse(content)
    except (OSError, SyntaxError):
        return None


# =============================================================================
# Function Call Detection
# =============================================================================


def get_call_name(node: ast.AST | None) -> str | None:
    """Extract full qualified name from call node.

    Args:
        node: AST node (expected to be ast.Call)

    Returns:
        Full qualified name (e.g., 'jwt.encode') or None if not a Call
    """
    if not isinstance(node, ast.Call):
        return None

    func = node.func
    parts = []

    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value

    if isinstance(func, ast.Name):
        parts.append(func.id)
        return ".".join(reversed(parts))

    return None


def matches_pattern(name: str, pattern: str) -> bool:
    """Match name against glob pattern (e.g., '*token*', 'api_*').

    Args:
        name: String to match
        pattern: Glob pattern with * wildcards

    Returns:
        True if name matches pattern
    """
    return fnmatch.fnmatch(name, pattern)


def find_function_calls(tree: ast.AST, func_pattern: str) -> list[tuple[ast.Call, int]]:
    """Find all calls matching pattern (e.g., 'jwt.encode', '*.execute').

    Args:
        tree: AST module to search
        func_pattern: Glob pattern for function name matching

    Returns:
        List of (Call node, line_number) tuples
    """
    results = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = get_call_name(node)
            if name and matches_pattern(name, func_pattern):
                results.append((node, node.lineno))

    return results


def has_function_call(tree: ast.AST, func_pattern: str) -> bool:
    """Check if file contains any matching function call.

    Args:
        tree: AST module to search
        func_pattern: Glob pattern for function name matching

    Returns:
        True if at least one matching call is found
    """
    return len(find_function_calls(tree, func_pattern)) > 0


# =============================================================================
# Decorator Detection
# =============================================================================


def _get_decorator_name(decorator: ast.expr) -> str | None:
    """Extract name from decorator node."""
    if isinstance(decorator, ast.Name):
        return decorator.id
    elif isinstance(decorator, ast.Attribute):
        # Handle module.decorator pattern
        parts = []
        node = decorator
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
    elif isinstance(decorator, ast.Call):
        # Decorator with arguments: @decorator(args)
        return _get_decorator_name(decorator.func)
    return None


def has_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, pattern: str
) -> bool:
    """Check if node has decorator matching pattern.

    Args:
        node: Function or class definition node
        pattern: Glob pattern for decorator name matching

    Returns:
        True if matching decorator is found
    """
    for decorator in node.decorator_list:
        name = _get_decorator_name(decorator)
        if name and matches_pattern(name, pattern):
            return True
    return False


def get_decorators(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
) -> list[str]:
    """Get all decorator names on a node.

    Args:
        node: Function or class definition node

    Returns:
        List of decorator names
    """
    names = []
    for decorator in node.decorator_list:
        name = _get_decorator_name(decorator)
        if name:
            names.append(name)
    return names


# =============================================================================
# Variable and Assignment Detection
# =============================================================================


def find_assignments(tree: ast.AST, var_pattern: str) -> list[ast.Assign | ast.AnnAssign]:
    """Find assignments to variables matching pattern.

    Args:
        tree: AST module to search
        var_pattern: Glob pattern for variable name matching

    Returns:
        List of assignment nodes
    """
    results = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and matches_pattern(target.id, var_pattern):
                    results.append(node)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):  # noqa: SIM102
            if matches_pattern(node.target.id, var_pattern):
                results.append(node)

    return results


def get_annotation_text(node: ast.AST | None) -> str | None:
    """Convert annotation AST to source text.

    Args:
        node: AST annotation node

    Returns:
        String representation of annotation or None
    """
    if node is None:
        return None

    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        name = get_call_name(node)
        return name
    elif isinstance(node, ast.Subscript):
        value = get_annotation_text(node.value)
        slice_node = node.slice
        if isinstance(slice_node, ast.Tuple):
            # An element may be unresolvable (e.g. ast.Starred -> None); coerce to ""
            # so the join never raises TypeError on a None member.
            elements = [get_annotation_text(elt) or "" for elt in slice_node.elts]
            return f"{value}[{', '.join(elements)}]"
        else:
            slice_text = get_annotation_text(slice_node)
            return f"{value}[{slice_text}]"
    elif isinstance(node, ast.Constant):
        return str(node.value)

    return None


def is_plain_type(annotation: ast.AST | None, type_name: str) -> bool:
    """Check if annotation is plain type (e.g., 'str', not 'SecretStr').

    Args:
        annotation: AST annotation node
        type_name: Expected plain type name

    Returns:
        True if annotation is exactly the plain type
    """
    text = get_annotation_text(annotation)
    return text == type_name


# =============================================================================
# Import Detection
# =============================================================================


def has_import(tree: ast.AST, module_pattern: str) -> bool:
    """Check if file imports matching module.

    Args:
        tree: AST module to search
        module_pattern: Glob pattern for module name matching

    Returns:
        True if matching import is found
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if matches_pattern(alias.name, module_pattern):
                    return True
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module
            and matches_pattern(node.module, module_pattern)
        ):
            return True
    return False


def get_import_aliases(tree: ast.AST) -> dict[str, str]:
    """Get mapping of imported names to their sources.

    Args:
        tree: AST module to search

    Returns:
        Dict mapping imported name to module source
    """
    aliases: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name
                aliases[name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name
                aliases[name] = f"{node.module}.{alias.name}"

    return aliases


# =============================================================================
# String and Formatting Detection
# =============================================================================


def contains_string_formatting(node: ast.AST) -> bool:
    """Check if node contains f-string, % formatting, or .format().

    Args:
        node: AST node to check

    Returns:
        True if node contains string formatting patterns
    """
    for child in ast.walk(node):
        # f-string
        if isinstance(child, ast.JoinedStr):
            return True
        # % formatting (BinOp with Mod)
        if (
            isinstance(child, ast.BinOp)
            and isinstance(child.op, ast.Mod)
            and isinstance(child.left, ast.Constant)
            and isinstance(child.left.value, str)
        ):
            return True
        # .format() call
        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and child.func.attr == "format"
        ):
            return True
    return False


def is_f_string_with_variable(node: ast.JoinedStr, var_name: str) -> bool:
    """Check if f-string contains specific variable.

    Args:
        node: JoinedStr (f-string) node
        var_name: Variable name to search for

    Returns:
        True if f-string contains the variable
    """
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id == var_name:
            return True
        # Also check for formatted values in f-strings
        if (
            isinstance(child, ast.FormattedValue)
            and isinstance(child.value, ast.Name)
            and child.value.id == var_name
        ):
            return True
    return False


# =============================================================================
# Class and Method Detection
# =============================================================================


def find_class_methods(tree: ast.AST, class_name: str | None = None) -> list[ast.FunctionDef]:
    """Find all methods, optionally filtered by class name.

    Args:
        tree: AST module to search
        class_name: Optional class name pattern to filter by

    Returns:
        List of function definition nodes
    """
    results = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and (
            class_name is None or matches_pattern(node.name, class_name)
        ):
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    results.append(item)

    return results


def find_classes(tree: ast.AST, name_pattern: str | None = None) -> list[ast.ClassDef]:
    """Find classes matching pattern.

    Args:
        tree: AST module to search
        name_pattern: Optional glob pattern for class name matching

    Returns:
        List of class definition nodes
    """
    results = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and (
            name_pattern is None or matches_pattern(node.name, name_pattern)
        ):
            results.append(node)

    return results


# =============================================================================
# Exception Handling Detection
# =============================================================================


def find_exception_handlers(tree: ast.AST, exc_type: str | None = None) -> list[ast.ExceptHandler]:
    """Find exception handlers, optionally filtered by exception type.

    Args:
        tree: AST module to search
        exc_type: Optional exception type name to filter by

    Returns:
        List of exception handler nodes
    """
    results = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if exc_type is None:
                results.append(node)
            elif node.type:
                # Check if the exception type matches
                type_name = None
                if isinstance(node.type, ast.Name):
                    type_name = node.type.id
                elif isinstance(node.type, ast.Tuple):
                    # Multiple exception types: except (A, B):
                    for elt in node.type.elts:
                        if isinstance(elt, ast.Name) and matches_pattern(elt.id, exc_type):
                            results.append(node)
                            break
                    continue

                if type_name and matches_pattern(type_name, exc_type):
                    results.append(node)

    return results


def handler_exposes_variable(handler: ast.ExceptHandler, var_name: str) -> bool:
    """Check if exception handler exposes variable in output.

    This checks if the handler variable (e.g., 'exc' in 'except E as exc')
    is used in a way that might expose it externally.

    Args:
        handler: Exception handler node
        var_name: Variable name to check (usually handler.name)

    Returns:
        True if variable is used in potentially exposing contexts
    """
    if not handler.name or handler.name != var_name:
        return False

    # Check if variable is used in the handler body
    return any(isinstance(node, ast.Name) and node.id == var_name for node in ast.walk(handler))


# =============================================================================
# Name Heuristics
# =============================================================================


def is_path_related_name(name: str) -> bool:
    """Check if name suggests path/file handling.

    Args:
        name: Variable or attribute name

    Returns:
        True if name suggests path-related usage
    """
    path_patterns = [
        "path",
        "file",
        "directory",
        "dir",
        "filename",
        "filepath",
        "folder",
    ]
    name_lower = name.lower()
    return any(pattern in name_lower for pattern in path_patterns)


def is_secret_field_name(name: str) -> bool:
    """Check if name suggests secret/credential.

    Args:
        name: Variable or attribute name

    Returns:
        True if name suggests secret-related usage
    """

    secret_patterns = [
        r"api[_-]?key",
        r"credential",
        r"dsn",
        r"password",
        r"private[_-]?key",
        r"secret",
        r"token",
        r"auth",
    ]
    name_lower = name.lower()
    return any(re.search(pattern, name_lower) for pattern in secret_patterns)


def is_cache_related_name(name: str) -> bool:
    """Check if name suggests caching.

    Args:
        name: Variable or attribute name

    Returns:
        True if name suggests cache-related usage
    """
    cache_patterns = ["cache", "lru", "memo", "cached"]
    name_lower = name.lower()
    return any(pattern in name_lower for pattern in cache_patterns)


# =============================================================================
# BatchVisitor (VAL-H1: Visitor Pattern Batching)
# =============================================================================


class BatchVisitor(ast.NodeVisitor):
    """Visitor that batches multiple detectors in a single AST walk.

    This implements the visitor pattern batching requirement from VAL-H1,
    allowing all 71 detectors to analyze a file in a single traversal
    rather than 71 separate walks.

    Usage:
        visitor = BatchVisitor()
        visitor.register_visitor("Call", my_detector.visit_call)
        visitor.register_visitor("FunctionDef", my_detector.visit_function)
        visitor.visit(ast_tree)
    """

    def __init__(self):
        """Initialize visitor with empty registry."""
        super().__init__()
        self._visitors: dict[str, list[Callable[[ast.AST], None]]] = {}

    def register_visitor(self, node_type: str, visitor_func: Callable[[ast.AST], None]) -> None:
        """Register a visitor function for a specific node type.

        Args:
            node_type: AST node type name (e.g., 'Call', 'FunctionDef')
            visitor_func: Function to call when visiting that node type
        """
        if node_type not in self._visitors:
            self._visitors[node_type] = []
        self._visitors[node_type].append(visitor_func)

    def _run_visitors(self, node: ast.AST) -> None:
        """Run all registered visitors for the node type.

        Args:
            node: AST node being visited
        """
        node_type = type(node).__name__
        if node_type in self._visitors:
            for visitor_func in self._visitors[node_type]:
                visitor_func(node)

    def visit(self, node: ast.AST) -> None:
        """Visit a node and dispatch to registered visitors.

        This overrides the base visit to add our dispatch logic while
        still maintaining the recursive traversal.

        Args:
            node: AST node to visit
        """
        self._run_visitors(node)
        # Continue with standard traversal
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Visit Call nodes."""
        self._run_visitors(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit FunctionDef nodes."""
        self._run_visitors(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit AsyncFunctionDef nodes."""
        self._run_visitors(node)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit ClassDef nodes."""
        self._run_visitors(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit Assign nodes."""
        self._run_visitors(node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Visit AnnAssign (annotated assignment) nodes."""
        self._run_visitors(node)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Visit Import nodes."""
        self._run_visitors(node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Visit ImportFrom nodes."""
        self._run_visitors(node)
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        """Visit Try nodes."""
        self._run_visitors(node)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Visit ExceptHandler nodes."""
        self._run_visitors(node)
        self.generic_visit(node)
