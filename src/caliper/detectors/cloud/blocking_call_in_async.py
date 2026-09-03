"""Detector for blocking calls inside async functions (#499).
# tested-by: tests/unit/detectors/cloud/test_blocking_call_in_async.py
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

from caliper.core.models import FindingSeverity
from caliper.detectors._registry import register_detector
from caliper.detectors.ast_utils import parse_file_safe
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding
from caliper.detectors.framework import BugDetector

_NESTED_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef)


@register_detector
class BlockingCallInAsyncDetector(BugDetector):
    """Detects synchronous blocking calls made directly inside an ``async def``.

    Reliability issue: a blocking sleep, HTTP request, subprocess, socket
    connect, or sync database/cache client call inside a coroutine stalls the
    whole event loop for its duration - every other task on the loop waits.

    GitHub: #499
    """

    # Exact dotted callees that block.
    BLOCKING_DOTTED = frozenset(
        {
            "time.sleep",
            "urllib.request.urlopen",
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
            "socket.create_connection",
        }
    )

    # Any attribute call whose receiver root is this name blocks.
    BLOCKING_ROOTS = frozenset({"requests"})

    # Constructors whose bound name yields a synchronous client.
    SYNC_CLIENT_CTORS = frozenset(
        {
            "redis.Redis",
            "redis.StrictRedis",
            "psycopg2.connect",
            "sqlite3.connect",
            "pymongo.MongoClient",
        }
    )

    # Calls whose arguments are offloaded to a thread and therefore exempt.
    OFFLOAD_ATTRS = frozenset({"to_thread", "run_in_executor"})

    @property
    def detector_id(self) -> str:
        return "CAL-028"

    @property
    def name(self) -> str:
        return "Blocking Call Inside Async Function"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.reliability

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.high

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.py",)

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Analyze file for blocking calls inside async functions.

        Fail-open: any parse, decode, or IO failure yields no findings.
        """
        try:
            return self._detect(file_path)
        except Exception:  # noqa: BLE001 - fail-open by design
            return []

    def _detect(self, file_path: Path) -> list[DetectorFinding]:
        tree = parse_file_safe(file_path)
        if not tree:
            return []

        bare_sleep_is_time = self._imports_sleep_from_time(tree)
        module_clients = self._bound_sync_clients(tree.body)

        findings: list[DetectorFinding] = []
        for func in ast.walk(tree):
            if not isinstance(func, ast.AsyncFunctionDef):
                continue
            clients = module_clients | self._bound_sync_clients(func.body)
            skip = self._offloaded_calls(func) | self._receiver_calls(func)
            for call in self._own_calls(func):
                if call in skip:
                    continue
                callee = self._blocking_callee(call, bare_sleep_is_time, clients)
                if callee is None:
                    continue
                lineno = call.lineno
                if not self._should_report_finding(file_path, lineno):
                    continue
                findings.append(
                    DetectorFinding(
                        detector_id=self.detector_id,
                        detector_name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=str(file_path),
                        line_number=lineno,
                        message=(
                            f"{callee}() inside async function '{func.name}' "
                            "blocks the event loop for its full duration"
                        ),
                        issue_reference="#499",
                        fix_hint="Use the async client, or wrap the call in asyncio.to_thread()",
                    )
                )

        findings.sort(key=lambda f: (f.line_number, f.message))
        return findings

    @staticmethod
    def _imports_sleep_from_time(tree: ast.Module) -> bool:
        """True when the module has ``from time import sleep``."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "time":
                if any(alias.name == "sleep" and alias.asname is None for alias in node.names):
                    return True
        return False

    def _bound_sync_clients(self, body: list[ast.stmt]) -> frozenset[str]:
        """Names bound by ``name = <sync ctor>(...)`` directly in ``body``."""
        names: set[str] = set()
        for stmt in body:
            if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
                continue
            target = stmt.targets[0]
            if not isinstance(target, ast.Name) or not isinstance(stmt.value, ast.Call):
                continue
            if self._dotted_name(stmt.value.func) in self.SYNC_CLIENT_CTORS:
                names.add(target.id)
        return frozenset(names)

    @classmethod
    def _own_nodes(cls, func: ast.AsyncFunctionDef) -> Iterator[ast.AST]:
        """Yield every node in ``func``'s body without entering nested defs."""
        stack: list[ast.AST] = [s for s in reversed(func.body) if not isinstance(s, _NESTED_SCOPES)]
        while stack:
            node = stack.pop()
            yield node
            for child in reversed(list(ast.iter_child_nodes(node))):
                if isinstance(child, _NESTED_SCOPES):
                    continue
                stack.append(child)

    @classmethod
    def _own_calls(cls, func: ast.AsyncFunctionDef) -> list[ast.Call]:
        return [n for n in cls._own_nodes(func) if isinstance(n, ast.Call)]

    def _offloaded_calls(self, func: ast.AsyncFunctionDef) -> set[ast.Call]:
        """Call nodes that are arguments of a ``to_thread``/``run_in_executor`` call."""
        exempt: set[ast.Call] = set()
        for call in self._own_calls(func):
            if not isinstance(call.func, ast.Attribute):
                continue
            if call.func.attr not in self.OFFLOAD_ATTRS:
                continue
            for arg in [*call.args, *(kw.value for kw in call.keywords)]:
                for inner in ast.walk(arg):
                    if isinstance(inner, ast.Call):
                        exempt.add(inner)
        return exempt

    def _receiver_calls(self, func: ast.AsyncFunctionDef) -> set[ast.Call]:
        """Call nodes used as the receiver of a further method call (``requests.Session()`` in ``requests.Session().post``)."""
        receivers: set[ast.Call] = set()
        for call in self._own_calls(func):
            node: ast.AST = call.func
            while isinstance(node, (ast.Attribute, ast.Call)):
                if isinstance(node, ast.Call):
                    receivers.add(node)
                    node = node.func
                else:
                    node = node.value
        return receivers

    def _blocking_callee(
        self,
        call: ast.Call,
        bare_sleep_is_time: bool,
        clients: frozenset[str],
    ) -> str | None:
        """Return the callee as written when ``call`` blocks, else ``None``."""
        func = call.func
        if isinstance(func, ast.Name):
            if func.id == "sleep" and bare_sleep_is_time:
                return "sleep"
            return None
        if not isinstance(func, ast.Attribute):
            return None

        dotted = self._dotted_name(func)
        if dotted in self.BLOCKING_DOTTED:
            return dotted
        if self._root_name(func) in self.BLOCKING_ROOTS:
            return ast.unparse(func)
        if isinstance(func.value, ast.Name) and func.value.id in clients:
            return dotted
        return None

    @staticmethod
    def _dotted_name(node: ast.AST) -> str | None:
        """``a.b.c`` for a pure Name/Attribute chain, else ``None``."""
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        parts.append(node.id)
        return ".".join(reversed(parts))

    @staticmethod
    def _root_name(node: ast.AST) -> str | None:
        """Leftmost Name of an attribute/call chain (``requests.Session().post`` -> ``requests``)."""
        while True:
            if isinstance(node, ast.Attribute):
                node = node.value
            elif isinstance(node, ast.Call):
                node = node.func
            elif isinstance(node, ast.Name):
                return node.id
            else:
                return None
