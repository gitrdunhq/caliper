"""RED tests for registry policy-removal (#158).

Contract under test (desired post-refactor behavior):
  1. run_all() NEVER passes findings= kwarg to any plugin.
  2. PluginRegistry has NO _run_policy method.
  3. A plugin with depends_on=["*"] is sorted last but called via the
     normal _run_one path — no special findings injection.
  4. A wildcard plugin whose run() signature does NOT accept findings=
     completes without error (no TypeError from hidden kwarg injection).
  5. The OPA plugin is no longer auto-registered in get_default_registry().

All five tests FAIL against current code, which still carries the
_run_policy / policy_plugins split.

# tested-by: tests/unit/test_registry_no_policy.py
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.core.registry import PluginRegistry

# ── shared fixtures ──────────────────────────────────────────────────────────


class _ScanPlugin(ScannerPlugin):
    """Regular scanner that always emits one finding."""

    @property
    def name(self) -> str:
        return "scan-alpha"

    @property
    def description(self) -> str:
        return "Emits a finding"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.dependency

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            findings=[{"id": "CVE-9999", "severity": "high", "message": "test"}],
        )


class _KwargSpyPlugin(ScannerPlugin):
    """Wildcard plugin that records every kwarg its run() receives."""

    def __init__(self) -> None:
        self.call_kwargs: list[dict] = []

    @property
    def name(self) -> str:
        return "spy-wildcard"

    @property
    def description(self) -> str:
        return "Records kwargs passed to run()"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.dependency

    @property
    def depends_on(self) -> list[str]:
        return ["*"]

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path, **kwargs) -> PluginResult:
        self.call_kwargs.append(dict(kwargs))
        return PluginResult(plugin_name=self.name)


class _StrictRunPlugin(ScannerPlugin):
    """Wildcard plugin with a strict run() that does NOT accept extra kwargs.

    When the registry injects findings= this plugin raises TypeError because
    its signature is `run(self, files, repo_path)` — exactly what a normal
    scanner looks like.  After the policy-removal refactor the registry must
    call it without any extra kwargs, so no TypeError is raised.
    """

    def __init__(self) -> None:
        self.was_called = False

    @property
    def name(self) -> str:
        return "strict-wildcard"

    @property
    def description(self) -> str:
        return "Strict signature — no kwargs accepted"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.dependency

    @property
    def depends_on(self) -> list[str]:
        return ["*"]

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:  # type: ignore[override]
        """Intentionally no **kwargs — a strict standard scanner signature."""
        self.was_called = True
        return PluginResult(plugin_name=self.name)


class _OrderTracker(ScannerPlugin):
    """Plain scanner that appends its name to a shared list on run()."""

    def __init__(self, plugin_name: str, order: list[str]) -> None:
        self._name = plugin_name
        self._order = order

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return f"Order tracker for {self._name}"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        self._order.append(self._name)
        return PluginResult(plugin_name=self._name)


# ── test cases ───────────────────────────────────────────────────────────────


class TestRegistryNoPolicyInjection:
    def test_run_all_never_passes_findings_kwarg_to_any_plugin(self):
        """run_all() must never call plugin.run() with a findings= kwarg.

        After #158: the registry is scanner-only; policy evaluation happens
        outside the registry via PolicyEnginePort.  No plugin should receive
        pre-merged findings injected by the registry.

        Fails against current code: _run_policy() calls
        plugin.run(files, repo_path, findings=<list>).
        """
        reg = PluginRegistry()
        reg.register(_ScanPlugin())
        spy = _KwargSpyPlugin()
        reg.register(spy)

        reg.run_all(["a.py"], Path("."))

        # No run() invocation should have received a 'findings' keyword arg
        assert spy.call_kwargs, "Spy plugin was never called — check test setup"
        for call_kw in spy.call_kwargs:
            assert (
                "findings" not in call_kw
            ), f"run_all() injected findings= into plugin.run(): {call_kw!r}"

    def test_registry_has_no_run_policy_method(self):
        """PluginRegistry must not expose a _run_policy method after #158.

        The _run_policy method is the implementation detail that separates
        wildcard plugins into a special policy execution path.  Removing it
        is the observable proof that the registry no longer owns policy dispatch.

        Fails against current code: _run_policy is defined on PluginRegistry.
        """
        reg = PluginRegistry()
        assert not hasattr(
            reg, "_run_policy"
        ), "PluginRegistry._run_policy still exists — policy-removal not done"

    def test_wildcard_plugin_sorted_last_called_without_findings_injection(self):
        """depends_on=["*"] plugin must run after all regular plugins but
        receive NO merged findings from the registry.

        This is the core contract change: wildcard means ordering only, not
        policy semantics.  The plugin executes last, but with the same plain
        (files, repo_path) call that every other scanner gets.

        Fails against current code: wildcard plugins are routed through
        _run_policy() which injects findings= from previous scan results.
        """
        order: list[str] = []
        recorded_kwargs: list[dict] = []

        class _WildcardOrderTracker(ScannerPlugin):
            @property
            def name(self) -> str:
                return "wildcard-last"

            @property
            def description(self) -> str:
                return "Tracks order + kwargs externally"

            @property
            def category(self) -> PluginCategory:
                return PluginCategory.code

            @property
            def depends_on(self) -> list[str]:
                return ["*"]

            def can_run(self, files: list[str], repo_path: Path) -> bool:
                return True

            def run(self, files: list[str], repo_path: Path, **kwargs) -> PluginResult:
                order.append("wildcard-last")
                # Record kwargs for external assertion — do NOT assert here so
                # the exception cannot be swallowed by _run_policy().
                recorded_kwargs.append(dict(kwargs))
                return PluginResult(plugin_name="wildcard-last")

        reg = PluginRegistry()
        first = _OrderTracker("first-scan", order)
        second = _OrderTracker("second-scan", order)
        reg.register(first)
        reg.register(second)
        reg.register(_WildcardOrderTracker())

        reg.run_all(["a.py"], Path("."))

        # All three must have run
        assert "first-scan" in order
        assert "second-scan" in order
        assert "wildcard-last" in order, "Wildcard plugin was never invoked"
        # Wildcard plugin must still be last (ordering contract preserved)
        assert order[-1] == "wildcard-last", f"Wildcard plugin did not run last: {order}"
        # Core assertion: no findings= was injected (external check, not inside run())
        assert recorded_kwargs, "No kwargs recorded — wildcard plugin never ran cleanly"
        for kw in recorded_kwargs:
            assert "findings" not in kw, f"Registry injected findings= into wildcard plugin: {kw!r}"

    def test_wildcard_plugin_without_findings_param_produces_no_error(self):
        """A wildcard plugin with a strict run(files, repo_path) signature must
        complete without error after the policy-removal refactor.

        Currently run_all() routes wildcard plugins through _run_policy(), which
        calls plugin.run(files, repo_path, findings=<list>).  A strict signature
        causes TypeError, which _run_policy() catches and returns as an error
        result.  After the refactor the registry must NOT inject findings=, so
        the strict-signature plugin succeeds.

        Fails against current code: _run_policy injects findings=, TypeError is
        swallowed into result.error.
        """
        reg = PluginRegistry()
        reg.register(_ScanPlugin())
        strict = _StrictRunPlugin()
        reg.register(strict)

        results = reg.run_all(["a.py"], Path("."))

        strict_result = next((r for r in results if r.plugin_name == "strict-wildcard"), None)
        assert strict_result is not None, "strict-wildcard result not found"
        assert strict_result.error == "", (
            f"Wildcard plugin produced error (findings= likely injected): "
            f"{strict_result.error!r}"
        )
        assert strict.was_called, "strict-wildcard plugin was never invoked"

    def test_opa_plugin_not_in_default_registry(self):
        """get_default_registry() must NOT include the OPA scanner plugin.

        After #158: OpaPlugin is removed (or deprecated) from the auto-discovery
        path.  Policy evaluation belongs to OpaRegoAdapter behind PolicyEnginePort,
        not to a ScannerPlugin registered in the scanner registry.

        Fails against current code: opa.py is in the plugins/ directory and is
        auto-discovered by discover_plugins(), so get_default_registry() returns
        a registry that includes an 'opa' plugin.
        """
        from caliper.plugins import get_default_registry

        registry = get_default_registry()
        opa_plugin = registry.get("opa")
        assert opa_plugin is None, (
            "OpaPlugin is still registered in the default registry — "
            "remove opa.py from plugins/ or mark it as deprecated and exclude "
            "it from auto-discovery"
        )
