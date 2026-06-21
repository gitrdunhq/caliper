"""Unit tests for the generic Registry[T] + autodiscover primitives.
# tested-by: tests/unit/test_generic_registry.py

RED phase for issue #405 — these import symbols that do not exist yet and are
expected to fail with ImportError until src/eedom/registry.py is added.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

from eedom.registry import Registry, autodiscover


class _Widget:
    def __init__(self, label: str = "default") -> None:
        self.label = label


class TestRegistryRegisterCreateKeys:
    def test_register_and_create(self):
        reg: Registry[_Widget] = Registry("widget")

        @reg.register("alpha")
        def _build_alpha(**kwargs) -> _Widget:
            return _Widget(label="alpha")

        widget = reg.create("alpha")
        assert isinstance(widget, _Widget)
        assert widget.label == "alpha"

    def test_register_returns_the_factory_unchanged(self):
        reg: Registry[_Widget] = Registry("widget")

        def _build(**kwargs) -> _Widget:
            return _Widget()

        decorated = reg.register("beta")(_build)
        assert decorated is _build

    def test_create_passes_kwargs_to_factory(self):
        reg: Registry[_Widget] = Registry("widget")

        @reg.register("gamma")
        def _build(label: str = "x", **kwargs) -> _Widget:
            return _Widget(label=label)

        assert reg.create("gamma", label="custom").label == "custom"

    def test_keys_lists_registered_keys(self):
        reg: Registry[_Widget] = Registry("widget")
        reg.register("one")(lambda **kw: _Widget())
        reg.register("two")(lambda **kw: _Widget())
        assert set(reg.keys()) == {"one", "two"}

    def test_unknown_key_raises_key_error(self):
        reg: Registry[_Widget] = Registry("widget")
        with pytest.raises(KeyError):
            reg.create("missing")


class TestAutodiscover:
    def test_imports_non_underscore_submodules(self, tmp_path: Path, monkeypatch):
        pkg_root = tmp_path / "discover_pkg"
        pkg_root.mkdir()
        (pkg_root / "__init__.py").write_text("")
        (pkg_root / "alpha.py").write_text(textwrap.dedent("""
                import discover_pkg
                discover_pkg.IMPORTED = getattr(discover_pkg, "IMPORTED", [])
                discover_pkg.IMPORTED.append("alpha")
                """))
        (pkg_root / "_private.py").write_text(textwrap.dedent("""
                import discover_pkg
                discover_pkg.IMPORTED = getattr(discover_pkg, "IMPORTED", [])
                discover_pkg.IMPORTED.append("_private")
                """))

        monkeypatch.syspath_prepend(str(tmp_path))
        for name in list(sys.modules):
            if name == "discover_pkg" or name.startswith("discover_pkg."):
                del sys.modules[name]

        import discover_pkg  # noqa: PLC0415

        autodiscover(discover_pkg.__name__, discover_pkg.__path__)

        assert "alpha" in getattr(discover_pkg, "IMPORTED", [])
        # Underscore-prefixed modules are skipped.
        assert "_private" not in getattr(discover_pkg, "IMPORTED", [])
