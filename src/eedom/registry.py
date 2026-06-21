"""Generic, type-parameterised adapter registry + autodiscovery.
# tested-by: tests/unit/test_generic_registry.py

This is the single reusable registry primitive the ports-&-adapters epic
(#404) builds on.  Each port area declares one module-level
``Registry[SomePort]`` instance, adapters self-register against it with the
``@REGISTRY.register("key")`` decorator, and ``autodiscover`` imports every
adapter submodule so those decorators run on package import.

The registry stores *factories*, not instances — ``create(key, **kwargs)``
constructs on demand and forwards keyword arguments (timeouts, paths, …) to
the factory.  Resolution does no I/O; all side effects belong to the adapter
the factory returns.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable, Iterable


class Registry[T]:
    """A keyed registry of factories producing instances of ``T``.

    *kind* is a human-readable label for the thing being registered
    (``"scanner"``, ``"policy_engine"``, …) used only in error messages.
    """

    def __init__(self, kind: str) -> None:
        self._kind = kind
        self._factories: dict[str, Callable[..., T]] = {}

    def register[F: Callable[..., object]](self, key: str) -> Callable[[F], F]:
        """Decorator registering the wrapped factory under *key*.

        The factory is returned unchanged so the decorator is transparent.
        """

        def decorator(factory: F) -> F:
            self._factories[key] = factory  # type: ignore[assignment]
            return factory

        return decorator

    def create(self, key: str, **kwargs: object) -> T:
        """Construct the instance registered under *key*.

        Forwards ``**kwargs`` to the factory.  Raises ``KeyError`` when *key*
        is unknown.
        """
        try:
            factory = self._factories[key]
        except KeyError:
            known = ", ".join(sorted(self._factories)) or "<none>"
            raise KeyError(
                f"unknown {self._kind} {key!r}; registered {self._kind}s: {known}"
            ) from None
        return factory(**kwargs)

    def keys(self) -> list[str]:
        """Return the registered keys, sorted for determinism."""
        return sorted(self._factories)

    def __contains__(self, key: object) -> bool:
        return key in self._factories


def autodiscover(package_name: str, package_path: Iterable[str]) -> None:
    """Import every non-underscore submodule of a package.

    Adapters self-register as a side effect of import, so calling this from a
    package ``__init__`` (``autodiscover(__name__, __path__)``) is what wires
    them into their registry.  Underscore-prefixed modules (``_private``,
    ``__init__``) are skipped.
    """
    for module in pkgutil.iter_modules(package_path):
        if module.name.startswith("_"):
            continue
        importlib.import_module(f"{package_name}.{module.name}")
