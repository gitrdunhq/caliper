"""Dependency scanners — port + self-registering adapter registry.
# tested-by: tests/unit/test_scanner_port.py

`SCANNERS` is the single registry of scanner factories. Adapter modules in
this package decorate their factory with ``@SCANNERS.register("<key>")`` and
``autodiscover`` imports them on package import so the decorators run.
"""

from __future__ import annotations

from eedom.data.scanners.base import ScannerPort
from eedom.registry import Registry, autodiscover

# Defined before autodiscover so adapter modules can import it on import.
SCANNERS: Registry[ScannerPort] = Registry("scanner")

# Import every adapter submodule so each self-registers against SCANNERS.
autodiscover(__name__, __path__)

__all__ = ["SCANNERS", "ScannerPort"]
