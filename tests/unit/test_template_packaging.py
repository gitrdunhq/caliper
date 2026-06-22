"""Tests for template packaging in wheel distribution.

# tested-by: tests/unit/test_template_packaging.py

These tests verify that Jinja2 template files are properly included in the
built wheel and can be loaded in both development and installed contexts.
"""

from __future__ import annotations

import importlib.resources
import zipfile
from pathlib import Path

import pytest


def test_templates_accessible_via_importlib_resources():
    """Verify templates are accessible via importlib.resources in both dev and installed contexts."""
    # This test should work whether caliper is installed or running from source
    import caliper

    caliper_package = caliper
    template_names = ["comment.md.j2", "semgrep.md.j2"]

    for template_name in template_names:
        # Try to access template using importlib.resources
        try:
            with importlib.resources.files("caliper.templates").joinpath(template_name).open() as f:
                content = f.read()
                assert len(content) > 0, f"Template {template_name} is empty"
        except (ImportError, ModuleNotFoundError, FileNotFoundError) as e:
            pytest.fail(f"Cannot access template {template_name}: {e}")


def test_wheel_contains_template_files():
    """Verify wheel contains template files when built.

    This test builds a wheel and checks that .j2 files are included.
    """
    import subprocess
    import sys
    import tempfile

    # Build wheel in a temp directory
    with tempfile.TemporaryDirectory() as tmpdir:
        # Build wheel
        result = subprocess.run(
            [sys.executable, "-m", "uv", "build", "--wheel", "--out-dir", tmpdir],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent,
        )

        if result.returncode != 0:
            pytest.skip(f"Wheel build failed: {result.stderr}")

        # Find the wheel file
        wheel_files = list(Path(tmpdir).glob("*.whl"))
        if not wheel_files:
            pytest.skip("No wheel file found after build")

        wheel_path = wheel_files[0]

        # Check for template files in wheel
        with zipfile.ZipFile(wheel_path, "r") as whl:
            template_files = [name for name in whl.namelist() if name.endswith(".j2")]

            assert len(template_files) > 0, (
                f"No .j2 template files found in wheel. " f"Wheel contents: {whl.namelist()}"
            )

            # Verify key templates exist
            template_basenames = [Path(p).name for p in template_files]
            assert "comment.md.j2" in template_basenames, "comment.md.j2 not found in wheel"
            assert "semgrep.md.j2" in template_basenames, "semgrep.md.j2 not found in wheel"


def test_renderer_can_load_templates_in_installed_context():
    """Verify renderer can load templates in installed package context.

    This simulates what happens after `uv tool install` when templates
    must be loaded from the installed package location.
    """
    import jinja2

    from caliper.core.renderer import render_comment

    # Try to render a comment - this will fail if templates aren't accessible
    try:
        result = render_comment(
            results=[],
            repo="test/repo",
            pr_num=1,
            title="Test PR",
            file_count=1,
        )
        assert isinstance(result, str)
    except jinja2.TemplateNotFound as e:
        pytest.fail(f"Template not found - packaging issue: {e}")


def test_templates_directory_structure_preserved():
    """Verify templates directory structure is preserved in wheel."""
    import subprocess
    import sys
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        # Build wheel
        result = subprocess.run(
            [sys.executable, "-m", "uv", "build", "--wheel", "--out-dir", tmpdir],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent,
        )

        if result.returncode != 0:
            pytest.skip(f"Wheel build failed: {result.stderr}")

        wheel_files = list(Path(tmpdir).glob("*.whl"))
        if not wheel_files:
            pytest.skip("No wheel file found")

        with zipfile.ZipFile(wheel_files[0], "r") as whl:
            # Check that templates are in the expected path
            expected_path_prefix = "caliper/templates/"
            template_paths = [
                name
                for name in whl.namelist()
                if name.endswith(".j2") and expected_path_prefix in name
            ]

            assert len(template_paths) > 0, (
                f"Templates not found at {expected_path_prefix} in wheel. "
                f"Wheel contents: {whl.namelist()}"
            )
