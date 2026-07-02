"""Tests for caliper.core.import_resolution — package-name -> import-name mapping (ADR-009)."""

from __future__ import annotations

from caliper.core.import_resolution import resolve_import_name


class TestCuratedMap:
    def test_pyyaml_resolves_to_yaml(self) -> None:
        assert resolve_import_name("PyYAML") == "yaml"

    def test_beautifulsoup4_resolves_to_bs4(self) -> None:
        assert resolve_import_name("beautifulsoup4") == "bs4"

    def test_pillow_resolves_to_pil_with_correct_case(self) -> None:
        """PIL is capitalized in the real `import PIL` statement -- a lowercase
        mapping would silently mismatch imports_module's case-sensitive exact match."""
        assert resolve_import_name("pillow") == "PIL"

    def test_pycryptodome_resolves_to_crypto_with_correct_case(self) -> None:
        assert resolve_import_name("pycryptodome") == "Crypto"

    def test_curated_lookup_is_case_and_dash_insensitive(self) -> None:
        assert resolve_import_name("Pillow") == "PIL"
        assert resolve_import_name("PILLOW") == "PIL"


class TestHeuristicFallback:
    def test_dash_separated_name_becomes_underscored(self) -> None:
        assert resolve_import_name("some-unmapped-package") == "some_unmapped_package"

    def test_dotted_name_becomes_underscored(self) -> None:
        assert resolve_import_name("some.unmapped.package") == "some_unmapped_package"

    def test_plain_name_is_returned_as_is(self) -> None:
        assert resolve_import_name("requests") == "requests"


class TestUnresolvable:
    def test_pathological_non_identifier_returns_none(self) -> None:
        assert resolve_import_name("123-not-an-identifier") is None

    def test_empty_string_returns_none(self) -> None:
        assert resolve_import_name("") is None
