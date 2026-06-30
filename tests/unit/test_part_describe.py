"""Tests for the describer composition edge — ``cli.part_describe``.

# tested-by: tests/unit/test_part_describe.py

This is the imperative shell: it resolves a describer from env/flag and runs it over
a cut to build the advisory ``{part.id: subject}`` map. The network call lives in the
data-tier adapter; here we only test wiring, env resolution, and fail-soft mapping
with a fake describer — no real backend.
"""

from __future__ import annotations

from caliper.cli.part_describe import describe_parts, describer_from_env
from caliper.core.commit_describer import DescribeRequest, NullDescriber
from caliper.core.models import ChangeType, Record
from caliper.core.parting import part
from caliper.core.repo_config import PartingConfig
from caliper.data.openai_describer import OpenAICompatDescriber


def _cut():
    records = [
        Record(file="a.py", change_type=ChangeType.logic, size=100),
        Record(file="poetry.lock", change_type=ChangeType.generated, size=10),
    ]
    return part(records, PartingConfig(size_cap=400))


class _FakeDescriber:
    def __init__(self, subject: str | None) -> None:
        self.subject = subject
        self.seen: list[DescribeRequest] = []

    def describe(self, request: DescribeRequest) -> str | None:
        self.seen.append(request)
        return self.subject


class TestDescribeParts:
    def test_maps_part_id_to_subject(self) -> None:
        cut = _cut()
        fake = _FakeDescriber("feat(x): a narrative subject")
        out = describe_parts(cut, fake)
        assert set(out) == {p.id for p in cut.parts}
        assert all(v == "feat(x): a narrative subject" for v in out.values())

    def test_prefix_passed_is_deterministic_for_the_bucket(self) -> None:
        cut = _cut()
        fake = _FakeDescriber("feat(x): y")
        describe_parts(cut, fake)
        prefixes = {r.prefix for r in fake.seen}
        # generated -> chore(generated): , logic -> feat(logic):
        assert "chore(generated): " in prefixes

    def test_none_subjects_are_skipped(self) -> None:
        assert describe_parts(_cut(), _FakeDescriber(None)) == {}

    def test_null_describer_short_circuits_to_empty(self) -> None:
        assert describe_parts(_cut(), NullDescriber()) == {}

    def test_describer_exception_is_swallowed(self) -> None:
        class Boom:
            def describe(self, request):  # noqa: ANN001, ARG002
                raise RuntimeError("backend on fire")

        assert describe_parts(_cut(), Boom()) == {}


class TestDescriberFromEnv:
    _CFG = {"CALIPER_DESCRIBER_MODEL": "gemma4:e4b", "CALIPER_DESCRIBER_BASE_URL": "http://h/v1"}

    def test_forced_off_returns_null(self) -> None:
        assert isinstance(describer_from_env(self._CFG, force=False), NullDescriber)

    def test_no_model_returns_null(self) -> None:
        assert isinstance(
            describer_from_env({"CALIPER_DESCRIBER_BASE_URL": "http://h/v1"}), NullDescriber
        )

    def test_no_base_url_returns_null(self) -> None:
        assert isinstance(describer_from_env({"CALIPER_DESCRIBER_MODEL": "m"}), NullDescriber)

    def test_explicit_disable_env_returns_null(self) -> None:
        env = {**self._CFG, "CALIPER_DESCRIBER": "off"}
        assert isinstance(describer_from_env(env), NullDescriber)

    def test_configured_builds_openai_adapter(self) -> None:
        d = describer_from_env(self._CFG)
        assert isinstance(d, OpenAICompatDescriber)

    def test_ollama_host_is_normalized_to_v1_base_url(self) -> None:
        env = {"CALIPER_DESCRIBER_MODEL": "m", "OLLAMA_HOST": "http://localhost:11434"}
        d = describer_from_env(env)
        assert isinstance(d, OpenAICompatDescriber)
        assert d._cfg.base_url == "http://localhost:11434/v1"
