"""Shared Hypothesis strategies for the diff/path/manifest parser boundary tests.

# tested-by: tests/unit/test_diff.py, test_sbom_diff.py, test_ignore.py,
#            test_pr_ref.py, test_manifest_discovery.py

Single source of truth for the input shapes fuzzed against caliper's five
pure-parsing boundaries (``core/diff.py``, ``core/sbom_diff.py``,
``core/ignore.py``, ``core/pr_ref.py``, ``core/manifest_discovery.py``). Each
of those parser test files imports from here instead of hand-rolling its own
ad-hoc strategy, so a single fix/tuning of e.g. "what a plausible path looks
like" propagates to every consumer.

Strategies are grouped by shape, not by which parser uses them — several are
shared across more than one parser's test file.
"""

from __future__ import annotations

from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Generic malformed / edge-case text
# ---------------------------------------------------------------------------

# Printable-ish unicode text, deliberately excluding lone surrogates (category
# "Cs") which cannot round-trip through UTF-8 encode/decode or json.dumps.
_SAFE_TEXT_ALPHABET = st.characters(blacklist_categories=("Cs",))


def garbage_text(max_size: int = 200) -> st.SearchStrategy[str]:
    """Arbitrary unicode text with no assumed structure at all.

    The catch-all fuzz strategy: for any parser boundary, "some human or
    machine handed me literally any string" must never crash the process.
    """
    return st.text(alphabet=_SAFE_TEXT_ALPHABET, max_size=max_size)


def whitespace_and_control_text(max_size: int = 40) -> st.SearchStrategy[str]:
    """Strings built only from whitespace / control characters.

    Regresses against parsers that assume ``.strip()`` always leaves
    something behind, or that blank-ish input is indistinguishable from
    genuinely empty input.
    """
    return st.text(
        alphabet=st.sampled_from(" \t\n\r\x0b\x0c\x00"),
        max_size=max_size,
    )


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PATH_SEGMENT_ALPHABET = st.sampled_from(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
)


def path_segment(min_size: int = 1, max_size: int = 12) -> st.SearchStrategy[str]:
    """A single plausible path component (no separators)."""
    return st.text(alphabet=_PATH_SEGMENT_ALPHABET, min_size=min_size, max_size=max_size)


@st.composite
def plausible_relative_path(draw: st.DrawFn, min_depth: int = 1, max_depth: int = 5) -> str:
    """A plausible forward-slash-separated relative file path.

    e.g. ``"src/pkg/module.py"`` — no leading slash, no ``..`` segments, no
    empty segments. This is the "normal" case every parser must handle
    without drama.
    """
    depth = draw(st.integers(min_value=min_depth, max_value=max_depth))
    segments = [draw(path_segment()) for _ in range(depth)]
    return "/".join(segments)


@st.composite
def path_traversal_shaped(draw: st.DrawFn) -> str:
    """A path-looking string with ``..`` traversal segments woven in.

    Mirrors ``../../etc/passwd``-style inputs: variable traversal depth,
    optional leading ``/``, mixed forward/back slashes, optional trailing
    segment. Used to check path-handling parsers don't loop, don't raise,
    and don't accidentally match something they shouldn't.
    """
    depth = draw(st.integers(min_value=0, max_value=6))
    traversal = "/".join([".."] * depth)
    tail_depth = draw(st.integers(min_value=0, max_value=3))
    tail = "/".join(draw(path_segment()) for _ in range(tail_depth))
    leading_slash = draw(st.booleans())
    use_backslash = draw(st.booleans())

    parts = [p for p in (traversal, tail) if p]
    combined = "/".join(parts)
    if leading_slash:
        combined = "/" + combined
    if use_backslash:
        combined = combined.replace("/", "\\")
    return combined


def any_path_like_text(max_size: int = 100) -> st.SearchStrategy[str]:
    """Free-form text that may or may not resemble a path at all."""
    return st.text(
        alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
        max_size=max_size,
    )


# ---------------------------------------------------------------------------
# Version strings
# ---------------------------------------------------------------------------


def semver_like_version() -> st.SearchStrategy[str]:
    """A well-formed ``MAJOR.MINOR.PATCH`` version string."""
    return st.builds(
        lambda a, b, c: f"{a}.{b}.{c}",
        a=st.integers(min_value=0, max_value=999),
        b=st.integers(min_value=0, max_value=999),
        c=st.integers(min_value=0, max_value=999),
    )


def malformed_version_string() -> st.SearchStrategy[str]:
    """Version-shaped text that a semver parser should choke on gracefully."""
    return st.one_of(
        st.just(""),
        st.just("*"),
        st.just("latest"),
        st.just("x"),
        st.just("not-a-version"),
        st.from_regex(r"[0-9]+\.[a-z]+\.[0-9]+", fullmatch=True),
        garbage_text(max_size=30),
    )


# ---------------------------------------------------------------------------
# requirements.txt-shaped lines
# ---------------------------------------------------------------------------

_PKG_NAME_ALPHABET = st.sampled_from(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)
_REQ_OPERATORS = st.sampled_from(["==", ">=", "<=", "~=", "!=", ">", "<"])


@st.composite
def valid_requirement_line(draw: st.DrawFn) -> str:
    """A syntactically valid ``requirements.txt`` line.

    ``name``, ``name[extra]``, ``name==1.2.3``, ``name[extra]>=1.0`` — the
    shapes ``_parse_requirement_line`` is documented to support.
    """
    name = draw(
        st.text(alphabet=_PKG_NAME_ALPHABET, min_size=1, max_size=20).filter(
            lambda s: s[0].isalnum()
        )
    )
    has_extra = draw(st.booleans())
    extra = ""
    if has_extra:
        extra_name = draw(st.text(alphabet=_PKG_NAME_ALPHABET, min_size=1, max_size=10))
        extra = f"[{extra_name}]"
    has_version = draw(st.booleans())
    version_part = ""
    if has_version:
        op = draw(_REQ_OPERATORS)
        version = draw(semver_like_version())
        version_part = f"{op}{version}"
    return f"{name}{extra}{version_part}"


@st.composite
def malformed_requirement_line(draw: st.DrawFn) -> str:
    """Lines that look almost like a requirement but aren't, or are noise.

    Comments, blank/whitespace-only lines, ``-e``/``-r`` pip directives,
    dangling operators, and plain garbage — everything
    ``_parse_requirement_line`` must return ``None`` for instead of raising.
    """
    return draw(
        st.one_of(
            st.just(""),
            st.just("   "),
            st.builds(lambda s: f"# {s}", garbage_text(max_size=40)),
            st.builds(lambda s: f"-e {s}", garbage_text(max_size=40)),
            st.builds(lambda s: f"-r {s}", garbage_text(max_size=40)),
            st.builds(lambda op: f"{op}1.0", _REQ_OPERATORS),  # dangling operator, no name
            garbage_text(max_size=60),
            whitespace_and_control_text(),
        )
    )


# ---------------------------------------------------------------------------
# GitHub PR reference shapes
# ---------------------------------------------------------------------------

_SLUG_COMPONENT = st.text(alphabet=_PKG_NAME_ALPHABET, min_size=1, max_size=15)


@st.composite
def valid_pr_url(draw: st.DrawFn) -> str:
    """A well-formed GitHub PR URL, optionally with a trailing sub-path."""
    scheme = draw(st.sampled_from(["https", "http"]))
    owner = draw(_SLUG_COMPONENT)
    repo = draw(_SLUG_COMPONENT)
    number = draw(st.integers(min_value=1, max_value=999_999))
    suffix = draw(st.sampled_from(["", "/files", "/commits", "#discussion_r1"]))
    return f"{scheme}://github.com/{owner}/{repo}/pull/{number}{suffix}"


@st.composite
def bare_pr_number(draw: st.DrawFn) -> str:
    """A bare PR number, optionally ``#``-prefixed."""
    number = draw(st.integers(min_value=1, max_value=999_999))
    hashed = draw(st.booleans())
    return f"#{number}" if hashed else str(number)


@st.composite
def malformed_pr_ref(draw: st.DrawFn) -> str:
    """Text that must raise a clean ``ValueError``, never an unhandled crash.

    Near-miss PR URLs (wrong host, missing number, non-numeric number, zero
    /negative number), non-URL garbage, and plain noise.
    """
    return draw(
        st.one_of(
            st.just(""),
            st.just("0"),
            st.just("-5"),
            st.just("https://github.com/o/r/pull/"),
            st.just("https://github.com/o/r/pull/0"),
            st.just("https://github.com/o/r/pull/abc"),
            st.builds(
                lambda o, r: f"https://gitlab.com/{o}/{r}/pull/5", _SLUG_COMPONENT, _SLUG_COMPONENT
            ),
            st.builds(
                lambda o, r: f"https://github.com/{o}/{r}/pulls/5", _SLUG_COMPONENT, _SLUG_COMPONENT
            ),
            garbage_text(max_size=60),
            whitespace_and_control_text(),
        )
    )


# ---------------------------------------------------------------------------
# Manifest / lockfile filename shapes
# ---------------------------------------------------------------------------

_KNOWN_MANIFEST_NAMES = (
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "Cargo.toml",
    "go.mod",
    "Gemfile",
    "pom.xml",
    "build.gradle",
)

_KNOWN_LOCKFILE_NAMES = (
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
)


def known_manifest_name() -> st.SearchStrategy[str]:
    """One of the exact filenames ``manifest_discovery.MANIFEST_MAP`` recognizes."""
    return st.sampled_from(_KNOWN_MANIFEST_NAMES)


def known_lockfile_name() -> st.SearchStrategy[str]:
    """One of the exact filenames ``manifest_discovery.LOCKFILE_MAP`` recognizes."""
    return st.sampled_from(_KNOWN_LOCKFILE_NAMES)


@st.composite
def near_miss_manifest_filename(draw: st.DrawFn) -> str:
    """A filename that looks *almost* like a known manifest/lockfile but isn't.

    Case variants, trailing junk, missing/extra characters, and directory-like
    suffixes — none of these must be misclassified as a real manifest.
    """
    base = draw(st.sampled_from(_KNOWN_MANIFEST_NAMES + _KNOWN_LOCKFILE_NAMES))
    mutation = draw(st.sampled_from(["upper", "lower", "suffix", "prefix", "truncate", "swapcase"]))
    if mutation == "upper":
        return base.upper()
    if mutation == "lower":
        return base.lower()
    if mutation == "swapcase":
        return base.swapcase()
    if mutation == "suffix":
        junk = draw(path_segment(min_size=1, max_size=6))
        return f"{base}.{junk}"
    if mutation == "prefix":
        junk = draw(path_segment(min_size=1, max_size=6))
        return f"{junk}.{base}"
    # truncate
    if len(base) <= 1:
        return base
    cut = draw(st.integers(min_value=1, max_value=len(base) - 1))
    return base[:cut]


@st.composite
def filesystem_safe_filename(draw: st.DrawFn, max_size: int = 20) -> str:
    """A filename fragment safe to actually create on disk (no separators/NUL)."""
    return draw(
        st.text(alphabet=_PATH_SEGMENT_ALPHABET, min_size=1, max_size=max_size).filter(
            lambda s: s not in {".", ".."}
        )
    )
