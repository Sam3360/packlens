"""Property-based tests. Skipped automatically when hypothesis is not installed."""

from __future__ import annotations

import io
import unicodedata
import zipfile

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from packlens.analysis.paths import analyze_path, normalized_key  # noqa: E402
from packlens.core.archive import open_archive_stream  # noqa: E402
from packlens.utils.formatting import escape_for_terminal, parse_size  # noqa: E402

any_text = st.text(max_size=200)
name_part = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc"), blacklist_characters="/\\:"),
    min_size=1,
    max_size=12,
).filter(lambda s: s not in (".", "..") and s == s.strip())


@given(any_text)
def test_path_analysis_never_raises(path):
    analyze_path(path, warn_depth=32)


@given(any_text)
def test_normalized_key_is_idempotent(path):
    key = normalized_key(path)
    assert normalized_key(key) == key


@given(st.lists(name_part, min_size=1, max_size=8))
def test_plain_relative_paths_are_never_flagged_as_traversal(parts):
    codes = {f.code for f in analyze_path("/".join(parts), warn_depth=64)}
    assert not codes & {"path-traversal", "absolute-path", "windows-drive-path", "parent-reference"}


@given(any_text)
def test_escaped_text_has_no_control_characters(text):
    escaped = escape_for_terminal(text)
    assert all(unicodedata.category(c) not in ("Cc", "Cs") for c in escaped)


@given(st.integers(min_value=0, max_value=10**15))
def test_parse_size_accepts_plain_integers(n):
    assert parse_size(str(n)) == n


@settings(max_examples=40, deadline=None)
@given(st.dictionaries(name_part, st.binary(max_size=300), min_size=0, max_size=8))
def test_zip_round_trip(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    buffer.seek(0)
    with open_archive_stream(buffer, "prop.zip") as handler:
        assert sorted(e.path for e in handler.entries()) == sorted(files)
        contents = {e.path: s.read() for e, s in handler.iter_data() if s is not None}
    assert contents == files
