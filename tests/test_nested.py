from __future__ import annotations

import io

import pytest

from helpers import make_tar, make_zip
from packlens.analysis.nested import archive_label_from_name, magic_format
from packlens.analysis.nested_scan import scan_nested
from packlens.core.archive import open_archive
from packlens.core.errors import EntryNotFoundError
from packlens.core.limits import Budget, Limits
from packlens.core.models import ArchiveFormat


def build(tmp_path, levels=3):
    """level N archive contains level N-1; the innermost has a traversal path."""
    inner = make_tar(tmp_path / "l0.tar.gz", {"../up.txt": b"1", "ok.txt": b"2"}, compression="gz").read_bytes()
    for n in range(1, levels):
        inner = make_zip(tmp_path / f"l{n}.zip", {f"level{n}.zip" if n > 1 else "inner.tar.gz": inner, "note.txt": b"x"}).read_bytes()
    return make_zip(tmp_path / "outer.zip", {"keep.txt": b"k", "nested.zip": inner})


def scan(path, limits=None):
    limits = limits or Limits()
    with open_archive(path, limits) as handler:
        return scan_nested(handler, limits, handler.budget)


def test_name_and_magic_detection():
    assert archive_label_from_name("a/b/backup.tar.gz") == "tar.gz"
    assert archive_label_from_name("x.TGZ") == "tar.gz"
    assert archive_label_from_name("lib.jar") == "zip"
    assert archive_label_from_name("notes.txt") is None
    assert archive_label_from_name(".gz") is None
    assert magic_format(b"PK\x03\x04rest") is ArchiveFormat.ZIP
    assert magic_format(b"plain text") is None


def test_nested_archives_are_inspected_in_memory(tmp_path):
    results = scan(build(tmp_path))
    (top,) = results
    assert top.status == "inspected" and top.path == "nested.zip"
    (child,) = top.children
    assert child.depth == 2
    assert any(f.code == "path-traversal" for r in [child] for f in (r.children[0].report.findings if r.children else r.report.findings))


def test_nested_is_not_scanned_unless_asked(tmp_path):
    path = build(tmp_path)
    from packlens.analysis.inspection import inspect_archive

    with open_archive(path) as handler:
        report = inspect_archive(handler, Limits())
    assert report.nested == []  # only a "nested-archive" note, no recursion
    assert report.finding_counts["nested-archive"] == 1


def test_depth_limit(tmp_path):
    results = scan(build(tmp_path, levels=4), Limits(max_nesting_depth=2))
    (level1,) = results
    (level2,) = level1.children
    (beyond,) = level2.children
    assert level1.status == level2.status == "inspected"
    assert beyond.depth == 3 and beyond.status == "skipped"
    assert "max-nesting-depth" in beyond.reason and beyond.report is None


def test_size_limit_skips_large_members(tmp_path):
    results = scan(build(tmp_path), Limits(max_nested_size=50))
    assert results[0].status == "skipped" and "max-nested-size" in results[0].reason


def test_disguised_archive_found_by_content(tmp_path):
    inner = make_zip(tmp_path / "i.zip", {"a": b"1"}).read_bytes()
    outer = make_zip(tmp_path / "o.zip", {"innocent.dat": inner, "plain.dat": b"just text"})
    results = scan(outer)
    assert [r.path for r in results] == ["innocent.dat"] and results[0].status == "inspected"


def test_fake_archive_name_is_reported_not_fatal(tmp_path):
    outer = make_zip(tmp_path / "o.zip", {"fake.zip": b"not really a zip", "ok.txt": b"x"})
    (result,) = scan(outer)
    assert result.status == "skipped" and "not a recognised archive" in result.reason


def test_unsupported_formats_are_named_not_opened(tmp_path):
    outer = make_zip(tmp_path / "o.zip", {"x.7z": b"7z\xbc\xaf\x27\x1c" + b"\0" * 20})
    (result,) = scan(outer)
    assert result.status == "skipped" and "7z" in result.reason


def test_decompression_bomb_inside_archive_is_bounded(tmp_path):
    import gzip

    bomb = gzip.compress(b"\0" * (30 * 1024 * 1024))
    outer = make_zip(tmp_path / "o.zip", {"bomb.gz": bomb})
    limits = Limits(max_total_bytes=2 * 1024 * 1024)
    (result,) = scan(outer, limits)
    assert result.status in {"skipped", "inspected"}
    if result.status == "inspected":  # listing degrades to "size not measured"
        assert result.report.stats.size_unknown


def test_into_opens_nested_archive_for_all_commands(tmp_path):
    outer = build(tmp_path, levels=2)
    with open_archive(outer, into=["nested.zip", "inner.tar.gz"]) as handler:
        assert {e.path for e in handler.entries()} == {"../up.txt", "ok.txt"}
        assert handler.name == "{}!nested.zip!inner.tar.gz".format(outer)


def test_into_missing_member(tmp_path, sample):
    with pytest.raises(EntryNotFoundError):
        open_archive(make_zip(tmp_path / "a.zip", sample), into=["nope.zip"])


def test_into_respects_size_limit(tmp_path):
    from packlens.core.errors import LimitExceededError

    with pytest.raises(LimitExceededError):
        open_archive(build(tmp_path), Limits(max_nested_size=10), into=["nested.zip"])
