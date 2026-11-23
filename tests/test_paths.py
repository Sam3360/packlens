from __future__ import annotations

import pytest

from helpers import Hardlink, Special, Symlink, make_tar, make_zip
from packlens.analysis.paths import ArchiveAnalyzer, analyze_path, escapes_root, normalized_key
from packlens.core.archive import open_archive
from packlens.core.limits import Limits
from packlens.core.models import ArchiveEntry, EntryType, Severity


def codes(path: str, depth: int = 32) -> set[str]:
    return {f.code for f in analyze_path(path, warn_depth=depth)}


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/etc/passwd", "absolute-path"),
        ("\\windows\\system32", "absolute-path"),
        ("C:\\Windows\\x.dll", "windows-drive-path"),
        ("c:/x", "windows-drive-path"),
        ("../../etc/passwd", "path-traversal"),
        ("a/../../b", "path-traversal"),
        ("..\\..\\boot.ini", "path-traversal"),
        ("dir\\file.txt", "backslash-separator"),
        ("evil\x00.txt", "control-characters"),
        ("line\nbreak", "control-characters"),
        ("name\u202etxt.exe", "bidi-control"),
        ("bad\udcffname", "invalid-encoding"),
    ],
)
def test_suspicious_paths_are_flagged(path, expected):
    assert expected in codes(path)


@pytest.mark.parametrize("path", ["a/b/c.txt", "./a/b", "dir/", "héllo/日本語.txt", "a/./b", "weird..name/x", "...", "a/b../c"])
def test_ordinary_paths_are_clean(path):
    assert codes(path) == set()


def test_dotdot_that_stays_inside_is_only_a_note_level_reference():
    assert codes("a/../b") == {"parent-reference"}
    assert not escapes_root(["a", "..", "b"])
    assert escapes_root(["a", "..", "..", "b"])


def test_deep_nesting_threshold():
    assert "deep-nesting" in codes("/".join(["d"] * 40), depth=32)
    assert "deep-nesting" not in codes("/".join(["d"] * 32), depth=32)


def test_normalized_key_collapses_equivalent_paths():
    assert normalized_key("./a//b/") == normalized_key("a/b") == "a/b"
    assert normalized_key("a/x/../b") == "a/b"
    assert normalized_key("../x") == "../x"


def analyze(entries, limits=None):
    analyzer = ArchiveAnalyzer(limits or Limits())
    for e in entries:
        analyzer.feed(e)
    return analyzer


def entry(path, kind=EntryType.FILE, **kw):
    kw.setdefault("size", 1)
    return ArchiveEntry(index=kw.pop("index", 0), path=path, type=kind, **kw)


def test_duplicate_paths_and_type_conflicts():
    a = analyze([entry("a.txt"), entry("./a.txt", index=1), entry("b", EntryType.DIRECTORY), entry("b", index=2)])
    assert a.counts["duplicate-path"] == 1
    assert a.counts["type-conflict"] == 1


def test_duplicate_directories_are_not_reported():
    a = analyze([entry("d/", EntryType.DIRECTORY), entry("d", EntryType.DIRECTORY, index=1)])
    assert a.counts["duplicate-path"] == 0


def test_case_and_unicode_collisions_are_notes():
    a = analyze([entry("README"), entry("readme", index=1), entry("caf\u00e9"), entry("cafe\u0301", index=2)])
    assert a.counts["case-collision"] == 2
    assert all(f.severity is Severity.INFO for f in a.findings if f.code == "case-collision")


def test_symlinks_hardlinks_specials():
    a = analyze(
        [
            entry("ok", EntryType.SYMLINK, link_target="sibling.txt"),
            entry("sub/up", EntryType.SYMLINK, link_target="../x"),
            entry("sub/up2", EntryType.SYMLINK, link_target="../../x"),
            entry("abs", EntryType.SYMLINK, link_target="/etc/shadow"),
            entry("h", EntryType.HARDLINK, link_target="a.txt"),
            entry("h2", EntryType.HARDLINK, link_target="../a.txt"),
            entry("dev", EntryType.OTHER),
        ]
    )
    assert a.counts["symlink"] == 2  # sibling.txt and ../x (from sub/, stays inside)
    assert a.counts["symlink-escape"] == 2
    assert a.counts["hardlink"] == 1 and a.counts["hardlink-escape"] == 1
    assert a.counts["special-file"] == 1


def test_large_entry_and_high_ratio_and_setuid():
    limits = Limits(warn_entry_size=1000, warn_ratio=50)
    a = analyze(
        [
            entry("big", size=5000, compressed_size=4000),
            entry("bomb", size=50 * 1024 * 1024, compressed_size=1000),
            entry("tiny-ratio", size=900, compressed_size=1),  # below the minimum size for ratio checks
            entry("suid", mode=0o4755),
        ],
        limits,
    )
    assert a.counts["large-entry"] == 2  # big and bomb
    assert a.counts["high-compression-ratio"] == 1
    assert a.counts["special-permissions"] == 1


def test_finding_storage_is_bounded_but_counts_are_exact():
    a = analyze([entry(f"../x{i}") for i in range(50)], Limits(max_findings=5))
    assert len(a.findings) == 5
    assert a.counts["path-traversal"] == 50
    assert a.suppressed == 45


def test_nested_archive_names_are_noted():
    a = analyze([entry("old/backup.tar.gz"), entry("x.zip"), entry("notes.txt"), entry("dir.zip/", EntryType.DIRECTORY)])
    assert a.counts["nested-archive"] == 2


def test_end_to_end_on_real_archives(tmp_path):
    path = make_tar(
        tmp_path / "x.tar",
        {"ok.txt": b"1", "../escape": b"2", "link": Symlink("/etc/passwd"), "hl": Hardlink("ok.txt"), "fifo": Special(b"6")},
    )
    with open_archive(path) as handler:
        analyzer = analyze(handler.entries())
    assert {"path-traversal", "symlink-escape", "hardlink", "special-file"} <= set(analyzer.counts)


def test_zip_backslash_name_end_to_end(tmp_path):
    path = make_zip(tmp_path / "w.zip", {"..\\..\\evil.dll": b"x"})
    with open_archive(path) as handler:
        analyzer = analyze(handler.entries())
    assert {"path-traversal", "backslash-separator"} <= set(analyzer.counts)
