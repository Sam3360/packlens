from __future__ import annotations

import pytest

from helpers import Symlink, make_tar, make_zip
from packlens.analysis.comparison import CompareMode, compare_archives
from packlens.core.archive import open_archive


def compare(old, new, mode=CompareMode.SIZE, **kw):
    with open_archive(old) as a, open_archive(new) as b:
        return compare_archives(a, b, mode, include_metadata=kw.get("metadata", False))


OLD = {"keep.txt": b"same", "edit.txt": b"before", "swap.txt": b"AAAA", "gone.txt": b"x", "d/": None}
NEW = {"keep.txt": b"same", "edit.txt": b"after!!", "swap.txt": b"BBBB", "new.txt": b"n", "d/": None}


def test_added_removed_changed_by_size(tmp_path):
    r = compare(make_zip(tmp_path / "o.zip", OLD), make_zip(tmp_path / "n.zip", NEW))
    assert [e.path for e in r.added] == ["new.txt"]
    assert [e.path for e in r.removed] == ["gone.txt"]
    assert [c.path for c in r.changed] == ["edit.txt", "swap.txt"]  # swap.txt via differing CRC-32
    assert r.same_size_unverified == 1  # keep.txt: size only; it is NOT called identical
    assert r.identical == 0


def test_same_size_is_never_called_identical_across_formats(tmp_path):
    # tar has no CRC, so equal sizes prove nothing in size mode.
    r = compare(make_tar(tmp_path / "o.tar", {"f": b"AAAA"}), make_tar(tmp_path / "n.tar", {"f": b"BBBB"}))
    assert r.changed == [] and r.identical == 0 and r.same_size_unverified == 1


def test_hash_mode_distinguishes_same_size_files(tmp_path):
    r = compare(make_tar(tmp_path / "o.tar", {"f": b"AAAA", "g": b"same"}), make_tar(tmp_path / "n.tar.gz", {"f": b"BBBB", "g": b"same"}, compression="gz"), CompareMode.HASH)
    assert [c.path for c in r.changed] == ["f"]
    assert r.changed[0].reasons == ["content differs (SHA-256)"]
    assert r.identical == 1


def test_path_mode_ignores_sizes(tmp_path):
    r = compare(make_zip(tmp_path / "o.zip", OLD), make_zip(tmp_path / "n.zip", NEW), CompareMode.PATH)
    assert r.changed == [] and len(r.added) == 1 and len(r.removed) == 1
    assert r.identical == 0 and r.same_size_unverified == 0


def test_empty_files_are_identical_without_hashing(tmp_path):
    r = compare(make_zip(tmp_path / "o.zip", {"e": b""}), make_zip(tmp_path / "n.zip", {"e": b""}))
    assert r.identical == 1


def test_type_and_link_changes(tmp_path):
    old = make_tar(tmp_path / "o.tar", {"a": b"file", "l": Symlink("x")})
    new = make_tar(tmp_path / "n.tar", {"a": Symlink("elsewhere"), "l": Symlink("y")})
    r = compare(old, new)
    reasons = {c.path: c.reasons[0] for c in r.changed}
    assert reasons["a"].startswith("type:") and reasons["l"].startswith("link target:")


def test_equivalent_spellings_of_a_path_match(tmp_path):
    r = compare(make_tar(tmp_path / "o.tar", {"./a/b.txt": b"1"}), make_tar(tmp_path / "n.tar", {"a/b.txt": b"1"}))
    assert not r.added and not r.removed


def test_metadata_differences_are_opt_in(tmp_path):
    old = make_tar(tmp_path / "o.tar", {"f": b"x"})
    new = make_tar(tmp_path / "n.tar", {"f": b"x"})
    import os, tarfile, io

    with tarfile.open(new, "w") as tf:  # same content, different mode and mtime
        info = tarfile.TarInfo("f")
        info.size, info.mode, info.mtime = 1, 0o755, 1_800_000_000
        tf.addfile(info, io.BytesIO(b"x"))
    assert compare(old, new).metadata_changes == []
    diff = dict(compare(old, new, metadata=True).metadata_changes)["f"]
    assert set(diff) == {"mode", "mtime"}


def test_zip_vs_tar_mtime_is_not_compared(tmp_path):
    r = compare(make_zip(tmp_path / "o.zip", {"f": b"x"}), make_tar(tmp_path / "n.tar", {"f": b"x"}), metadata=True)
    assert all("mtime" not in d for _, d in r.metadata_changes)


def test_identical_archives(tmp_path, sample):
    p = make_zip(tmp_path / "a.zip", sample)
    r = compare(p, p, CompareMode.HASH)
    assert not r.added and not r.removed and not r.changed
    assert r.identical == 4
