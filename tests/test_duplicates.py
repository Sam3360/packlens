from __future__ import annotations

import warnings

import pytest

from helpers import make_tar, make_zip
from packlens.analysis.duplicates import find_duplicates
from packlens.core.archive import open_archive

FILES = [
    ("x/one.bin", b"A" * 100),
    ("y/two.bin", b"A" * 100),
    ("z/three.bin", b"B" * 100),  # same size, different content
    ("w/solo.bin", b"C" * 77),
    ("e1", b""),
    ("e2", b""),
]


def run(path, **kw):
    with open_archive(path) as handler:
        return find_duplicates(handler, **kw)


@pytest.mark.parametrize("builder,name", [(make_zip, "a.zip"), (make_tar, "a.tar")])
def test_same_size_different_content_is_not_a_duplicate(tmp_path, builder, name):
    report = run(builder(tmp_path / name, FILES))
    assert len(report.groups) == 1
    assert report.groups[0].paths == ["x/one.bin", "y/two.bin"]
    assert report.wasted_bytes == 100
    assert report.candidates_hashed == 3  # the solo file and empties were never hashed


def test_compressed_tar(tmp_path):
    report = run(make_tar(tmp_path / "a.tar.gz", FILES, compression="gz"))
    assert [g.paths for g in report.groups] == [["x/one.bin", "y/two.bin"]]


def test_empty_files_only_with_flag(tmp_path):
    path = make_zip(tmp_path / "a.zip", FILES)
    report = run(path, include_empty=True)
    assert any(g.size == 0 and sorted(g.paths) == ["e1", "e2"] for g in report.groups)


def test_duplicate_names_are_reported_separately_from_duplicate_content(tmp_path):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        path = make_zip(tmp_path / "a.zip", [("same.txt", b"one"), ("same.txt", b"two"), ("other.txt", b"one")])
    report = run(path)
    assert report.repeated_paths == {"same.txt": 2}
    # "same.txt"(first) and "other.txt" hold identical bytes; that is content duplication.
    assert [sorted(g.paths) for g in report.groups] == [["other.txt", "same.txt"]]


def test_no_duplicates(tmp_path):
    report = run(make_zip(tmp_path / "a.zip", {"a": b"1", "b": b"22"}))
    assert report.groups == [] and report.repeated_paths == {}


def test_symlinks_and_directories_are_ignored(tmp_path):
    from helpers import Symlink

    report = run(make_zip(tmp_path / "a.zip", {"d/": None, "f": b"xx", "l": Symlink("f")}))
    assert report.files_examined == 1


def test_unreadable_candidates_are_skipped_not_fatal(tmp_path):
    from helpers import flip_byte
    import zipfile

    path = make_zip(tmp_path / "a.zip", {"a": b"hello world", "b": b"hello world", "c": b"hello world"}, compression=zipfile.ZIP_STORED)
    flip_byte(path, path.read_bytes().index(b"hello world") + 2)
    report = run(path)
    assert len(report.skipped) == 1
    assert len(report.groups) == 1 and len(report.groups[0].paths) == 2
