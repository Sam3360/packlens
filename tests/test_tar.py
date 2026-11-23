from __future__ import annotations

import tarfile

import pytest

from helpers import Hardlink, Special, Symlink, flip_byte, make_tar, truncate
from packlens.core.archive import open_archive
from packlens.core.errors import ArchiveReadError, LimitExceededError
from packlens.core.limits import Limits
from packlens.core.models import ArchiveFormat, EntryType

VARIANTS = [
    ("", ArchiveFormat.TAR),
    ("gz", ArchiveFormat.TAR_GZ),
    ("bz2", ArchiveFormat.TAR_BZ2),
    ("xz", ArchiveFormat.TAR_XZ),
]


def entries_of(path, **kw):
    with open_archive(path, **kw) as handler:
        return list(handler.entries())


@pytest.mark.parametrize("comp,fmt", VARIANTS)
def test_every_compression_variant_lists_the_same_entries(tmp_path, sample, comp, fmt):
    path = make_tar(tmp_path / f"a.tar.{comp or 'x'}", sample, compression=comp)
    with open_archive(path) as handler:
        assert handler.format is fmt
        entries = list(handler.entries())
    assert {e.path for e in entries} == {k.rstrip("/") for k in sample}
    main = next(e for e in entries if e.path == "src/main.py")
    assert main.size == len(sample["src/main.py"])
    assert main.mode == 0o644
    assert main.mtime is not None and main.mtime.year == 2023


@pytest.mark.parametrize("comp,fmt", VARIANTS)
def test_iter_data_streams_every_variant(tmp_path, sample, comp, fmt):
    path = make_tar(tmp_path / "a.tar", sample, compression=comp)
    with open_archive(path) as handler:
        contents = {e.path: s.read() for e, s in handler.iter_data() if s is not None}
    assert contents["docs/guide.txt"] == sample["docs/guide.txt"]
    assert len(contents) == 4


def test_link_and_special_entries(tmp_path):
    path = make_tar(
        tmp_path / "a.tar",
        {
            "real.txt": b"data",
            "sym": Symlink("real.txt"),
            "hard": Hardlink("real.txt"),
            "pipe": Special(tarfile.FIFOTYPE),
        },
    )
    kinds = {e.path: e for e in entries_of(path)}
    assert kinds["sym"].type is EntryType.SYMLINK and kinds["sym"].link_target == "real.txt"
    assert kinds["hard"].type is EntryType.HARDLINK and kinds["hard"].link_target == "real.txt"
    assert kinds["pipe"].type is EntryType.OTHER


@pytest.mark.parametrize("comp", ["", "gz", "bz2", "xz"])
def test_empty_archives(tmp_path, comp):
    path = make_tar(tmp_path / "empty.tar", {}, compression=comp)
    with open_archive(path) as handler:
        assert list(handler.entries()) == []
        assert handler.notes() == []


def test_unicode_and_long_names(tmp_path):
    long_name = "d/" * 80 + "file-ü.txt"  # longer than the 100-byte ustar limit
    names = ["日本語/ファイル.txt", "emoji-😀.txt", long_name]
    path = make_tar(tmp_path / "u.tar.gz", {n: b"x" for n in names}, compression="gz")
    assert sorted(e.path for e in entries_of(path)) == sorted(names)


def test_duplicate_member_names_are_both_listed(tmp_path):
    path = make_tar(tmp_path / "d.tar", [("a.txt", b"one"), ("a.txt", b"two!")])
    assert [e.size for e in entries_of(path)] == [3, 4]


def test_traversal_names_are_reported_verbatim(tmp_path):
    path = make_tar(tmp_path / "t.tar", {"../../evil.txt": b"x", "/abs.txt": b"y"})
    assert {e.path for e in entries_of(path)} == {"../../evil.txt", "/abs.txt"}


def test_entry_limit(tmp_path):
    path = make_tar(tmp_path / "m.tar", {f"f{i}": b"" for i in range(30)})
    with pytest.raises(LimitExceededError, match="max-entries"):
        entries_of(path, limits=Limits(max_entries=5))


def test_source_is_never_modified(tmp_path, sample):
    path = make_tar(tmp_path / "a.tar.gz", sample, compression="gz")
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    with open_archive(path) as handler:
        list(handler.entries())
        for _e, stream in handler.iter_data():
            if stream is not None:
                stream.read()
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_truncated_inside_member_data(tmp_path):
    path = make_tar(tmp_path / "a.tar", {"big.bin": b"z" * 5000, "after.txt": b"tail"})
    truncate(path, 1024)  # header + part of the data
    with pytest.raises(ArchiveReadError):
        entries_of(path)


def test_truncated_compressed_stream(tmp_path):
    import os

    payload = {f"f{i}.bin": os.urandom(4000) for i in range(10)}  # incompressible
    path = make_tar(tmp_path / "a.tar.gz", payload, compression="gz")
    truncate(path, path.stat().st_size // 2)
    with pytest.raises(ArchiveReadError):
        entries_of(path)


def test_missing_end_marker_is_noted_when_listing(tmp_path):
    path = make_tar(tmp_path / "a.tar", {"a.txt": b"x" * 600})
    truncate(path, 512 + 1024)  # exactly header + padded data, no zero blocks
    with open_archive(path) as handler:
        assert [e.path for e in handler.entries()] == ["a.txt"]
        assert any(n.code == "tar-structure" for n in handler.notes())


def test_corrupt_second_header_is_not_silently_ignored(tmp_path):
    path = make_tar(tmp_path / "a.tar", {"a.txt": b"x" * 100, "b.txt": b"y" * 100})
    # tarfile alone would treat the damaged second header as end-of-archive.
    flip_byte(path, 1024 + 5)  # second header starts at 512 (header) + 512 (data)
    with open_archive(path) as handler:
        assert [e.path for e in handler.entries()] == ["a.txt"]
        assert any("invalid header" in n.message for n in handler.notes())
    with open_archive(path) as handler:
        with pytest.raises(ArchiveReadError, match="invalid header"):
            for _e, stream in handler.iter_data(complete=True):
                if stream:
                    stream.read()


def test_partial_trailing_header_is_detected(tmp_path):
    path = make_tar(tmp_path / "a.tar", {"a.txt": b"x" * 100, "b.txt": b"y" * 100})
    truncate(path, 1024 + 200)  # cut inside the second header
    with open_archive(path) as handler:
        with pytest.raises(ArchiveReadError, match="truncated header"):
            for _e, stream in handler.iter_data(complete=True):
                if stream:
                    stream.read()


def test_read_entry_bytes_random_access(tmp_path, sample):
    path = make_tar(tmp_path / "a.tar.xz", sample, compression="xz")
    with open_archive(path) as handler:
        target = next(e for e in handler.entries() if e.path == "docs/guide.txt")
        assert handler.read_entry_bytes(target, None) == sample["docs/guide.txt"]
