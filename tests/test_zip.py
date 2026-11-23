from __future__ import annotations

import zipfile

import pytest

from helpers import Symlink, flip_byte, make_zip, truncate
from packlens.core.archive import open_archive
from packlens.core.errors import ArchiveReadError, LimitExceededError
from packlens.core.limits import Limits
from packlens.core.models import EntryType


def entries_of(path, **kw):
    with open_archive(path, **kw) as handler:
        return list(handler.entries())


def test_lists_files_and_directories(tmp_path, sample):
    entries = entries_of(make_zip(tmp_path / "a.zip", sample))
    by_path = {e.path: e for e in entries}
    assert by_path["src/"].type is EntryType.DIRECTORY
    assert by_path["src/main.py"].type is EntryType.FILE
    assert by_path["src/main.py"].size == len(sample["src/main.py"])
    assert [e.index for e in entries] == list(range(len(entries)))


def test_metadata_fields(tmp_path):
    path = make_zip(tmp_path / "a.zip", {"f.txt": b"x" * 1000})
    (entry,) = entries_of(path)
    assert entry.compression == "deflate"
    assert entry.compressed_size is not None and entry.compressed_size < 1000
    assert entry.crc32 == zipfile.ZipFile(path).getinfo("f.txt").CRC
    assert entry.mtime is not None and entry.mtime.year == 2024
    assert entry.mode == 0o644


def test_stored_compression_reported(tmp_path):
    path = make_zip(tmp_path / "a.zip", {"f.txt": b"x" * 100}, compression=zipfile.ZIP_STORED)
    assert entries_of(path)[0].compression == "stored"


def test_symlink_entry_and_target(tmp_path):
    path = make_zip(tmp_path / "a.zip", {"link": Symlink("../../etc/passwd")})
    (entry,) = entries_of(path)
    assert entry.type is EntryType.SYMLINK
    assert entry.link_target == "../../etc/passwd"


def test_empty_zip(tmp_path):
    path = make_zip(tmp_path / "e.zip", {})
    with open_archive(path) as handler:
        assert list(handler.entries()) == []
        assert handler.info().compressed_size == 22


def test_unicode_names_round_trip(tmp_path):
    names = ["héllo/wörld.txt", "日本語/ファイル.txt", "emoji-😀.txt", "cyrillic/файл.txt"]
    path = make_zip(tmp_path / "u.zip", {n: b"data" for n in names})
    assert sorted(e.path for e in entries_of(path)) == sorted(names)


def test_duplicate_names_are_kept_as_separate_entries(tmp_path):
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        path = make_zip(tmp_path / "d.zip", [("a.txt", b"one"), ("a.txt", b"two!")])
    entries = entries_of(path)
    assert [e.path for e in entries] == ["a.txt", "a.txt"]
    assert [e.size for e in entries] == [3, 4]
    with open_archive(path) as handler:
        data = {entry.index: stream.read() for entry, stream in handler.iter_data()}
    assert data == {0: b"one", 1: b"two!"}  # both are readable, not just the last


def test_backslash_names_are_preserved(tmp_path):
    path = make_zip(tmp_path / "b.zip", {"a\\b.txt": b"x"})
    assert entries_of(path)[0].path == "a\\b.txt"


def test_archive_comment_in_info(tmp_path):
    path = make_zip(tmp_path / "c.zip", {"a": b"1"}, comment=b"built by tests")
    with open_archive(path) as handler:
        assert handler.info().metadata["comment"] == "built by tests"


def test_iter_data_streams_contents(tmp_path, sample):
    path = make_zip(tmp_path / "a.zip", sample)
    with open_archive(path) as handler:
        contents = {e.path: s.read() for e, s in handler.iter_data() if s is not None}
    assert contents["src/main.py"] == sample["src/main.py"]
    assert "src/" not in contents


def test_large_entry_is_streamed(tmp_path):
    big = tmp_path / "big.zip"
    with zipfile.ZipFile(big, "w", zipfile.ZIP_DEFLATED) as zf:
        with zf.open("zeros.bin", "w", force_zip64=True) as out:
            for _ in range(100):
                out.write(b"\0" * (1024 * 1024))
    with open_archive(big) as handler:
        total = 0
        for entry, stream in handler.iter_data():
            while chunk := stream.read(65536):
                total += len(chunk)
    assert total == 100 * 1024 * 1024


def test_source_is_never_modified(tmp_path, sample):
    path = make_zip(tmp_path / "a.zip", sample)
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    with open_archive(path) as handler:
        list(handler.entries())
        for _entry, stream in handler.iter_data():
            if stream is not None:
                stream.read()
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_not_a_zip_raises_read_error(tmp_path, sample):
    path = make_zip(tmp_path / "a.zip", sample)
    truncate(path, path.stat().st_size - 30)  # chops the end-of-central-directory record
    with pytest.raises(ArchiveReadError):
        open_archive(path)


def test_entry_count_limit_is_checked_before_parsing(tmp_path):
    path = make_zip(tmp_path / "many.zip", {f"f{i}": b"" for i in range(50)})
    with pytest.raises(LimitExceededError, match="max-entries"):
        open_archive(path, Limits(max_entries=10))


def test_corrupted_data_surfaces_as_read_error(tmp_path):
    path = make_zip(tmp_path / "a.zip", {"f.txt": b"hello world" * 100}, compression=zipfile.ZIP_STORED)
    flip_byte(path, 40)  # inside the stored file data
    with open_archive(path) as handler:
        with pytest.raises(ArchiveReadError):
            for _entry, stream in handler.iter_data():
                stream.read()


def test_encrypted_flag_and_unreadable_stream(tmp_path):
    path = make_zip(tmp_path / "a.zip", {"f.txt": b"secret"})
    data = bytearray(path.read_bytes())
    # Set the "encrypted" general-purpose flag in both the local and central headers.
    for sig in (b"PK\x03\x04", b"PK\x01\x02"):
        pos = data.find(sig)
        offset = pos + (6 if sig == b"PK\x03\x04" else 8)
        data[offset] |= 0x1
    path.write_bytes(bytes(data))
    with open_archive(path) as handler:
        (entry,) = list(handler.entries())
        assert entry.encrypted
        for _e, stream in handler.iter_data():
            with pytest.raises(Exception, match="encrypted"):
                stream.read()


def test_unsupported_zip_version_is_a_clean_error(tmp_path):
    # Found by fuzzing: zipfile raised NotImplementedError from its constructor.
    from packlens.core.errors import UnsupportedFeatureError

    path = make_zip(tmp_path / "a.zip", {"f": b"x"})
    data = bytearray(path.read_bytes())
    pos = data.index(b"PK\x01\x02")
    data[pos + 6 : pos + 8] = (136).to_bytes(2, "little")  # "version needed" 13.6
    path.write_bytes(bytes(data))
    with pytest.raises(UnsupportedFeatureError):
        open_archive(path)


def test_corrupt_local_header_offset_is_a_failed_check_not_a_crash(tmp_path):
    # Found by fuzzing: a bogus offset made zipfile raise "negative seek value".
    from packlens.analysis.integrity import verify_archive

    path = make_zip(tmp_path / "a.zip", {"f": b"x" * 100})
    data = bytearray(path.read_bytes())
    pos = data.index(b"PK\x01\x02")
    data[pos + 42 : pos + 46] = (0x7FFFFFF0).to_bytes(4, "little")  # local header offset
    path.write_bytes(bytes(data))
    with open_archive(path) as handler:
        report = verify_archive(handler)
    assert report.verdict == "failed" and report.failed == 1


def test_fixture_really_stores_backslashes(tmp_path):
    # Guards the test helper itself: on Windows zipfile rewrites "\\" in ZipInfo.filename, which is
    # what gets written, so a naive fixture builds an archive with no backslash in it at all.
    path = make_zip(tmp_path / "w.zip", {"a\\b.txt": b"x"})
    assert b"a\\b.txt" in path.read_bytes()
    assert b"a/b.txt" not in path.read_bytes()


def test_names_do_not_depend_on_zipfile_name_handling(tmp_path, monkeypatch):
    # Even if a Python version also normalised ZipInfo.orig_filename, entry paths must be the
    # names stored in the archive, because path analysis inspects the real representation.
    path = make_zip(tmp_path / "w.zip", {"a\\b.txt": b"x", "..\\..\\evil.dll": b"y", "ok/f.txt": b"z"})
    original = zipfile.ZipInfo.__init__

    def normalising_init(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.orig_filename = self.filename.replace("\\", "/")

    monkeypatch.setattr(zipfile.ZipInfo, "__init__", normalising_init)
    assert [e.path for e in entries_of(path)] == ["a\\b.txt", "..\\..\\evil.dll", "ok/f.txt"]


def test_stored_names_with_prefix_and_unicode(tmp_path):
    plain = make_zip(tmp_path / "p.zip", {"d\u00e9j\u00e0/\u65e5\u672c.txt": b"1", "x\\y": b"2"})
    prefixed = tmp_path / "prefixed.bin"
    prefixed.write_bytes(b"#!/bin/sh\n" * 7 + plain.read_bytes())
    assert [e.path for e in entries_of(prefixed)] == ["d\u00e9j\u00e0/\u65e5\u672c.txt", "x\\y"]
