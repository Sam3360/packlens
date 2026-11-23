from __future__ import annotations

import os
import zipfile

import pytest

from helpers import flip_byte, make_stream, make_tar, make_zip, truncate
from packlens.analysis.integrity import CheckStatus, verify_archive
from packlens.core.archive import open_archive
from packlens.core.errors import LimitExceededError
from packlens.core.limits import Limits


def verify(path, **kw):
    with open_archive(path, **kw) as handler:
        return verify_archive(handler)


@pytest.mark.parametrize("key", ["zip", "tar", "tar.gz", "tar.bz2", "tar.xz", "gzip", "bzip2", "xz"])
def test_valid_archives_pass(archives, key):
    report = verify(archives[key])
    assert report.verdict == "passed"
    assert report.failed == 0 and report.unavailable == 0
    assert report.structure.status is CheckStatus.PASSED


def test_levels_do_not_overclaim(archives):
    assert verify(archives["zip"]).level == "content-checksums"
    assert verify(archives["gzip"]).level == "content-checksums"
    assert verify(archives["tar"]).level == "structure-and-readability"
    assert verify(archives["tar.gz"]).level == "structure-and-readability"


def test_zip_crc_corruption_is_pinpointed(tmp_path):
    path = make_zip(tmp_path / "a.zip", {"good.txt": b"g" * 200, "bad.txt": b"hello world" * 50, "also-good.txt": b"z" * 200}, compression=zipfile.ZIP_STORED)
    offset = path.read_bytes().index(b"hello world") + 3
    flip_byte(path, offset)
    report = verify(path)
    assert report.verdict == "failed"
    assert report.failed == 1 and report.passed == 2  # other entries are still checked
    assert report.results[0].path == "bad.txt"


def test_zip_deflate_corruption(tmp_path):
    path = make_zip(tmp_path / "a.zip", {"f.bin": os.urandom(3000) + b"A" * 3000})
    flip_byte(path, 60)
    assert verify(path).verdict == "failed"


def test_zip_truncated_central_directory_is_a_read_error(tmp_path, sample):
    from packlens.core.errors import ArchiveReadError

    path = make_zip(tmp_path / "a.zip", sample)
    truncate(path, path.stat().st_size - 40)
    with pytest.raises(ArchiveReadError):
        open_archive(path)


def test_zip_lying_size_is_detected(tmp_path):
    path = make_zip(tmp_path / "a.zip", {"f.txt": b"abc" * 100}, compression=zipfile.ZIP_STORED)
    data = bytearray(path.read_bytes())
    # Central directory header: uncompressed size is at offset 24 of the record.
    pos = data.index(b"PK\x01\x02") + 24
    data[pos : pos + 4] = (299).to_bytes(4, "little")
    path.write_bytes(bytes(data))
    assert verify(path).verdict == "failed"


@pytest.mark.parametrize("comp", ["", "gz", "bz2", "xz"])
def test_tar_truncation_fails(tmp_path, comp):
    payload = {f"f{i}.bin": os.urandom(5000) for i in range(6)}
    path = make_tar(tmp_path / "a.tar", payload, compression=comp)
    truncate(path, path.stat().st_size * 2 // 3)
    assert verify(path).verdict == "failed"


def test_compressed_tar_trailer_damage_is_caught(tmp_path):
    path = make_tar(tmp_path / "a.tar.gz", {"a.txt": b"hello" * 100}, compression="gz")
    size = path.stat().st_size
    flip_byte(path, size - 6)  # inside the gzip CRC-32 trailer
    report = verify(path)
    assert report.verdict == "failed"


def test_tar_without_end_marker_fails(tmp_path):
    path = make_tar(tmp_path / "a.tar", {"a.txt": b"x" * 600})
    truncate(path, 512 + 1024)
    assert verify(path).verdict == "failed"


def test_stream_corruption(tmp_path):
    path = make_stream(tmp_path / "a.gz", os.urandom(2000), "gzip")
    flip_byte(path, 100)
    assert verify(path).verdict == "failed"


@pytest.mark.parametrize("codec", ["gzip", "bzip2", "xz"])
def test_truncated_stream_fails(tmp_path, codec):
    path = make_stream(tmp_path / "a.bin", os.urandom(20000), codec)
    truncate(path, path.stat().st_size - 10)
    assert verify(path).verdict == "failed"


def test_encrypted_entries_are_unavailable_not_passed(tmp_path):
    path = make_zip(tmp_path / "a.zip", {"s.txt": b"secret", "p.txt": b"plain"})
    data = bytearray(path.read_bytes())
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        data[data.index(sig) + off] |= 0x1
    path.write_bytes(bytes(data))
    report = verify(path)
    assert report.verdict == "incomplete"
    assert report.unavailable == 1 and report.passed == 1


def set_zip_method(path, method):
    """Rewrite the compression method in both the local and central headers."""
    data = bytearray(path.read_bytes())
    for sig, off in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):
        pos = data.index(sig) + off
        data[pos : pos + 2] = method.to_bytes(2, "little")
    path.write_bytes(bytes(data))


def test_unsupported_compression_is_unavailable(tmp_path):
    # Method 98 (PPMd) is not implemented by any Python version. Zstandard (93) used to be the
    # example here, but Python 3.14 can decode it, so it is no longer a valid "unsupported" case.
    path = make_zip(tmp_path / "a.zip", {"f.txt": b"x" * 50}, compression=zipfile.ZIP_STORED)
    set_zip_method(path, 98)
    report = verify(path)
    assert report.unavailable == 1 and report.verdict == "incomplete"


def test_zstd_entry_is_handled_whatever_the_python_version(tmp_path):
    # Regression: on Python 3.14 zipfile can decode zstd, and corrupt data raised an uncaught
    # compression.zstd.ZstdError. Where zstd is unsupported the entry is "unavailable";
    # where it is supported, undecodable data is a failed check. Neither may crash.
    path = make_zip(tmp_path / "a.zip", {"f.txt": b"definitely not a zstd frame" * 3, "ok.txt": b"fine"}, compression=zipfile.ZIP_STORED)
    data = bytearray(path.read_bytes())
    # Only the first entry (f.txt) is switched to zstd: patch its local and central headers.
    data[data.index(b"PK\x03\x04") + 8 : data.index(b"PK\x03\x04") + 10] = (93).to_bytes(2, "little")
    data[data.index(b"PK\x01\x02") + 10 : data.index(b"PK\x01\x02") + 12] = (93).to_bytes(2, "little")
    path.write_bytes(bytes(data))
    report = verify(path)
    if hasattr(zipfile, "ZIP_ZSTANDARD"):
        assert report.failed == 1 and report.verdict == "failed"
    else:
        assert report.unavailable == 1 and report.verdict == "incomplete"
    assert report.passed == 1  # the other entry is still verified


def test_codec_specific_errors_become_read_errors():
    # compression.zstd only exists on Python 3.14+; its error type must be translated like the others.
    import importlib
    import io

    from packlens.core.errors import ArchiveReadError
    from packlens.core.limits import Budget
    from packlens.formats.base import GuardedStream

    pytest.importorskip("compression.zstd")
    zstd = importlib.import_module("compression.zstd")

    class Exploding(io.RawIOBase):
        def read(self, size=-1):
            raise zstd.ZstdError("bad frame")

    stream = GuardedStream(Exploding(), "entry", budget=Budget(None), max_entry_size=None)
    with pytest.raises(ArchiveReadError, match="bad frame"):
        stream.read(10)


def test_xz_without_integrity_check_is_incomplete(tmp_path):
    import lzma

    path = tmp_path / "nocheck.xz"
    path.write_bytes(lzma.compress(b"payload" * 100, check=lzma.CHECK_NONE))
    report = verify(path)
    assert report.verdict == "incomplete"
    assert not report.integrity_available


def test_directory_only_archive_has_nothing_to_check(tmp_path):
    path = make_zip(tmp_path / "d.zip", {"a/": None, "a/b/": None})
    report = verify(path)
    assert report.entries_without_data == 2 and report.verdict == "passed"


def test_verification_respects_decompression_limit(tmp_path):
    path = make_stream(tmp_path / "bomb.gz", b"\0" * (10 * 1024 * 1024), "gzip")
    with pytest.raises(LimitExceededError):
        verify(path, limits=Limits(max_total_bytes=1024 * 1024))


def test_verify_never_modifies_source(tmp_path, sample):
    path = make_zip(tmp_path / "a.zip", sample)
    before = path.read_bytes()
    verify(path)
    assert path.read_bytes() == before


def test_zip_symlink_entries_are_checksummed_too(tmp_path):
    import zipfile
    from helpers import Symlink

    path = make_zip(tmp_path / "a.zip", {"link": Symlink("target-file-name")}, compression=zipfile.ZIP_STORED)
    flip_byte(path, path.read_bytes().index(b"target-file-name") + 2)
    report = verify(path)
    assert report.verdict == "failed" and report.results[0].path == "link"
