from __future__ import annotations

import io
from pathlib import Path

import pytest

from helpers import flip_byte, make_stream, make_tar, make_zip, truncate
from packlens.core.archive import open_archive, open_archive_stream
from packlens.core.detection import detect_format
from packlens.core.errors import UnsupportedFormatError
from packlens.core.models import ArchiveFormat


@pytest.mark.parametrize(
    "key,expected",
    [
        ("zip", ArchiveFormat.ZIP),
        ("tar", ArchiveFormat.TAR),
        ("tar.gz", ArchiveFormat.TAR_GZ),
        ("tar.bz2", ArchiveFormat.TAR_BZ2),
        ("tar.xz", ArchiveFormat.TAR_XZ),
        ("gzip", ArchiveFormat.GZIP),
        ("bzip2", ArchiveFormat.BZIP2),
        ("xz", ArchiveFormat.XZ),
    ],
)
def test_detects_every_format_by_content(archives, tmp_path, key, expected):
    # The name is deliberately meaningless: detection must use the content.
    disguised = tmp_path / "mystery.bin"
    disguised.write_bytes(archives[key].read_bytes())
    with open(disguised, "rb") as handle:
        assert detect_format(handle, disguised.name) is expected


def test_tgz_tbz2_txz_extensions_work(tmp_path, sample):
    for ext, comp, fmt in [
        (".tgz", "gz", ArchiveFormat.TAR_GZ),
        (".tbz2", "bz2", ArchiveFormat.TAR_BZ2),
        (".txz", "xz", ArchiveFormat.TAR_XZ),
    ]:
        path = make_tar(tmp_path / f"a{ext}", sample, compression=comp)
        with open_archive(path) as handler:
            assert handler.format is fmt


def test_empty_zip_is_detected(tmp_path):
    path = make_zip(tmp_path / "empty.zip", {})
    with open(path, "rb") as handle:
        assert detect_format(handle, path.name) is ArchiveFormat.ZIP


def test_empty_tar_needs_name_hint(tmp_path):
    path = make_tar(tmp_path / "empty.tar", {})
    with open(path, "rb") as handle:
        assert detect_format(handle, "empty.tar") is ArchiveFormat.TAR
        assert detect_format(handle, "zeros.bin") is None  # all-zero files are not assumed to be tars


def test_empty_compressed_tar_with_hint(tmp_path):
    path = make_tar(tmp_path / "empty.tar.gz", {}, compression="gz")
    with open(path, "rb") as handle:
        assert detect_format(handle, "empty.tar.gz") is ArchiveFormat.TAR_GZ


def test_gzip_of_non_tar_is_a_stream(tmp_path):
    path = make_stream(tmp_path / "notes.txt.gz", b"just text", "gzip")
    with open(path, "rb") as handle:
        assert detect_format(handle, path.name) is ArchiveFormat.GZIP


def test_damaged_gzip_is_still_gzip(tmp_path):
    path = make_stream(tmp_path / "x.gz", b"a" * 5000, "gzip")
    truncate(path, 12)
    with open(path, "rb") as handle:
        assert detect_format(handle, path.name) is ArchiveFormat.GZIP


def test_truncated_tar_gz_keeps_tar_hint(tmp_path, sample):
    path = make_tar(tmp_path / "t.tar.gz", sample, compression="gz")
    truncate(path, 12)
    with open(path, "rb") as handle:
        assert detect_format(handle, "t.tar.gz") is ArchiveFormat.TAR_GZ


def test_zip_with_prefix_is_detected(tmp_path, sample):
    path = make_zip(tmp_path / "plain.zip", sample)
    prefixed = tmp_path / "selfextract.bin"
    prefixed.write_bytes(b"#!/bin/sh\nexit 0\n" + path.read_bytes())
    with open(prefixed, "rb") as handle:
        assert detect_format(handle, prefixed.name) is ArchiveFormat.ZIP


def test_random_data_is_not_an_archive(tmp_path):
    path = tmp_path / "noise.dat"
    path.write_bytes(bytes(range(256)) * 10)
    with pytest.raises(UnsupportedFormatError, match="not a recognised archive"):
        open_archive(path)


def test_empty_file_gets_clear_error(tmp_path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    with pytest.raises(UnsupportedFormatError, match="empty"):
        open_archive(path)


def test_recognised_but_unsupported_formats_are_named(tmp_path):
    path = tmp_path / "x.7z"
    path.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 64)
    with pytest.raises(UnsupportedFormatError, match="7z archives are not supported"):
        open_archive(path)


def test_directory_is_rejected(tmp_path):
    with pytest.raises(Exception, match="is a directory"):
        open_archive(tmp_path)


def test_open_archive_stream_from_memory(tmp_path, sample):
    data = make_zip(tmp_path / "m.zip", sample).read_bytes()
    with open_archive_stream(io.BytesIO(data), "memory.zip") as handler:
        assert handler.format is ArchiveFormat.ZIP
