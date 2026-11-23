from __future__ import annotations

import pytest

from helpers import flip_byte, make_stream, truncate
from packlens.core.archive import open_archive
from packlens.core.errors import ArchiveReadError, LimitExceededError
from packlens.core.limits import Limits
from packlens.core.models import ArchiveFormat, EntryType

PAYLOAD = b"some repeated payload\n" * 500


@pytest.mark.parametrize(
    "codec,fmt",
    [("gzip", ArchiveFormat.GZIP), ("bzip2", ArchiveFormat.BZIP2), ("xz", ArchiveFormat.XZ)],
)
def test_stream_is_exposed_as_one_logical_entry(tmp_path, codec, fmt):
    path = make_stream(tmp_path / "payload.txt.gz", PAYLOAD, codec)
    with open_archive(path) as handler:
        assert handler.format is fmt
        (entry,) = list(handler.entries())
        assert entry.type is EntryType.FILE
        assert entry.size == len(PAYLOAD)  # measured by streaming, not trusted from a header
        assert entry.compressed_size == path.stat().st_size
        assert entry.compression == codec
    with open_archive(path) as handler:
        for _entry, stream in handler.iter_data():
            assert stream.read() == PAYLOAD


def test_gzip_header_name_is_used(tmp_path):
    path = make_stream(tmp_path / "renamed.bin", PAYLOAD, "gzip", name="original.txt")
    with open_archive(path) as handler:
        assert handler.info().metadata["original_name"] == "original.txt"
        (entry,) = list(handler.entries())
        assert entry.path == "original.txt"
        assert entry.mtime is not None


def test_name_derived_from_suffix_when_no_header_name(tmp_path):
    path = make_stream(tmp_path / "report.csv.xz", PAYLOAD, "xz")
    with open_archive(path) as handler:
        assert next(handler.entries()).path == "report.csv"


def test_xz_check_type_in_metadata(tmp_path):
    path = make_stream(tmp_path / "a.xz", PAYLOAD, "xz")
    with open_archive(path) as handler:
        assert handler.info().metadata["check"] in {"CRC64", "CRC32", "SHA-256"}
        assert handler.info().integrity.available


def test_damaged_stream_lists_with_unknown_size_and_note(tmp_path):
    path = make_stream(tmp_path / "a.gz", PAYLOAD, "gzip")
    truncate(path, path.stat().st_size - 20)
    with open_archive(path) as handler:
        (entry,) = list(handler.entries())
        assert entry.size is None
        assert any(n.code == "damaged-stream" for n in handler.notes())


def test_decompression_limit_stops_a_bomb(tmp_path):
    path = make_stream(tmp_path / "bomb.gz", b"\0" * (20 * 1024 * 1024), "gzip")
    limits = Limits(max_total_bytes=1024 * 1024)
    with open_archive(path, limits) as handler:
        (entry,) = list(handler.entries())  # listing degrades gracefully
        assert entry.size is None
        assert any(n.code == "size-not-measured" for n in handler.notes())
    with open_archive(path, limits) as handler:
        with pytest.raises(LimitExceededError, match="max-total-bytes"):
            for _e, stream in handler.iter_data():
                while stream.read(65536):
                    pass


def test_max_entry_size_limit(tmp_path):
    path = make_stream(tmp_path / "a.gz", b"x" * 100_000, "gzip")
    with open_archive(path, Limits(max_entry_size=1000)) as handler:
        with pytest.raises(LimitExceededError, match="max-entry-size"):
            for _e, stream in handler.iter_data():
                stream.read()
