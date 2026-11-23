"""Standalone gzip / bzip2 / xz streams, exposed as a single logical entry."""

from __future__ import annotations

import bz2
import gzip
import lzma
import struct
from datetime import datetime, timezone
from typing import BinaryIO, Iterator

from packlens.core.errors import ArchiveReadError, LimitExceededError
from packlens.core.models import (
    ArchiveEntry,
    ArchiveFormat,
    ArchiveInfo,
    EntryType,
    IntegrityInfo,
    Severity,
)
from packlens.formats.base import ArchiveHandler, EntryStream, GuardedStream, SelectFn
from packlens.utils.hashing import CHUNK_SIZE

_SUFFIXES = {
    ArchiveFormat.GZIP: (".gz", ".gzip"),
    ArchiveFormat.BZIP2: (".bz2", ".bz"),
    ArchiveFormat.XZ: (".xz",),
}
_CODEC_NAMES = {ArchiveFormat.GZIP: "gzip", ArchiveFormat.BZIP2: "bzip2", ArchiveFormat.XZ: "xz"}
_XZ_CHECKS = {0: "none", 1: "CRC32", 4: "CRC64", 10: "SHA-256"}
_GZIP_HEADER_MAX = 64 * 1024


def parse_gzip_header(data: bytes) -> dict[str, object] | None:
    """Parse the fields of a gzip member header (RFC 1952). Returns ``None`` if malformed."""
    if len(data) < 10 or data[:2] != b"\x1f\x8b" or data[2] != 8:
        return None
    flags = data[3]
    mtime = struct.unpack_from("<I", data, 4)[0]
    pos = 10
    result: dict[str, object] = {"mtime": mtime, "os": data[9], "name": None, "comment": None}
    if flags & 0x04:  # FEXTRA
        if pos + 2 > len(data):
            return result
        pos += 2 + struct.unpack_from("<H", data, pos)[0]
    for flag, key in ((0x08, "name"), (0x10, "comment")):
        if flags & flag:
            end = data.find(b"\x00", pos)
            if end < 0:
                return result
            result[key] = data[pos:end].decode("latin-1")
            pos = end + 1
    return result


class CompressedStreamHandler(ArchiveHandler):
    def __init__(self, fileobj: BinaryIO, name: str, *, format: ArchiveFormat, **kwargs: object) -> None:
        if not format.is_stream:
            raise ValueError(f"{format} is not a compressed stream format")
        super().__init__(fileobj, name, **kwargs)  # type: ignore[arg-type]
        self.format = format
        self._metadata: dict[str, str] = {}
        self._header_mtime: datetime | None = None
        self._payload_name = self._derive_name(None)
        checked = True
        head = fileobj.read(_GZIP_HEADER_MAX)
        fileobj.seek(0)
        if format is ArchiveFormat.GZIP:
            header = parse_gzip_header(head)
            if header is not None:
                original = header["name"]
                if isinstance(original, str) and original:
                    self._metadata["original_name"] = original
                    self._payload_name = original
                if header["mtime"]:
                    self._header_mtime = datetime.fromtimestamp(int(header["mtime"]), tz=timezone.utc)  # type: ignore[call-overload]
                if header["comment"]:
                    self._metadata["comment"] = str(header["comment"])
        elif format is ArchiveFormat.BZIP2 and len(head) >= 4:
            self._metadata["block_size"] = f"{int(chr(head[3])) * 100}k"
        elif format is ArchiveFormat.XZ and len(head) >= 8:
            check = _XZ_CHECKS.get(head[7] & 0x0F, f"type-{head[7] & 0x0F}")
            self._metadata["check"] = check
            checked = check != "none"
        scope = {
            ArchiveFormat.GZIP: "gzip CRC-32 and length trailer, checked while decompressing",
            ArchiveFormat.BZIP2: "bzip2 block and stream CRCs, checked while decompressing",
            ArchiveFormat.XZ: f"xz integrity check ({self._metadata.get('check', 'unknown')}), "
            "checked while decompressing",
        }[format]
        if not checked:
            scope = "this xz stream has no integrity check; only successful decompression can be confirmed"
        self.integrity = IntegrityInfo(checked, scope)
        self._size: int | None = None
        self._measured = False

    def _derive_name(self, original: str | None) -> str:
        base = self.name.rsplit("!", 1)[-1].replace("\\", "/").rsplit("/", 1)[-1]
        for suffix in _SUFFIXES[self.format]:
            if base.lower().endswith(suffix) and len(base) > len(suffix):
                return base[: -len(suffix)]
        return base + ".decompressed" if base else "data"

    def info(self) -> ArchiveInfo:
        return ArchiveInfo(self.name, self.format, self.file_size, self.integrity, dict(self._metadata))

    def _open_decompressor(self) -> BinaryIO:
        self._file.seek(0)
        if self.format is ArchiveFormat.GZIP:
            return gzip.GzipFile(fileobj=self._file, mode="rb")  # type: ignore[return-value]
        if self.format is ArchiveFormat.BZIP2:
            return bz2.BZ2File(self._file, "rb")  # type: ignore[return-value]
        return lzma.LZMAFile(self._file, "rb")  # type: ignore[return-value]

    def _guarded(self) -> GuardedStream:
        return GuardedStream(
            self._open_decompressor(),
            self.name,
            budget=self.budget,
            max_entry_size=self.limits.max_entry_size,
        )

    def _measure(self) -> int | None:
        """Decompress once, in chunks, to learn the real size. Memory use stays constant."""
        if self._measured:
            return self._size
        self._measured = True
        stream = self._guarded()
        total = 0
        try:
            while True:
                chunk = stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
            self._size = total
        except LimitExceededError as exc:
            self._note("size-not-measured", Severity.WARNING, f"decompressed size not measured: {exc}")
        except ArchiveReadError as exc:
            self._note(
                "damaged-stream",
                Severity.WARNING,
                f"stream is damaged or truncated after {stream.bytes_read:,} decompressed bytes: {exc}",
            )
        finally:
            stream.close()
        return self._size

    def _entry(self, size: int | None) -> ArchiveEntry:
        return ArchiveEntry(
            index=0,
            path=self._payload_name,
            type=EntryType.FILE,
            size=size,
            compressed_size=self.file_size,
            mtime=self._header_mtime,
            compression=_CODEC_NAMES[self.format],
        )

    def entries(self) -> Iterator[ArchiveEntry]:
        yield self._entry(self._measure())

    def iter_data(
        self, select: SelectFn | None = None, *, complete: bool = False
    ) -> Iterator[tuple[ArchiveEntry, EntryStream | None]]:
        entry = self._entry(self._size if self._measured else None)
        if select is not None and not select(entry):
            yield entry, None
            return
        stream = self._guarded()
        try:
            yield entry, stream
        finally:
            stream.close()
