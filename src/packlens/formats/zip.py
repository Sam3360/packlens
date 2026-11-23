"""ZIP handler built on :mod:`zipfile`. Reads the central directory; entry data is streamed."""

from __future__ import annotations

import stat
import struct
import zipfile
from datetime import datetime
from typing import BinaryIO, Iterator

from packlens.core.errors import ArchiveReadError, LimitExceededError, UnsupportedFeatureError
from packlens.core.models import (
    ArchiveEntry,
    ArchiveFormat,
    ArchiveInfo,
    EntryType,
    IntegrityInfo,
)
from packlens.formats.base import (
    STREAM_ERRORS,
    ArchiveHandler,
    EntryStream,
    ErrorStream,
    GuardedStream,
    SelectFn,
)

_COMPRESSION_NAMES = {
    zipfile.ZIP_STORED: "stored",
    zipfile.ZIP_DEFLATED: "deflate",
    zipfile.ZIP_BZIP2: "bzip2",
    zipfile.ZIP_LZMA: "lzma",
    93: "zstd",
    95: "xz",
    96: "jpeg",
    97: "wavpack",
    98: "ppmd",
    99: "aes-encrypted",
}
_LINK_TARGET_MAX = 4096
_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP64_LOCATOR = b"PK\x06\x07"
_ZIP64_EOCD = b"PK\x06\x06"


def peek_entry_count(fileobj: BinaryIO) -> int | None:
    """Read the declared entry count from the end-of-central-directory record.

    This lets us refuse a hostile archive *before* :mod:`zipfile` parses millions of headers.
    """
    size = fileobj.seek(0, 2)
    tail_len = min(size, 65535 + 22 + 20)
    fileobj.seek(size - tail_len)
    tail = fileobj.read(tail_len)
    pos = tail.rfind(_EOCD_SIGNATURE)
    if pos < 0 or pos + 22 > len(tail):
        return None
    total = struct.unpack_from("<H", tail, pos + 10)[0]
    if total == 0xFFFF and pos >= 20 and tail[pos - 20 : pos - 16] == _ZIP64_LOCATOR:
        zip64_offset = struct.unpack_from("<Q", tail, pos - 20 + 8)[0]
        if zip64_offset + 56 <= size:
            fileobj.seek(zip64_offset)
            record = fileobj.read(56)
            if record[:4] == _ZIP64_EOCD and len(record) >= 40:
                total = struct.unpack_from("<Q", record, 32)[0]
    return total


_CENTRAL_HEADER = b"PK\x01\x02"
_CENTRAL_HEADER_SIZE = 46


def read_central_names(fileobj: BinaryIO, start_dir: int, infos: list[zipfile.ZipInfo]) -> list[str] | None:
    """File names exactly as stored in the central directory, in ``infos`` order.

    ``zipfile`` rewrites path separators in ``ZipInfo.filename`` depending on the host platform
    (a backslash becomes ``/`` on Windows). Security analysis must see what the archive really
    contains, so the names are read here directly. Returns ``None`` when the directory does not
    line up with ``infos``; callers then fall back to ``ZipInfo.orig_filename``.
    """
    names: list[str] = []
    try:
        fileobj.seek(start_dir)
        for info in infos:
            header = fileobj.read(_CENTRAL_HEADER_SIZE)
            if len(header) != _CENTRAL_HEADER_SIZE or header[:4] != _CENTRAL_HEADER:
                return None
            flags = struct.unpack_from("<H", header, 8)[0]
            crc = struct.unpack_from("<I", header, 16)[0]
            name_len, extra_len, comment_len = struct.unpack_from("<HHH", header, 28)
            raw = fileobj.read(name_len)
            if len(raw) != name_len or crc != info.CRC:  # CRC doubles as an alignment check
                return None
            fileobj.seek(extra_len + comment_len, 1)
            names.append(raw.decode("utf-8" if flags & 0x800 else "cp437"))
    except (OSError, UnicodeDecodeError, struct.error):
        return None
    return names


def _entry_type(info: zipfile.ZipInfo, name: str) -> tuple[EntryType, int | None]:
    unix_mode = (info.external_attr >> 16) & 0xFFFF if info.create_system == 3 else 0
    kind = stat.S_IFMT(unix_mode)
    perms = (unix_mode & 0o7777) if unix_mode else None
    if name.endswith("/") or kind == stat.S_IFDIR:
        return EntryType.DIRECTORY, perms
    if info.create_system == 0 and info.external_attr & 0x10:  # MS-DOS directory attribute
        return EntryType.DIRECTORY, perms
    if kind == stat.S_IFLNK:
        return EntryType.SYMLINK, perms
    if kind in (0, stat.S_IFREG):
        return EntryType.FILE, perms
    return EntryType.OTHER, perms


class ZipHandler(ArchiveHandler):
    format = ArchiveFormat.ZIP
    integrity = IntegrityInfo(True, "Per-entry CRC-32 checks (requires reading all entry data)")

    def __init__(self, fileobj: BinaryIO, name: str, **kwargs: object) -> None:
        super().__init__(fileobj, name, **kwargs)  # type: ignore[arg-type]
        declared = peek_entry_count(fileobj)
        fileobj.seek(0)
        limit = self.limits.max_entries
        if limit is not None and declared is not None and declared > limit:
            raise LimitExceededError("max_entries", limit, f"Entry count ({declared:,})")
        try:
            self._zf = zipfile.ZipFile(fileobj)
        except NotImplementedError as exc:  # e.g. an unsupported "version needed to extract"
            raise UnsupportedFeatureError(f"{name}: {exc}") from exc
        except STREAM_ERRORS as exc:
            raise ArchiveReadError(f"{name}: not a readable ZIP archive ({exc})") from exc
        self._infos = self._zf.infolist()
        stored = read_central_names(fileobj, getattr(self._zf, "start_dir", 0), self._infos)
        self._names = stored if stored is not None else [info.orig_filename for info in self._infos]
        if limit is not None and len(self._infos) > limit:
            raise LimitExceededError("max_entries", limit, f"Entry count ({len(self._infos):,})")
        self._entry_cache: list[ArchiveEntry] | None = None

    def info(self) -> ArchiveInfo:
        metadata: dict[str, str] = {}
        if self._zf.comment:
            metadata["comment"] = self._zf.comment.decode("utf-8", "replace")[:1000]
        return ArchiveInfo(self.name, self.format, self.file_size, self.integrity, metadata)

    def _link_target(self, info: zipfile.ZipInfo) -> str | None:
        if info.flag_bits & 0x1 or info.file_size > _LINK_TARGET_MAX:
            return None
        try:
            with self._zf.open(info) as handle:
                return handle.read(_LINK_TARGET_MAX).decode("utf-8", "replace")
        except (*STREAM_ERRORS, NotImplementedError):
            return None

    def _build_entry(self, index: int, info: zipfile.ZipInfo) -> ArchiveEntry:
        name = self._names[index]
        kind, perms = _entry_type(info, name)
        try:
            mtime: datetime | None = datetime(*info.date_time)
        except ValueError:
            mtime = None
        target = self._link_target(info) if kind is EntryType.SYMLINK else None
        return ArchiveEntry(
            index=index,
            path=name,  # exactly as stored; ZipInfo.filename is rewritten by zipfile per platform
            type=kind,
            size=0 if kind is EntryType.DIRECTORY else info.file_size,
            compressed_size=info.compress_size,
            mtime=mtime,
            compression=_COMPRESSION_NAMES.get(info.compress_type, f"method-{info.compress_type}"),
            crc32=None if kind is EntryType.DIRECTORY else info.CRC,
            mode=perms,
            link_target=target,
            encrypted=bool(info.flag_bits & 0x1),
        )

    def _entries(self) -> list[ArchiveEntry]:
        if self._entry_cache is None:
            self._entry_cache = [self._build_entry(i, zi) for i, zi in enumerate(self._infos)]
        return self._entry_cache

    def entries(self) -> Iterator[ArchiveEntry]:
        yield from self._entries()

    def _open(self, info: zipfile.ZipInfo, entry: ArchiveEntry) -> EntryStream:
        if entry.encrypted:
            return ErrorStream(
                UnsupportedFeatureError(f"{entry.path}: entry is encrypted; contents cannot be checked")
            )
        try:
            raw = self._zf.open(info)
        except NotImplementedError as exc:
            return ErrorStream(UnsupportedFeatureError(f"{entry.path}: {exc}"))
        except STREAM_ERRORS as exc:
            return ErrorStream(ArchiveReadError(f"{entry.path}: {exc}"))
        return GuardedStream(
            raw, entry.path, budget=self.budget, max_entry_size=self.limits.max_entry_size
        )

    def iter_data(
        self, select: SelectFn | None = None, *, complete: bool = False
    ) -> Iterator[tuple[ArchiveEntry, EntryStream | None]]:
        for entry, info in zip(self._entries(), self._infos):
            if select is None:
                wanted = entry.type is EntryType.FILE
            else:
                wanted = entry.type in (EntryType.FILE, EntryType.SYMLINK) and select(entry)
            if not wanted:
                yield entry, None
                continue
            stream = self._open(info, entry)
            try:
                yield entry, stream
            finally:
                stream.close()

    def _close_impl(self) -> None:
        self._zf.close()
