"""TAR handler (plain, gzip, bzip2 and xz compressed) built on :mod:`tarfile`.

Two things are handled here that ``tarfile`` does not do by itself:

* A corrupted or truncated header *after* the first member is silently treated by ``tarfile``
  as the end of the archive. We inspect the block where reading stopped and report a problem
  unless it is a proper end-of-archive marker.
* Compressed tars are read through our own decompressor so that decompressed bytes are
  counted against the resource budget even while ``tarfile`` skips over member data.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import tarfile
from datetime import datetime, timezone
from typing import BinaryIO, Iterator

from packlens.core.errors import ArchiveReadError, LimitExceededError
from packlens.core.limits import Budget
from packlens.core.models import (
    ArchiveEntry,
    ArchiveFormat,
    ArchiveInfo,
    EntryType,
    IntegrityInfo,
    Severity,
)
from packlens.formats.base import (
    STREAM_ERRORS,
    ArchiveHandler,
    EntryStream,
    GuardedStream,
    SelectFn,
)
from packlens.utils.hashing import CHUNK_SIZE

_BLOCK = tarfile.BLOCKSIZE
_CODEC_NAMES = {
    ArchiveFormat.TAR_GZ: "gzip",
    ArchiveFormat.TAR_BZ2: "bzip2",
    ArchiveFormat.TAR_XZ: "xz",
}


class _TrackingReader:
    """File-like wrapper handed to ``tarfile``.

    It remembers the last 512-byte read (the header ``tarfile`` stopped at) and counts bytes
    that are actually decompressed. For compressed input, forward seeks are performed by
    reading so that skipped data is counted too.
    """

    def __init__(self, raw: BinaryIO, budget: Budget | None, *, skip_by_reading: bool) -> None:
        self._raw = raw
        self._budget = budget
        self._skip_by_reading = skip_by_reading
        self.last_block: tuple[int, bytes] | None = None

    def _count(self, amount: int) -> None:
        if self._budget is not None and amount:
            self._budget.consume(amount)

    def read(self, size: int = -1) -> bytes:
        start = self._raw.tell()
        data = self._raw.read(size)
        self._count(len(data))
        if size == _BLOCK:
            self.last_block = (start, data)
        return data

    def tell(self) -> int:
        return self._raw.tell()

    def seek(self, offset: int, whence: int = 0) -> int:
        if self._skip_by_reading and whence == 0:
            remaining = offset - self._raw.tell()
            if remaining > 0:
                while remaining > 0:
                    chunk = self._raw.read(min(remaining, CHUNK_SIZE))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    self._count(len(chunk))
                return self._raw.tell()
        return self._raw.seek(offset, whence)


def _timestamp(value: float) -> datetime | None:
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _entry_from(index: int, info: tarfile.TarInfo) -> ArchiveEntry:
    if info.isdir():
        kind = EntryType.DIRECTORY
    elif info.issym():
        kind = EntryType.SYMLINK
    elif info.islnk():
        kind = EntryType.HARDLINK
    elif info.isreg():
        kind = EntryType.FILE
    else:
        kind = EntryType.OTHER
    return ArchiveEntry(
        index=index,
        path=info.name,
        type=kind,
        size=info.size if kind is EntryType.FILE else 0,
        mtime=_timestamp(info.mtime),
        mode=info.mode & 0o7777,
        link_target=info.linkname if kind in (EntryType.SYMLINK, EntryType.HARDLINK) else None,
    )


class TarHandler(ArchiveHandler):
    def __init__(self, fileobj: BinaryIO, name: str, *, format: ArchiveFormat, **kwargs: object) -> None:
        if not format.is_tar:
            raise ValueError(f"{format} is not a TAR format")
        super().__init__(fileobj, name, **kwargs)  # type: ignore[arg-type]
        self.format = format
        if format is ArchiveFormat.TAR:
            self.integrity = IntegrityInfo(
                True,
                "Header checksums and member readability only; TAR stores no content checksums",
            )
        else:
            self.integrity = IntegrityInfo(
                True,
                f"{_CODEC_NAMES[format]} stream checksum plus TAR structure; "
                "TAR members themselves have no content checksums",
            )

    def info(self) -> ArchiveInfo:
        metadata: dict[str, str] = {}
        if self.format in _CODEC_NAMES:
            metadata["compression"] = _CODEC_NAMES[self.format]
        return ArchiveInfo(self.name, self.format, self.file_size, self.integrity, metadata)

    # -- low level -------------------------------------------------------------------

    def _open_raw(self) -> BinaryIO:
        self._file.seek(0)
        if self.format is ArchiveFormat.TAR_GZ:
            return gzip.GzipFile(fileobj=self._file, mode="rb")  # type: ignore[return-value]
        if self.format is ArchiveFormat.TAR_BZ2:
            return bz2.BZ2File(self._file, "rb")  # type: ignore[return-value]
        if self.format is ArchiveFormat.TAR_XZ:
            return lzma.LZMAFile(self._file, "rb")  # type: ignore[return-value]
        return self._file

    def _walk(self, *, complete: bool) -> Iterator[tuple[int, tarfile.TarInfo, tarfile.TarFile]]:
        raw = self._open_raw()
        compressed = self.format.is_compressed
        tracker = _TrackingReader(raw, self.budget, skip_by_reading=compressed)
        try:
            try:
                tf = tarfile.open(fileobj=tracker, mode="r:")  # type: ignore[call-overload]
            except STREAM_ERRORS as exc:
                raise ArchiveReadError(f"{self.name}: not a readable {self.format.label} archive ({exc})") from exc
            index = 0
            limit = self.limits.max_entries
            try:
                while True:
                    try:
                        info = tf.next()
                    except STREAM_ERRORS as exc:
                        raise ArchiveReadError(
                            f"{self.name}: damaged archive after {index:,} entries ({exc})"
                        ) from exc
                    if info is None:
                        break
                    if limit is not None and index >= limit:
                        raise LimitExceededError("max_entries", limit, f"Entry count (more than {limit:,})")
                    yield index, info, tf
                    tf.members.clear()  # do not retain every TarInfo for huge archives
                    index += 1
                self._finish_pass(tracker, tf, index, complete=complete)
            finally:
                tf.close()
        finally:
            if raw is not self._file:
                raw.close()

    def _finish_pass(self, tracker: _TrackingReader, tf: tarfile.TarFile, count: int, *, complete: bool) -> None:
        problem = self._end_problem(tracker, tf.offset)
        if complete:
            # Drain the rest so the compression layer verifies its trailing checksum.
            trailing_data = False
            try:
                while True:
                    chunk = tracker.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    if chunk.count(0) != len(chunk):
                        trailing_data = True
            except STREAM_ERRORS as exc:
                raise ArchiveReadError(f"{self.name}: damaged data after {count:,} entries ({exc})") from exc
            if trailing_data and problem is None:
                self._note(
                    "tar-trailing-data",
                    Severity.WARNING,
                    "non-zero data follows the end-of-archive marker (concatenated archives?)",
                )
        if problem is not None:
            if complete:
                raise ArchiveReadError(f"{self.name}: {problem}")
            self._note("tar-structure", Severity.WARNING, problem)

    @staticmethod
    def _end_problem(tracker: _TrackingReader, offset: int) -> str | None:
        """Classify the block where ``tarfile`` stopped reading headers."""
        last = tracker.last_block
        if last is None or last[0] != offset:
            return None  # nothing was read at that offset; treat as a clean end
        data = last[1]
        if len(data) == _BLOCK and data.count(0) == _BLOCK:
            return None
        if len(data) == 0:
            return "archive ends without an end-of-archive marker (it may be truncated)"
        if len(data) < _BLOCK:
            return f"truncated header block at offset {offset:,}"
        return f"invalid header block at offset {offset:,} (bad checksum); later members were not read"

    # -- interface -------------------------------------------------------------------

    def entries(self) -> Iterator[ArchiveEntry]:
        for index, info, _tf in self._walk(complete=False):
            yield _entry_from(index, info)

    def iter_data(
        self, select: SelectFn | None = None, *, complete: bool = False
    ) -> Iterator[tuple[ArchiveEntry, EntryStream | None]]:
        for index, info, tf in self._walk(complete=complete):
            entry = _entry_from(index, info)
            wanted = entry.type is EntryType.FILE and (select is None or select(entry))
            if not wanted:
                yield entry, None
                continue
            try:
                raw = tf.extractfile(info)
            except STREAM_ERRORS as exc:
                raise ArchiveReadError(f"{entry.path}: {exc}") from exc
            if raw is None:
                yield entry, None
                continue
            # Budget accounting for tar happens in the tracking reader, not per entry.
            stream = GuardedStream(raw, entry.path, budget=None, max_entry_size=self.limits.max_entry_size)
            try:
                yield entry, stream
            finally:
                stream.close()
