"""The common archive handler interface plus shared streaming helpers."""

from __future__ import annotations

import lzma
import struct
import tarfile
import zipfile
import zlib
from abc import ABC, abstractmethod
from typing import BinaryIO, Callable, Iterator, Protocol

from packlens.core.errors import (
    ArchiveReadError,
    EntryNotFoundError,
    LimitExceededError,
    UnsupportedFeatureError,
)
from packlens.core.limits import DEFAULT_LIMITS, Budget, Limits
from packlens.core.models import (
    ArchiveEntry,
    ArchiveFormat,
    ArchiveInfo,
    Finding,
    IntegrityInfo,
    Severity,
)
from packlens.utils.hashing import CHUNK_SIZE

def _optional_codec_errors() -> tuple[type[BaseException], ...]:
    """Error types of codecs that only exist in newer Pythons (Zstandard arrived in 3.14)."""
    try:
        from compression.zstd import ZstdError  # type: ignore[import-not-found,unused-ignore]
    except ImportError:
        return ()
    return (ZstdError,)


# Exceptions the standard-library codecs raise for damaged or truncated data.
STREAM_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    EOFError,
    zlib.error,
    lzma.LZMAError,
    tarfile.TarError,
    zipfile.BadZipFile,
    # Corrupt offsets and lengths make the stdlib raise these instead of its own error types.
    ValueError,  # includes UnicodeError and "negative seek value"
    OverflowError,
    struct.error,
    *_optional_codec_errors(),
)

SelectFn = Callable[[ArchiveEntry], bool]


class EntryStream(Protocol):
    """A forward-only stream of one entry's decompressed content."""

    bytes_read: int

    def read(self, size: int = -1) -> bytes: ...

    def close(self) -> None: ...


class GuardedStream:
    """Wraps a raw stream: normalises codec errors and enforces size limits.

    Reads raise :class:`ArchiveReadError` for damaged data, :class:`UnsupportedFeatureError`
    for unsupported codecs and :class:`LimitExceededError` when a limit is hit.
    """

    def __init__(
        self,
        raw: BinaryIO,
        label: str,
        *,
        budget: Budget | None,
        max_entry_size: int | None,
    ) -> None:
        self._raw = raw
        self._label = label
        self._budget = budget
        self._max_entry_size = max_entry_size
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            parts: list[bytes] = []
            while True:
                chunk = self._read_once(CHUNK_SIZE)
                if not chunk:
                    return b"".join(parts)
                parts.append(chunk)
        return self._read_once(size)

    def _read_once(self, size: int) -> bytes:
        try:
            data = self._raw.read(size)
        except NotImplementedError as exc:
            raise UnsupportedFeatureError(f"{self._label}: {exc}") from exc
        except STREAM_ERRORS as exc:
            raise ArchiveReadError(f"{self._label}: {exc}") from exc
        self.bytes_read += len(data)
        if self._max_entry_size is not None and self.bytes_read > self._max_entry_size:
            raise LimitExceededError(
                "max_entry_size", self._max_entry_size, f"Entry {self._label!r}", is_bytes=True
            )
        if self._budget is not None:
            self._budget.consume(len(data))
        return data

    def close(self) -> None:
        try:
            self._raw.close()
        except STREAM_ERRORS:
            pass  # closing a damaged stream must not mask the read error that preceded it


class ErrorStream:
    """Stands in for an entry that cannot be opened; the first read raises the stored error."""

    bytes_read = 0

    def __init__(self, error: ArchiveReadError | UnsupportedFeatureError) -> None:
        self._error = error

    def read(self, size: int = -1) -> bytes:
        raise self._error

    def close(self) -> None:
        return None


def read_bounded(stream: EntryStream, max_bytes: int | None, what: str) -> bytes:
    """Read a whole stream into memory, refusing to exceed ``max_bytes``."""
    parts: list[bytes] = []
    total = 0
    while True:
        want = CHUNK_SIZE if max_bytes is None else min(CHUNK_SIZE, max_bytes - total + 1)
        chunk = stream.read(want)
        if not chunk:
            return b"".join(parts)
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            raise LimitExceededError("max_nested_size", max_bytes, what, is_bytes=True)
        parts.append(chunk)


class ArchiveHandler(ABC):
    """Interface every archive format implements.

    Handlers never modify the source and never write to disk. ``entries`` and ``iter_data``
    are single-pass generators: do not interleave two passes on the same handler.
    """

    format: ArchiveFormat
    integrity: IntegrityInfo

    def __init__(
        self,
        fileobj: BinaryIO,
        name: str,
        *,
        limits: Limits = DEFAULT_LIMITS,
        budget: Budget | None = None,
        owns_file: bool = False,
        on_close: tuple[Callable[[], None], ...] = (),
    ) -> None:
        self.name = name
        self.limits = limits
        self.budget = budget if budget is not None else Budget(limits.max_total_bytes)
        self._file = fileobj
        self._owns_file = owns_file
        self._on_close = list(on_close)
        self._notes: list[Finding] = []
        self._closed = False
        fileobj.seek(0, 2)
        self.file_size: int = fileobj.tell()
        fileobj.seek(0)

    # -- interface -------------------------------------------------------------------

    @abstractmethod
    def info(self) -> ArchiveInfo:
        """Archive-level metadata."""

    @abstractmethod
    def entries(self) -> Iterator[ArchiveEntry]:
        """Yield entries from the archive's metadata, without reading file contents where possible."""

    @abstractmethod
    def iter_data(
        self, select: SelectFn | None = None, *, complete: bool = False
    ) -> Iterator[tuple[ArchiveEntry, EntryStream | None]]:
        """Walk the archive once, yielding ``(entry, stream)``.

        ``stream`` is provided for entries whose data can be read and which are selected
        (``select`` is ``None`` means every regular file), otherwise ``None``. A stream is only
        valid until the generator advances. With ``complete=True`` the pass also validates
        archive-level structure and trailing checksums, and raises :class:`ArchiveReadError`
        at the end when something is wrong.
        """

    def _close_impl(self) -> None:
        """Release format-specific resources."""

    # -- shared behaviour ------------------------------------------------------------

    def notes(self) -> list[Finding]:
        """Format-level findings gathered while reading (e.g. missing end-of-archive marker)."""
        return list(self._notes)

    def _note(self, code: str, severity: Severity, message: str, path: str | None = None) -> None:
        if len(self._notes) < self.limits.max_findings:
            self._notes.append(Finding(code, severity, message, path))

    def read_entry_bytes(self, entry: ArchiveEntry, max_bytes: int | None) -> bytes:
        """Read one entry fully into memory, bounded by ``max_bytes``."""
        wanted = entry.index
        for current, stream in self.iter_data(select=lambda e: e.index == wanted):
            if current.index != wanted:
                continue
            if stream is None:
                raise ArchiveReadError(f"{entry.path!r} has no readable data")
            return read_bounded(stream, max_bytes, f"Nested archive {entry.path!r}")
        raise EntryNotFoundError(f"entry {entry.path!r} not found")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._close_impl()
        finally:
            if self._owns_file:
                self._file.close()
            for callback in self._on_close:
                callback()

    def __enter__(self) -> "ArchiveHandler":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
