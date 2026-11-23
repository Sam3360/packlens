"""Format detection by content (magic numbers), with file names used only as hints."""

from __future__ import annotations

import bz2
import gzip
import lzma
import tarfile
import zipfile
from typing import BinaryIO, Callable

from packlens.core.models import ArchiveFormat
from packlens.formats.base import STREAM_ERRORS

_PEEK = tarfile.BLOCKSIZE

_TAR_NAME_HINTS = {
    ArchiveFormat.TAR: (".tar",),
    ArchiveFormat.TAR_GZ: (".tar.gz", ".tgz"),
    ArchiveFormat.TAR_BZ2: (".tar.bz2", ".tbz2", ".tbz"),
    ArchiveFormat.TAR_XZ: (".tar.xz", ".txz"),
}

# Formats we recognise but do not implement yet. Used only to give a helpful error.
_UNSUPPORTED_MAGIC = (
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"\x28\xb5\x2f\xfd", "Zstandard"),
)


def _name_hints_tar(name: str, fmt: ArchiveFormat) -> bool:
    lowered = name.lower()
    return lowered.endswith(_TAR_NAME_HINTS[fmt])


def _looks_like_tar(block: bytes, name: str) -> bool:
    if len(block) < _PEEK:
        return False
    if block[257:262] == b"ustar":
        return True
    if block.count(0) == _PEEK:  # an empty archive is only zero blocks; trust the name
        return _name_hints_tar(name, ArchiveFormat.TAR)
    try:
        tarfile.TarInfo.frombuf(block, "utf-8", "surrogateescape")
    except tarfile.HeaderError:
        return False
    return True


def _peek_decompressed(fileobj: BinaryIO, opener: Callable[[BinaryIO], BinaryIO]) -> bytes | None:
    """First block of the decompressed payload, or ``None`` if it cannot be decompressed."""
    fileobj.seek(0)
    try:
        stream = opener(fileobj)
        try:
            return stream.read(_PEEK)
        finally:
            stream.close()
    except STREAM_ERRORS:
        return None
    finally:
        fileobj.seek(0)


_CODECS: tuple[tuple[Callable[[bytes], bool], ArchiveFormat, ArchiveFormat, Callable[[BinaryIO], BinaryIO]], ...] = (
    (
        lambda h: h[:2] == b"\x1f\x8b",
        ArchiveFormat.GZIP,
        ArchiveFormat.TAR_GZ,
        lambda f: gzip.GzipFile(fileobj=f, mode="rb"),  # type: ignore[return-value]
    ),
    (
        lambda h: h[:3] == b"BZh" and h[3:4] in (b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9"),
        ArchiveFormat.BZIP2,
        ArchiveFormat.TAR_BZ2,
        lambda f: bz2.BZ2File(f, "rb"),  # type: ignore[return-value]
    ),
    (
        lambda h: h[:6] == b"\xfd7zXZ\x00",
        ArchiveFormat.XZ,
        ArchiveFormat.TAR_XZ,
        lambda f: lzma.LZMAFile(f, "rb"),  # type: ignore[return-value]
    ),
)


def detect_format(fileobj: BinaryIO, name: str = "") -> ArchiveFormat | None:
    """Identify the archive format from content. Returns ``None`` if it is not recognised.

    Never raises for damaged input: a corrupted gzip file is still reported as gzip so that
    ``verify`` can describe the damage.
    """
    fileobj.seek(0)
    head = fileobj.read(_PEEK)
    fileobj.seek(0)
    if not head:
        return None
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return ArchiveFormat.ZIP
    for matches, stream_format, tar_format, opener in _CODECS:
        if matches(head):
            payload = _peek_decompressed(fileobj, opener)
            if payload is None:
                # Cannot decompress even the first block: fall back to the name as a hint.
                return tar_format if _name_hints_tar(name, tar_format) else stream_format
            if _looks_like_tar(payload, name):
                return tar_format
            if len(payload) == _PEEK and payload.count(0) == _PEEK and _name_hints_tar(name, tar_format):
                return tar_format
            return stream_format
    if _looks_like_tar(head, name):
        return ArchiveFormat.TAR
    try:
        if zipfile.is_zipfile(fileobj):  # ZIPs with a prefix, e.g. self-extracting archives
            return ArchiveFormat.ZIP
    finally:
        fileobj.seek(0)
    return None


def identify_unsupported(head: bytes) -> str | None:
    """Name a recognised-but-unsupported format (7z, RAR, Zstandard), if any."""
    for magic, label in _UNSUPPORTED_MAGIC:
        if head.startswith(magic):
            return label
    return None
