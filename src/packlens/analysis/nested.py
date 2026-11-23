"""Detection of archives stored inside archives, and bounded in-memory inspection of them."""

from __future__ import annotations

from packlens.core.models import ArchiveFormat

# Longest suffixes first so ``.tar.gz`` wins over ``.gz``.
_SUFFIX_LABELS: tuple[tuple[str, str], ...] = (
    (".tar.gz", "tar.gz"),
    (".tar.bz2", "tar.bz2"),
    (".tar.xz", "tar.xz"),
    (".tar.zst", "tar.zst"),
    (".tgz", "tar.gz"),
    (".tbz2", "tar.bz2"),
    (".tbz", "tar.bz2"),
    (".txz", "tar.xz"),
    (".tar", "tar"),
    (".zip", "zip"),
    (".jar", "zip"),
    (".war", "zip"),
    (".ear", "zip"),
    (".whl", "zip"),
    (".gz", "gzip"),
    (".bz2", "bzip2"),
    (".xz", "xz"),
    (".7z", "7z"),
    (".rar", "rar"),
    (".zst", "zstd"),
)

_SUPPORTED_LABELS = {"tar.gz", "tar.bz2", "tar.xz", "tar", "zip", "gzip", "bzip2", "xz"}


def archive_label_from_name(path: str) -> str | None:
    """Guess the archive type from a file name alone. Cheap; the content is not examined."""
    lowered = path.rsplit("/", 1)[-1].lower()
    for suffix, label in _SUFFIX_LABELS:
        if lowered.endswith(suffix) and len(lowered) > len(suffix):
            return label
    return None


def is_supported_label(label: str) -> bool:
    return label in _SUPPORTED_LABELS


def magic_format(head: bytes) -> ArchiveFormat | None:
    """Cheap container sniffing on the first 512 bytes (compressed tars show as their codec)."""
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return ArchiveFormat.ZIP
    if head[:2] == b"\x1f\x8b":
        return ArchiveFormat.GZIP
    if head[:3] == b"BZh" and head[3:4].isdigit():
        return ArchiveFormat.BZIP2
    if head[:6] == b"\xfd7zXZ\x00":
        return ArchiveFormat.XZ
    if head[257:262] == b"ustar":
        return ArchiveFormat.TAR
    return None
