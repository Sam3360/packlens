"""Typed models shared across Packlens."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from packlens.utils.formatting import json_safe


class ArchiveFormat(str, enum.Enum):
    ZIP = "zip"
    TAR = "tar"
    TAR_GZ = "tar.gz"
    TAR_BZ2 = "tar.bz2"
    TAR_XZ = "tar.xz"
    GZIP = "gzip"
    BZIP2 = "bzip2"
    XZ = "xz"

    @property
    def label(self) -> str:
        return _FORMAT_LABELS[self]

    @property
    def is_tar(self) -> bool:
        return self in (ArchiveFormat.TAR, ArchiveFormat.TAR_GZ, ArchiveFormat.TAR_BZ2, ArchiveFormat.TAR_XZ)

    @property
    def is_stream(self) -> bool:
        return self in (ArchiveFormat.GZIP, ArchiveFormat.BZIP2, ArchiveFormat.XZ)

    @property
    def is_compressed(self) -> bool:
        return self is not ArchiveFormat.TAR


_FORMAT_LABELS = {
    ArchiveFormat.ZIP: "ZIP",
    ArchiveFormat.TAR: "TAR",
    ArchiveFormat.TAR_GZ: "TAR + gzip",
    ArchiveFormat.TAR_BZ2: "TAR + bzip2",
    ArchiveFormat.TAR_XZ: "TAR + xz",
    ArchiveFormat.GZIP: "gzip stream",
    ArchiveFormat.BZIP2: "bzip2 stream",
    ArchiveFormat.XZ: "xz stream",
}


class EntryType(str, enum.Enum):
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    HARDLINK = "hardlink"
    OTHER = "other"  # devices, FIFOs and other special files


class Severity(str, enum.Enum):
    INFO = "info"
    WARNING = "warning"


@dataclass(frozen=True, slots=True)
class ArchiveEntry:
    """One member of an archive, as declared by the archive's own metadata (untrusted)."""

    index: int
    path: str
    type: EntryType
    size: int | None  # declared uncompressed size; None when unknown
    compressed_size: int | None = None
    mtime: datetime | None = None
    compression: str | None = None
    crc32: int | None = None
    mode: int | None = None  # permission bits only (0o7777)
    link_target: str | None = None
    encrypted: bool = False

    @property
    def is_file(self) -> bool:
        return self.type is EntryType.FILE

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": json_safe(self.path),
            "type": self.type.value,
            "size": self.size,
            "compressed_size": self.compressed_size,
            "mtime": self.mtime.isoformat() if self.mtime else None,
            "compression": self.compression,
            "crc32": f"{self.crc32:08x}" if self.crc32 is not None else None,
            "mode": f"{self.mode:04o}" if self.mode is not None else None,
            "link_target": json_safe(self.link_target),
            "encrypted": self.encrypted,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """A warning or note about an archive. Findings are observations, never verdicts of intent."""

    code: str
    severity: Severity
    message: str
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "message": json_safe(self.message),
            "path": json_safe(self.path),
        }


@dataclass(frozen=True, slots=True)
class IntegrityInfo:
    """What kind of integrity checking a format supports."""

    available: bool
    scope: str


@dataclass
class ArchiveInfo:
    name: str
    format: ArchiveFormat
    compressed_size: int | None  # size of the archive file/stream itself
    integrity: IntegrityInfo
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class ArchiveStats:
    """Aggregate numbers, accumulated one entry at a time."""

    file_count: int = 0
    directory_count: int = 0
    symlink_count: int = 0
    hardlink_count: int = 0
    other_count: int = 0
    total_size: int = 0
    size_unknown: bool = False
    entry_compressed_total: int = 0
    entry_compressed_known: bool = True

    @property
    def entry_count(self) -> int:
        return (
            self.file_count + self.directory_count + self.symlink_count + self.hardlink_count + self.other_count
        )

    def add(self, entry: ArchiveEntry) -> None:
        if entry.type is EntryType.FILE:
            self.file_count += 1
        elif entry.type is EntryType.DIRECTORY:
            self.directory_count += 1
        elif entry.type is EntryType.SYMLINK:
            self.symlink_count += 1
        elif entry.type is EntryType.HARDLINK:
            self.hardlink_count += 1
        else:
            self.other_count += 1
        if entry.type is EntryType.FILE:
            if entry.size is None:
                self.size_unknown = True
            else:
                self.total_size += entry.size
        if entry.compressed_size is None:
            if entry.type is EntryType.FILE:
                self.entry_compressed_known = False
        else:
            self.entry_compressed_total += entry.compressed_size
