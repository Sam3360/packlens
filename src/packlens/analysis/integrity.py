"""Integrity verification: read every byte and let the format's own checks run.

Results are kept honest: a check is *passed*, *failed*, or *unavailable*, and the report says
what kind of verification actually took place (content checksums versus structure only).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Callable

from packlens.core.errors import ArchiveReadError, UnsupportedFeatureError
from packlens.core.models import ArchiveEntry, ArchiveFormat
from packlens.formats.base import ArchiveHandler
from packlens.utils.formatting import json_safe
from packlens.utils.hashing import CHUNK_SIZE

MAX_STORED_RESULTS = 1000


class CheckStatus(str, enum.Enum):
    PASSED = "passed"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: CheckStatus
    detail: str
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "status": self.status.value, "detail": json_safe(self.detail), "path": json_safe(self.path)}


@dataclass
class VerifyReport:
    archive: str
    format: ArchiveFormat
    scope: str
    checksums_per_entry: bool  # does the format carry checksums that were compared?
    integrity_available: bool
    entries_total: int = 0
    entries_without_data: int = 0  # directories, links and other entries with nothing to read
    passed: int = 0
    failed: int = 0
    unavailable: int = 0
    bytes_read: int = 0
    structure: CheckResult | None = None
    results: list[CheckResult] = field(default_factory=list)  # failures and unavailable checks only
    results_not_listed: int = 0

    @property
    def verdict(self) -> str:
        structure_failed = self.structure is not None and self.structure.status is CheckStatus.FAILED
        if self.failed or structure_failed:
            return "failed"
        if self.unavailable or not self.integrity_available:
            return "incomplete"
        return "passed"

    @property
    def level(self) -> str:
        """What the passed checks actually establish."""
        if self.checksums_per_entry and self.integrity_available:
            return "content-checksums"
        return "structure-and-readability"

    def to_dict(self) -> dict[str, Any]:
        return {
            "archive": json_safe(self.archive),
            "format": self.format.value,
            "verdict": self.verdict,
            "level": self.level,
            "scope": self.scope,
            "entries": {
                "total": self.entries_total,
                "without_data": self.entries_without_data,
                "passed": self.passed,
                "failed": self.failed,
                "unavailable": self.unavailable,
            },
            "bytes_read": self.bytes_read,
            "structure": self.structure.to_dict() if self.structure else None,
            "problems": [r.to_dict() for r in self.results],
            "problems_not_listed": self.results_not_listed,
        }


def verify_archive(
    handler: ArchiveHandler,
    *,
    on_result: Callable[[ArchiveEntry, CheckResult], None] | None = None,
    on_entry: Callable[[int], None] | None = None,
) -> VerifyReport:
    """Read the whole archive, collecting per-entry results. Resource-limit errors propagate."""
    info = handler.info()
    fmt = handler.format
    report = VerifyReport(
        archive=info.name,
        format=fmt,
        scope=info.integrity.scope,
        checksums_per_entry=fmt is ArchiveFormat.ZIP or fmt.is_stream,
        integrity_available=info.integrity.available,
    )

    def record(entry: ArchiveEntry, result: CheckResult) -> None:
        if result.status is CheckStatus.PASSED:
            report.passed += 1
        else:
            if result.status is CheckStatus.FAILED:
                report.failed += 1
            else:
                report.unavailable += 1
            if len(report.results) < MAX_STORED_RESULTS:
                report.results.append(result)
            else:
                report.results_not_listed += 1
        if on_result:
            on_result(entry, result)

    pass_detail = {
        True: "content checksum matched",
        False: "readable and size matches header (format has no content checksum)",
    }[report.checksums_per_entry and info.integrity.available]
    try:
        for entry, stream in handler.iter_data(select=lambda _e: True, complete=True):
            report.entries_total += 1
            if on_entry and report.entries_total % 100 == 0:
                on_entry(report.entries_total)
            if stream is None:
                report.entries_without_data += 1
                continue
            try:
                total = 0
                while True:
                    chunk = stream.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    total += len(chunk)
                report.bytes_read += total
                if entry.size is not None and total != entry.size:
                    record(entry, CheckResult("entry-data", CheckStatus.FAILED, f"declared size {entry.size:,} bytes but {total:,} were read", entry.path))
                else:
                    record(entry, CheckResult("entry-data", CheckStatus.PASSED, pass_detail, entry.path))
            except UnsupportedFeatureError as exc:
                record(entry, CheckResult("entry-data", CheckStatus.UNAVAILABLE, str(exc), entry.path))
            except ArchiveReadError as exc:
                record(entry, CheckResult("entry-data", CheckStatus.FAILED, str(exc), entry.path))
        report.structure = CheckResult("archive-structure", CheckStatus.PASSED, "all headers and the end of the archive are well-formed")
    except ArchiveReadError as exc:
        report.structure = CheckResult("archive-structure", CheckStatus.FAILED, str(exc))
    return report
