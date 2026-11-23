"""The ``inspect`` pipeline: stream entries once, accumulate statistics and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from packlens.analysis.paths import ArchiveAnalyzer
from packlens.core.errors import ArchiveReadError
from packlens.core.limits import Limits
from packlens.core.models import (
    ArchiveFormat,
    ArchiveInfo,
    ArchiveStats,
    Finding,
    Severity,
)
from packlens.formats.base import ArchiveHandler
from packlens.utils.formatting import json_safe


@dataclass
class InspectionReport:
    info: ArchiveInfo
    stats: ArchiveStats
    findings: list[Finding]
    finding_counts: dict[str, int]
    findings_suppressed: int = 0
    error: str | None = None  # set when the archive could only be listed partially
    nested: list[Any] = field(default_factory=list)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.WARNING)

    @property
    def compression_ratio(self) -> float | None:
        """Uncompressed / archive size. ``None`` where it is not meaningful (plain TAR, unknown sizes)."""
        if self.info.format is ArchiveFormat.TAR or self.stats.size_unknown:
            return None
        if not self.info.compressed_size or not self.stats.total_size:
            return None
        return self.stats.total_size / self.info.compressed_size

    def to_dict(self) -> dict[str, Any]:
        stats = self.stats
        ratio = self.compression_ratio
        return {
            "archive": {
                "name": json_safe(self.info.name),
                "format": self.info.format.value,
                "compressed_size": self.info.compressed_size,
                "metadata": {k: json_safe(v) for k, v in self.info.metadata.items()},
            },
            "summary": {
                "entries": stats.entry_count,
                "files": stats.file_count,
                "directories": stats.directory_count,
                "symlinks": stats.symlink_count,
                "hardlinks": stats.hardlink_count,
                "other": stats.other_count,
                "uncompressed_size": None if stats.size_unknown else stats.total_size,
                "compression_ratio": round(ratio, 3) if ratio is not None else None,
            },
            "integrity": {"available": self.info.integrity.available, "scope": self.info.integrity.scope},
            "findings": [f.to_dict() for f in self.findings],
            "finding_counts": dict(self.finding_counts),
            "findings_not_listed": self.findings_suppressed,
            "nested": [n.to_dict() for n in self.nested],
            "error": json_safe(self.error),
        }


def inspect_archive(
    handler: ArchiveHandler,
    limits: Limits,
    *,
    on_entry: Callable[[int], None] | None = None,
) -> InspectionReport:
    """Collect statistics and findings without holding entries in memory."""
    stats = ArchiveStats()
    analyzer = ArchiveAnalyzer(limits)
    error: str | None = None
    try:
        for entry in handler.entries():
            stats.add(entry)
            analyzer.feed(entry)
            if on_entry is not None and stats.entry_count % 1000 == 0:
                on_entry(stats.entry_count)
    except ArchiveReadError as exc:
        error = str(exc)
    info = handler.info()
    analyzer.finish(info, stats)
    findings = handler.notes() + analyzer.findings
    return InspectionReport(
        info=info,
        stats=stats,
        findings=findings,
        finding_counts=dict(analyzer.counts) | _count_codes(handler.notes()),
        findings_suppressed=analyzer.suppressed,
        error=error,
    )


def _count_codes(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.code] = counts.get(finding.code, 0) + 1
    return counts
