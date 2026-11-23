"""Inspect archives stored inside archives, in memory, within configured limits.

Nested archives are never written to disk. Each one is read into memory (bounded by
``max_nested_size``), inspected, and discarded. Depth is bounded by ``max_nesting_depth`` and
all reads count against the shared decompression budget.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from typing import Any

from packlens.analysis.inspection import InspectionReport, inspect_archive
from packlens.analysis.nested import archive_label_from_name, is_supported_label, magic_format
from packlens.core.archive import open_archive_stream
from packlens.core.errors import (
    ArchiveReadError,
    LimitExceededError,
    UnsupportedFeatureError,
    UnsupportedFormatError,
)
from packlens.core.limits import Budget, Limits
from packlens.core.models import EntryType
from packlens.formats.base import ArchiveHandler, read_bounded
from packlens.utils.formatting import json_safe

_SNIFF = 512


@dataclass
class NestedArchive:
    path: str  # path of the nested archive inside its parent
    depth: int  # 1 = directly inside the archive that was opened
    status: str  # "inspected", "skipped" or "error"
    reason: str | None = None
    report: InspectionReport | None = None
    children: list["NestedArchive"] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "path": json_safe(self.path),
            "depth": self.depth,
            "status": self.status,
            "reason": json_safe(self.reason),
        }
        if self.report is not None:
            body = self.report.to_dict()
            data.update(format=body["archive"]["format"], summary=body["summary"], findings=body["findings"], error=body["error"])
        data["children"] = [c.to_dict() for c in self.children]
        return data


def scan_nested(handler: ArchiveHandler, limits: Limits, budget: Budget, depth: int = 1) -> list[NestedArchive]:
    """Find and inspect nested archives. Candidates are found by name *and* by content signature."""
    results: list[NestedArchive] = []
    try:
        for entry, stream in handler.iter_data(select=lambda e: e.type is EntryType.FILE and bool(e.size)):
            if stream is None or len(results) >= limits.max_findings:
                continue
            label = archive_label_from_name(entry.path)
            try:
                head = stream.read(_SNIFF)
            except (ArchiveReadError, UnsupportedFeatureError) as exc:
                if label:
                    results.append(NestedArchive(entry.path, depth, "error", str(exc)))
                continue
            sniffed = magic_format(head)
            if label is None and sniffed is None:
                continue
            if label is not None and not is_supported_label(label) and sniffed is None:
                results.append(NestedArchive(entry.path, depth, "skipped", f"{label} archives are not supported yet"))
                continue
            results.append(_inspect_member(handler, entry.path, entry.size, head, stream, limits, budget, depth))
    except LimitExceededError as exc:
        results.append(NestedArchive("(scan stopped)", depth, "skipped", str(exc)))
    except ArchiveReadError as exc:
        results.append(NestedArchive("(scan stopped)", depth, "error", str(exc)))
    return results


def _inspect_member(handler, path, size, head, stream, limits, budget, depth) -> NestedArchive:
    if depth > limits.max_nesting_depth:
        return NestedArchive(path, depth, "skipped", f"nesting depth limit ({limits.max_nesting_depth}) reached; raise --max-nesting-depth")
    cap = limits.max_nested_size
    if cap is not None and size is not None and size > cap:
        return NestedArchive(path, depth, "skipped", f"{size:,} bytes exceeds the in-memory limit; raise --max-nested-size")
    try:
        rest = read_bounded(stream, None if cap is None else max(cap - len(head), 0), f"Nested archive {path!r}")
        buffer = io.BytesIO(head + rest)
        inner = open_archive_stream(buffer, f"{handler.name}!{path}", limits, budget)
    except UnsupportedFormatError as exc:
        return NestedArchive(path, depth, "skipped", str(exc))
    except LimitExceededError as exc:
        return NestedArchive(path, depth, "skipped", str(exc))
    except (ArchiveReadError, UnsupportedFeatureError) as exc:
        return NestedArchive(path, depth, "error", str(exc))
    with inner:
        try:
            report = inspect_archive(inner, limits)
            children = scan_nested(inner, limits, budget, depth + 1)  # beyond the limit, members are reported as skipped
        except LimitExceededError as exc:
            return NestedArchive(path, depth, "skipped", str(exc))
    return NestedArchive(path, depth, "inspected", None, report, children)
