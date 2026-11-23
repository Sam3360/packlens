"""Compare two archives without extracting either.

A matching size is never reported as "identical". Only a hash comparison (``--by hash``),
or two empty files, establishes that content is the same.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from packlens.analysis.paths import normalized_key
from packlens.core.errors import ArchiveReadError, UnsupportedFeatureError
from packlens.core.models import ArchiveEntry, EntryType
from packlens.formats.base import ArchiveHandler
from packlens.utils.formatting import json_safe
from packlens.utils.hashing import hash_stream

MTIME_TOLERANCE_SECONDS = 2  # ZIP timestamps have 2-second resolution


class CompareMode(str, enum.Enum):
    PATH = "path"  # which paths exist
    SIZE = "size"  # paths plus sizes (and CRC-32 where both archives have it)
    HASH = "hash"  # paths plus SHA-256 of content


@dataclass
class Change:
    path: str
    reasons: list[str]
    old: ArchiveEntry
    new: ArchiveEntry


@dataclass
class ComparisonReport:
    mode: CompareMode
    old_name: str
    new_name: str
    added: list[ArchiveEntry] = field(default_factory=list)
    removed: list[ArchiveEntry] = field(default_factory=list)
    changed: list[Change] = field(default_factory=list)
    in_both: int = 0
    identical: int = 0  # content proven equal (hash match, or both empty)
    same_size_unverified: int = 0  # size matches; content was NOT compared
    unverifiable: list[tuple[str, str]] = field(default_factory=list)
    metadata_changes: list[tuple[str, dict[str, tuple[str, str]]]] = field(default_factory=list)
    repeated_paths_old: int = 0
    repeated_paths_new: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "old": json_safe(self.old_name),
            "new": json_safe(self.new_name),
            "summary": {
                "added": len(self.added),
                "removed": len(self.removed),
                "changed": len(self.changed),
                "in_both": self.in_both,
                "identical": self.identical,
                "same_size_content_not_compared": self.same_size_unverified,
                "unverifiable": len(self.unverifiable),
            },
            "added": [e.to_dict() for e in self.added],
            "removed": [e.to_dict() for e in self.removed],
            "changed": [
                {"path": json_safe(c.path), "reasons": c.reasons, "old": c.old.to_dict(), "new": c.new.to_dict()}
                for c in self.changed
            ],
            "unverifiable": [{"path": json_safe(p), "reason": json_safe(r)} for p, r in self.unverifiable],
            "metadata_changes": [{"path": json_safe(p), "differences": d} for p, d in self.metadata_changes],
            "repeated_paths": {"old": self.repeated_paths_old, "new": self.repeated_paths_new},
        }


def _index(handler: ArchiveHandler) -> tuple[dict[str, ArchiveEntry], int]:
    """Map normalised path to its winning entry (the last one, as on extraction)."""
    table: dict[str, ArchiveEntry] = {}
    repeats = 0
    for entry in handler.entries():
        key = normalized_key(entry.path)
        if not key:
            continue
        if key in table and entry.type is not EntryType.DIRECTORY:
            repeats += 1
        table[key] = entry
    return table, repeats


def _hash_entries(handler: ArchiveHandler, wanted: set[int]) -> tuple[dict[int, str], dict[int, str]]:
    digests: dict[int, str] = {}
    problems: dict[int, str] = {}
    if not wanted:
        return digests, problems
    for entry, stream in handler.iter_data(select=lambda e: e.index in wanted):
        if stream is None or entry.index not in wanted:
            continue
        try:
            digests[entry.index], _ = hash_stream(stream)
        except (ArchiveReadError, UnsupportedFeatureError) as exc:
            problems[entry.index] = str(exc)
    return digests, problems


def _metadata_diff(old: ArchiveEntry, new: ArchiveEntry) -> dict[str, tuple[str, str]]:
    diff: dict[str, tuple[str, str]] = {}
    if old.mode is not None and new.mode is not None and old.mode != new.mode:
        diff["mode"] = (f"{old.mode:04o}", f"{new.mode:04o}")
    a, b = old.mtime, new.mtime
    # Naive (ZIP) and aware (TAR) timestamps are not comparable; skip rather than guess.
    if a is not None and b is not None and (a.tzinfo is None) == (b.tzinfo is None):
        if abs((a - b).total_seconds()) > MTIME_TOLERANCE_SECONDS:
            diff["mtime"] = (a.isoformat(), b.isoformat())
    return diff


def compare_archives(
    old: ArchiveHandler,
    new: ArchiveHandler,
    mode: CompareMode = CompareMode.SIZE,
    *,
    include_metadata: bool = False,
) -> ComparisonReport:
    report = ComparisonReport(mode, old.name, new.name)
    old_index, report.repeated_paths_old = _index(old)
    new_index, report.repeated_paths_new = _index(new)
    report.removed = [old_index[k] for k in sorted(old_index.keys() - new_index.keys())]
    report.added = [new_index[k] for k in sorted(new_index.keys() - old_index.keys())]

    to_hash: list[tuple[str, ArchiveEntry, ArchiveEntry]] = []
    for key in sorted(old_index.keys() & new_index.keys()):
        a, b = old_index[key], new_index[key]
        report.in_both += 1
        reasons: list[str] = []
        if a.type is not b.type:
            reasons.append(f"type: {a.type.value} -> {b.type.value}")
        elif a.type in (EntryType.SYMLINK, EntryType.HARDLINK):
            if a.link_target != b.link_target:
                reasons.append(f"link target: {a.link_target!r} -> {b.link_target!r}")
        elif a.type is EntryType.FILE and mode is not CompareMode.PATH:
            if a.size is None or b.size is None:
                report.unverifiable.append((a.path, "size unknown in one archive"))
            elif a.size != b.size:
                reasons.append(f"size: {a.size:,} -> {b.size:,} bytes")
            elif a.size == 0:
                report.identical += 1  # two empty files are provably the same
            elif a.crc32 is not None and b.crc32 is not None and a.crc32 != b.crc32:
                reasons.append("content differs (CRC-32 mismatch)")
            elif mode is CompareMode.HASH:
                to_hash.append((key, a, b))
            else:
                report.same_size_unverified += 1
        if reasons:
            report.changed.append(Change(a.path, reasons, a, b))
        elif include_metadata:
            diff = _metadata_diff(a, b)
            if diff:
                report.metadata_changes.append((a.path, diff))

    if to_hash:
        old_digests, old_problems = _hash_entries(old, {a.index for _, a, _ in to_hash})
        new_digests, new_problems = _hash_entries(new, {b.index for _, _, b in to_hash})
        for _key, a, b in to_hash:
            if a.index in old_problems or b.index in new_problems:
                report.unverifiable.append((a.path, old_problems.get(a.index) or new_problems.get(b.index, "")))
            elif old_digests.get(a.index) == new_digests.get(b.index) and a.index in old_digests:
                report.identical += 1
            else:
                report.changed.append(Change(a.path, ["content differs (SHA-256)"], a, b))
        report.changed.sort(key=lambda c: c.path)
    return report
