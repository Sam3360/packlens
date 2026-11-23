"""Duplicate detection in stages: group by size, then hash only same-size candidates, streaming."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

from packlens.core.errors import ArchiveReadError, UnsupportedFeatureError
from packlens.core.models import EntryType
from packlens.formats.base import ArchiveHandler
from packlens.utils.formatting import json_safe
from packlens.utils.hashing import hash_stream

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


@dataclass
class DuplicateGroup:
    size: int
    sha256: str
    paths: list[str]

    @property
    def wasted(self) -> int:
        return self.size * (len(self.paths) - 1)


@dataclass
class DuplicateReport:
    archive: str
    files_examined: int = 0
    candidates_hashed: int = 0
    bytes_hashed: int = 0
    groups: list[DuplicateGroup] = field(default_factory=list)  # identical *content*
    repeated_paths: dict[str, int] = field(default_factory=dict)  # same *name* stored more than once
    skipped: list[tuple[str, str]] = field(default_factory=list)
    error: str | None = None

    @property
    def wasted_bytes(self) -> int:
        return sum(g.wasted for g in self.groups)

    def to_dict(self) -> dict[str, Any]:
        return {
            "archive": json_safe(self.archive),
            "files_examined": self.files_examined,
            "candidates_hashed": self.candidates_hashed,
            "bytes_hashed": self.bytes_hashed,
            "duplicate_content": [
                {"size": g.size, "sha256": g.sha256, "count": len(g.paths), "wasted_bytes": g.wasted, "paths": [json_safe(p) for p in g.paths]}
                for g in self.groups
            ],
            "wasted_bytes": self.wasted_bytes,
            "repeated_paths": {json_safe(p): n for p, n in self.repeated_paths.items()},
            "skipped": [{"path": json_safe(p), "reason": json_safe(r)} for p, r in self.skipped],
            "error": json_safe(self.error),
        }


def find_duplicates(
    handler: ArchiveHandler,
    *,
    include_empty: bool = False,
    on_progress: Callable[[int], None] | None = None,
) -> DuplicateReport:
    report = DuplicateReport(archive=handler.info().name)
    by_size: dict[int, list[tuple[int, str]]] = defaultdict(list)
    path_counts: Counter[str] = Counter()
    try:
        for entry in handler.entries():
            if entry.type is not EntryType.FILE:
                continue
            report.files_examined += 1
            path_counts[entry.path] += 1
            if entry.size is None:
                continue
            by_size[entry.size].append((entry.index, entry.path))
    except ArchiveReadError as exc:
        report.error = str(exc)
        return report
    report.repeated_paths = {p: n for p, n in path_counts.items() if n > 1}

    found: dict[tuple[int, str], list[str]] = defaultdict(list)
    candidates: dict[int, str] = {}
    for size, members in by_size.items():
        if len(members) < 2:
            continue
        if size == 0:
            if include_empty:
                found[(0, EMPTY_SHA256)].extend(p for _, p in members)  # all empty files are identical
            continue
        candidates.update(members)
    report.candidates_hashed = len(candidates)

    if candidates:
        done = 0
        try:
            for entry, stream in handler.iter_data(select=lambda e: e.index in candidates):
                if stream is None or entry.index not in candidates:
                    continue
                try:
                    digest, actual = hash_stream(stream)
                except (ArchiveReadError, UnsupportedFeatureError) as exc:
                    report.skipped.append((entry.path, str(exc)))
                    continue
                report.bytes_hashed += actual
                found[(actual, digest)].append(entry.path)
                done += 1
                if on_progress:
                    on_progress(done)
        except ArchiveReadError as exc:
            report.error = str(exc)
    report.groups = sorted(
        (DuplicateGroup(size, digest, paths) for (size, digest), paths in found.items() if len(paths) > 1),
        key=lambda g: (-g.wasted, g.paths[0]),
    )
    return report
