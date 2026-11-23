"""Path and metadata analysis. Everything here treats archive contents as untrusted input.

Findings are observations ("this path would leave the extraction directory if extracted
naively"), not claims about intent.
"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter

from packlens.analysis.nested import archive_label_from_name
from packlens.core.limits import Limits
from packlens.core.models import (
    ArchiveEntry,
    ArchiveInfo,
    ArchiveFormat,
    ArchiveStats,
    EntryType,
    Finding,
    Severity,
)
from packlens.utils.formatting import BIDI_CONTROLS, format_size

RATIO_MIN_SIZE = 1024 * 1024  # ratios of tiny entries are meaningless noise
_SEPARATORS = re.compile(r"[\\/]+")
_DRIVE = re.compile(r"^[A-Za-z]:")


def components(path: str) -> list[str]:
    """Split on both ``/`` and ``\\`` (conservative: Windows treats both as separators)."""
    return [part for part in _SEPARATORS.split(path) if part not in ("", ".")]


def escapes_root(parts: list[str]) -> bool:
    """True if resolving ``..`` in ``parts`` would climb above the starting directory."""
    depth = 0
    for part in parts:
        if part == "..":
            if depth == 0:
                return True
            depth -= 1
        else:
            depth += 1
    return False


def normalized_key(path: str) -> str:
    """Canonical form for duplicate detection: separators, ``.`` and ``..`` resolved."""
    stack: list[str] = []
    for part in components(path):
        if part == "..":
            if stack and stack[-1] != "..":
                stack.pop()
            else:
                stack.append("..")
        else:
            stack.append(part)
    return "/".join(stack)


def _is_absolute(target: str) -> bool:
    return target.startswith(("/", "\\")) or bool(_DRIVE.match(target))


def analyze_path(path: str, *, warn_depth: int) -> list[Finding]:
    """Findings for a single entry path, independent of any other entry."""
    found: list[Finding] = []

    def add(code: str, message: str, severity: Severity = Severity.WARNING) -> None:
        found.append(Finding(code, severity, message, path))

    if any(ord(ch) < 32 or ord(ch) == 127 for ch in path):
        add("control-characters", "path contains control characters (including NUL or newlines)")
    if any(ch in BIDI_CONTROLS for ch in path):
        add("bidi-control", "path contains bidirectional text controls that can disguise the real name")
    if any("\udc80" <= ch <= "\udcff" for ch in path):
        add("invalid-encoding", "path is not valid UTF-8; shown with escapes", Severity.INFO)
    if path.startswith(("/", "\\")):
        add("absolute-path", "absolute path: extracting naively could write outside the target directory")
    if _DRIVE.match(path):
        add("windows-drive-path", "path starts with a Windows drive letter")
    if "\\" in path:
        add("backslash-separator", "path contains a backslash, which Windows treats as a directory separator")

    parts = components(path)
    if escapes_root(parts):
        add(
            "path-traversal",
            "path climbs out of the extraction directory ('..'); extracting naively could write outside it",
        )
    elif ".." in parts:
        add("parent-reference", "path contains '..' components but stays inside the extraction directory")
    if len(parts) > warn_depth:
        add("deep-nesting", f"path is {len(parts)} levels deep (threshold {warn_depth})")
    return found


def link_escapes(entry: ArchiveEntry) -> bool | None:
    """Whether a link target resolves outside the extraction root. ``None`` if unknown."""
    target = entry.link_target
    if not target:
        return None
    if _is_absolute(target):
        return True
    base = components(entry.path)[:-1] if entry.type is EntryType.SYMLINK else []
    return escapes_root(base + components(target))


class ArchiveAnalyzer:
    """Feed entries one at a time; collect findings with bounded memory."""

    def __init__(self, limits: Limits) -> None:
        self._limits = limits
        self.findings: list[Finding] = []
        self.counts: Counter[str] = Counter()
        self.suppressed = 0
        self._seen: dict[str, bool] = {}  # normalized path -> is directory
        self._folded: dict[str, str] = {}  # case/NFC-folded path -> normalized path

    def _add(self, finding: Finding) -> None:
        self.counts[finding.code] += 1
        if len(self.findings) < self._limits.max_findings:
            self.findings.append(finding)
        else:
            self.suppressed += 1

    def feed(self, entry: ArchiveEntry) -> None:
        limits = self._limits
        for finding in analyze_path(entry.path, warn_depth=limits.warn_path_depth):
            self._add(finding)
        self._check_conflicts(entry)
        self._check_metadata(entry)

    def _check_conflicts(self, entry: ArchiveEntry) -> None:
        key = normalized_key(entry.path)
        if not key:
            return
        is_dir = entry.type is EntryType.DIRECTORY
        if key in self._seen:
            if self._seen[key] != is_dir:
                self._add(
                    Finding(
                        "type-conflict",
                        Severity.WARNING,
                        "path appears both as a file and as a directory",
                        entry.path,
                    )
                )
            elif not is_dir:
                self._add(
                    Finding(
                        "duplicate-path",
                        Severity.WARNING,
                        "path appears more than once; on extraction a later entry replaces an earlier one",
                        entry.path,
                    )
                )
            return
        self._seen[key] = is_dir
        folded = unicodedata.normalize("NFC", key).casefold()
        other = self._folded.get(folded)
        if other is not None and other != key:
            self._add(
                Finding(
                    "case-collision",
                    Severity.INFO,
                    f"differs from {other!r} only by letter case or Unicode form; "
                    "they would collide on case-insensitive filesystems",
                    entry.path,
                )
            )
        else:
            self._folded[folded] = key

    def _check_metadata(self, entry: ArchiveEntry) -> None:
        limits = self._limits
        path = entry.path
        if entry.type is EntryType.SYMLINK:
            escapes = link_escapes(entry)
            target = entry.link_target if entry.link_target is not None else "(unreadable)"
            if escapes:
                self._add(
                    Finding(
                        "symlink-escape",
                        Severity.WARNING,
                        f"symbolic link to {target!r} points outside the extraction directory",
                        path,
                    )
                )
            else:
                self._add(Finding("symlink", Severity.WARNING, f"symbolic link to {target!r}", path))
        elif entry.type is EntryType.HARDLINK:
            if link_escapes(entry):
                self._add(
                    Finding(
                        "hardlink-escape",
                        Severity.WARNING,
                        f"hard link to {entry.link_target!r} points outside the extraction directory",
                        path,
                    )
                )
            else:
                self._add(Finding("hardlink", Severity.WARNING, f"hard link to {entry.link_target!r}", path))
        elif entry.type is EntryType.OTHER:
            self._add(
                Finding("special-file", Severity.WARNING, "special file (device node, FIFO or similar)", path)
            )
        if entry.type is EntryType.FILE and entry.mode is not None and entry.mode & 0o6000:
            self._add(Finding("special-permissions", Severity.WARNING, "setuid or setgid bit is set", path))
        if entry.encrypted:
            self._add(
                Finding("encrypted-entry", Severity.INFO, "entry is encrypted; its contents cannot be checked", path)
            )
        if entry.size is not None and entry.size > limits.warn_entry_size:
            self._add(
                Finding(
                    "large-entry",
                    Severity.WARNING,
                    f"declared size is {format_size(entry.size)} (threshold {format_size(limits.warn_entry_size)})",
                    path,
                )
            )
        if (
            entry.size is not None
            and entry.compressed_size
            and entry.size >= RATIO_MIN_SIZE
            and entry.size / entry.compressed_size >= limits.warn_ratio
        ):
            self._add(
                Finding(
                    "high-compression-ratio",
                    Severity.WARNING,
                    f"expands {entry.size / entry.compressed_size:,.0f}x "
                    f"({format_size(entry.compressed_size)} -> {format_size(entry.size)})",
                    path,
                )
            )
        label = archive_label_from_name(path) if entry.type is EntryType.FILE else None
        if label is not None:
            self._add(Finding("nested-archive", Severity.INFO, f"file looks like a nested {label} archive", path))

    def finish(self, info: ArchiveInfo, stats: ArchiveStats) -> list[Finding]:
        """Archive-level findings that need the totals. Returns the complete finding list."""
        limits = self._limits
        if stats.entry_count > limits.warn_entries:
            self._add(
                Finding(
                    "many-entries",
                    Severity.WARNING,
                    f"archive has {stats.entry_count:,} entries (threshold {limits.warn_entries:,})",
                )
            )
        if (
            info.format is not ArchiveFormat.TAR
            and not stats.size_unknown
            and info.compressed_size
            and stats.total_size >= RATIO_MIN_SIZE
            and stats.total_size / info.compressed_size >= limits.warn_ratio
        ):
            self._add(
                Finding(
                    "high-total-ratio",
                    Severity.WARNING,
                    f"archive expands {stats.total_size / info.compressed_size:,.0f}x overall "
                    f"({format_size(info.compressed_size)} -> {format_size(stats.total_size)})",
                )
            )
        return self.findings
