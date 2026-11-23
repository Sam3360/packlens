"""Human-readable terminal output. All archive-derived text is escaped before printing."""

from __future__ import annotations

import os
import sys
import time
from typing import IO

from packlens.analysis.inspection import InspectionReport
from packlens.analysis.tree import TreeLine
from packlens.core.models import EntryType, Finding, Severity
from packlens.utils.formatting import escape_for_terminal as esc
from packlens.utils.formatting import format_size

_STYLES = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "cyan": "36",
}


class Console:
    """Owns the output streams plus the quiet / verbose / colour decisions."""

    def __init__(
        self,
        out: IO[str] | None = None,
        err: IO[str] | None = None,
        *,
        quiet: bool = False,
        verbose: bool = False,
        color: bool | None = None,
    ) -> None:
        self.out = out if out is not None else sys.stdout
        self.err = err if err is not None else sys.stderr
        self.quiet = quiet
        self.verbose = verbose
        if color is None:
            color = (
                self.out.isatty()
                and not os.environ.get("NO_COLOR")
                and os.environ.get("TERM", "") != "dumb"
            )
        self.color = color

    def style(self, text: str, *names: str) -> str:
        if not self.color or not names:
            return text
        codes = ";".join(_STYLES[n] for n in names)
        return f"\033[{codes}m{text}\033[0m"

    def print(self, text: str = "") -> None:
        print(text, file=self.out)

    def note(self, text: str) -> None:
        """Informational message on stderr; suppressed by --quiet."""
        if not self.quiet:
            print(text, file=self.err)

    def warn(self, text: str) -> None:
        print(f"{self.style('warning:', 'yellow')} {text}", file=self.err)

    def error(self, text: str) -> None:
        print(f"{self.style('packlens: error:', 'red', 'bold')} {text}", file=self.err)

    def supports(self, text: str) -> bool:
        encoding = getattr(self.out, "encoding", None) or "ascii"
        try:
            text.encode(encoding)
        except (UnicodeEncodeError, LookupError):
            return False
        return True


class Progress:
    """A throttled one-line progress indicator on stderr. Does nothing unless stderr is a terminal."""

    def __init__(self, console: Console, label: str) -> None:
        self._console = console
        self._label = label
        self._enabled = not console.quiet and console.err.isatty()
        self._last = 0.0
        self._shown = False

    def update(self, count: int, detail: str = "") -> None:
        if not self._enabled:
            return
        now = time.monotonic()
        if now - self._last < 0.1:
            return
        self._last = now
        suffix = f" ({detail})" if detail else ""
        self._console.err.write(f"\r{self._label}: {count:,} entries{suffix}\033[K")
        self._console.err.flush()
        self._shown = True

    def finish(self) -> None:
        if self._shown:
            self._console.err.write("\r\033[K")
            self._console.err.flush()
            self._shown = False


# -- inspect -----------------------------------------------------------------------------


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count:,} {singular if count == 1 else (plural or singular + 's')}"


def _contents_line(report: InspectionReport) -> str:
    stats = report.stats
    parts = [_plural(stats.file_count, "file"), _plural(stats.directory_count, "directory", "directories")]
    if stats.symlink_count:
        parts.append(_plural(stats.symlink_count, "symlink"))
    if stats.hardlink_count:
        parts.append(_plural(stats.hardlink_count, "hardlink"))
    if stats.other_count:
        parts.append(_plural(stats.other_count, "special file"))
    return ", ".join(parts)


def render_findings(console: Console, findings: list[Finding], counts: dict[str, int], not_listed: int) -> None:
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(finding.code, []).append(finding)
    warnings = sum(n for code, n in counts.items() if any(f.severity is Severity.WARNING for f in groups.get(code, [])))
    notes = sum(counts.values()) - warnings
    console.print()
    console.print(console.style(f"Findings: {warnings:,} warning(s), {notes:,} note(s)", "bold"))
    console.print(
        console.style("  These are observations about the archive, not conclusions about intent.", "dim")
    )
    ordered = sorted(groups.items(), key=lambda kv: (kv[1][0].severity is not Severity.WARNING, kv[0]))
    sample = 50 if console.verbose else 3
    for code, items in ordered:
        first = items[0]
        tone = "yellow" if first.severity is Severity.WARNING else "cyan"
        total = counts.get(code, len(items))
        label = "warning" if first.severity is Severity.WARNING else "note"
        console.print(f"  {console.style(label, tone)} {code} x{total:,}")
        for item in items[:sample]:
            where = f"{esc(item.path)}: " if item.path else ""
            console.print(f"      {where}{esc(item.message)}")
        if total > min(len(items), sample):
            console.print(console.style(f"      ... and {total - min(len(items), sample):,} more", "dim"))
    if not_listed:
        console.print(console.style(f"  ({not_listed:,} further findings were counted but not stored)", "dim"))


def render_inspect(console: Console, report: InspectionReport, archive_arg: str) -> None:
    info, stats = report.info, report.stats
    if console.quiet:
        size = "unknown size" if stats.size_unknown else format_size(stats.total_size)
        console.print(
            f"{esc(info.name)}: {info.format.label}, {_contents_line(report)}, {size}, "
            f"{report.warning_count:,} warning(s)"
        )
        return
    rows: list[tuple[str, str]] = [
        ("Archive", esc(info.name)),
        ("Format", info.format.label),
        ("Contents", _contents_line(report)),
        (
            "Uncompressed",
            "unknown (could not be measured)" if stats.size_unknown else format_size(stats.total_size),
        ),
        ("Compressed", f"{format_size(info.compressed_size)} (archive size on disk)"),
    ]
    ratio = report.compression_ratio
    rows.append(("Ratio", f"{ratio:.2f}x" if ratio is not None else "n/a"))
    for key, value in info.metadata.items():
        rows.append((key.replace("_", " ").capitalize(), esc(value)))
    integrity = info.integrity
    verdict = "available" if integrity.available else "not available"
    rows.append(("Integrity", f"{verdict}: {integrity.scope}"))
    width = max(len(k) for k, _ in rows)
    for key, value in rows:
        console.print(f"{console.style(key.ljust(width), 'bold')}  {value}")
    if integrity.available:
        console.print(console.style(f"{' ' * width}  run `packlens verify {esc(archive_arg)}` to perform the checks", "dim"))
    if report.error:
        console.print()
        console.print(console.style(f"Listing is incomplete: {esc(report.error)}", "red"))
    if report.findings:
        render_findings(console, report.findings, report.finding_counts, report.findings_suppressed)
    else:
        console.print()
        console.print("No findings.")
    if report.nested:
        console.print()
        console.print(console.style("Nested archives", "bold"))
        for nested in report.nested:
            render_nested(console, nested, indent=0)


def render_nested(console: Console, nested: object, indent: int) -> None:
    """Rendered by the nested-archive module; kept here so all terminal output lives in one place."""
    from packlens.analysis.nested_scan import NestedArchive

    assert isinstance(nested, NestedArchive)
    pad = "  " * indent
    head = f"{pad}  {esc(nested.path)}"
    if nested.status == "inspected" and nested.report is not None:
        r = nested.report
        console.print(f"{head}  [{r.info.format.label}] {_contents_line(r)}, {r.warning_count:,} warning(s)")
        for f in r.findings:
            if f.severity is Severity.WARNING:
                console.print(f"{pad}      {console.style('warning', 'yellow')} {f.code}: {esc(f.path or '')} {esc(f.message)}")
    else:
        console.print(f"{head}  {console.style(nested.status, 'yellow')}: {esc(nested.reason or '')}")
    for child in nested.children:
        render_nested(console, child, indent + 1)


# -- tree --------------------------------------------------------------------------------


def render_tree_line(console: Console, line: TreeLine) -> str:
    node = line.node
    name = esc(node.name)
    entry = node.entry
    suffix = ""
    if node.is_dir:
        name += "/"
        suffix = f"  ({format_size(node.total_size)})"
        if line.hidden:
            suffix = f"  ({format_size(node.total_size)}, {line.hidden:,} item(s) hidden by --depth)"
    elif entry is not None:
        if entry.type is EntryType.SYMLINK:
            name += f" -> {esc(entry.link_target or '?')}"
        elif entry.type is EntryType.HARDLINK:
            name += f" => {esc(entry.link_target or '?')} (hard link)"
        elif entry.type is EntryType.OTHER:
            suffix = "  (special file)"
        else:
            suffix = f"  ({format_size(entry.size)})"
    if node.repeats:
        suffix += console.style(f"  [path stored {node.repeats + 1} times]", "yellow")
    if node.conflict:
        suffix += console.style("  [stored as both file and directory]", "yellow")
    shown = console.style(name, "bold") if node.is_dir else name
    return f"{line.prefix}{shown}{console.style(suffix, 'dim') if suffix and not node.repeats and not node.conflict else suffix}"


# -- verify ------------------------------------------------------------------------------


def render_verify(console: Console, report: "VerifyReport") -> None:  # noqa: F821
    from packlens.analysis.integrity import CheckStatus

    verdict = report.verdict
    if console.quiet:
        if verdict != "passed":
            console.print(f"{esc(report.archive)}: {verdict.upper()}")
        for result in report.results:
            if result.status is CheckStatus.FAILED:
                console.print(f"  FAILED {esc(result.path or '')}: {esc(result.detail)}")
        if report.structure and report.structure.status is CheckStatus.FAILED:
            console.print(f"  FAILED archive structure: {esc(report.structure.detail)}")
        return
    console.print(f"{console.style('Archive', 'bold')}   {esc(report.archive)} ({report.format.label})")
    console.print(f"{console.style('Checks', 'bold')}    {report.scope}")
    console.print(
        f"{console.style('Entries', 'bold')}   {report.entries_total:,} total: "
        f"{report.passed:,} passed, {report.failed:,} failed, {report.unavailable:,} unavailable, "
        f"{report.entries_without_data:,} with no data to check"
    )
    console.print(f"{console.style('Read', 'bold')}      {format_size(report.bytes_read)} decompressed")
    structure = report.structure
    if structure is not None:
        tone = "green" if structure.status is CheckStatus.PASSED else "red"
        console.print(f"{console.style('Structure', 'bold')} {console.style(structure.status.value, tone)}: {esc(structure.detail)}")
    for result in report.results:
        tone = "red" if result.status is CheckStatus.FAILED else "yellow"
        console.print(f"  {console.style(result.status.value.upper(), tone)} {esc(result.path or '')}: {esc(result.detail)}")
    if report.results_not_listed:
        console.print(console.style(f"  ... and {report.results_not_listed:,} more problems not listed", "dim"))
    console.print()
    if verdict == "failed":
        console.print(console.style("FAILED: the archive is damaged or inconsistent.", "red", "bold"))
    elif verdict == "incomplete":
        why = "some checks could not be performed" if report.unavailable else "the format provides no integrity check"
        console.print(console.style(f"NO FAILURES FOUND, but verification is incomplete: {why}.", "yellow", "bold"))
    elif report.level == "content-checksums":
        console.print(console.style("PASSED: content checksums matched for every readable entry.", "green", "bold"))
    else:
        console.print(console.style("PASSED (structure and readability only).", "green", "bold"))
        console.print(console.style("  This format stores no content checksums, so a passing result cannot prove the data is unaltered.", "dim"))


# -- duplicates --------------------------------------------------------------------------


def render_duplicates(console: Console, report: "DuplicateReport") -> None:  # noqa: F821
    if console.quiet and not report.groups and not report.repeated_paths:
        return
    console.print(f"{console.style('Archive', 'bold')}  {esc(report.archive)}")
    console.print(
        f"{console.style('Examined', 'bold')}  {report.files_examined:,} files; "
        f"hashed {report.candidates_hashed:,} same-size candidates ({format_size(report.bytes_hashed)})"
    )
    console.print()
    console.print(console.style(f"Duplicate content: {len(report.groups):,} group(s), {format_size(report.wasted_bytes)} redundant", "bold"))
    if not report.groups:
        console.print("  none found")
    for group in report.groups:
        console.print(f"  {len(group.paths)} files, {format_size(group.size)} each, sha256 {group.sha256[:16]}...")
        for path in group.paths:
            console.print(f"    {esc(path)}")
    console.print()
    console.print(console.style(f"Repeated paths: {len(report.repeated_paths):,}", "bold"))
    console.print(console.style("  (the same file name stored more than once; the contents may or may not match)", "dim"))
    if not report.repeated_paths:
        console.print("  none found")
    for path, count in sorted(report.repeated_paths.items()):
        console.print(f"  {esc(path)}  x{count}")
    for path, reason in report.skipped:
        console.print(f"{console.style('skipped', 'yellow')} {esc(path)}: {esc(reason)}")
    if report.error:
        console.print(console.style(f"Incomplete: {esc(report.error)}", "red"))


# -- compare -----------------------------------------------------------------------------


def render_compare(console: Console, report: "ComparisonReport") -> None:  # noqa: F821
    from packlens.analysis.comparison import CompareMode

    console.print(f"{console.style('Comparing', 'bold')} {esc(report.old_name)} -> {esc(report.new_name)}  (by {report.mode.value})")
    console.print()
    for entry in report.added:
        console.print(f"  {console.style('+ added  ', 'green')} {esc(entry.path)}  {format_size(entry.size) if entry.type is EntryType.FILE else ''}".rstrip())
    for entry in report.removed:
        console.print(f"  {console.style('- removed', 'red')} {esc(entry.path)}  {format_size(entry.size) if entry.type is EntryType.FILE else ''}".rstrip())
    for change in report.changed:
        console.print(f"  {console.style('~ changed', 'yellow')} {esc(change.path)}  ({esc('; '.join(change.reasons))})")
    if report.metadata_changes:
        console.print()
        console.print(console.style("Metadata differences (content otherwise unchanged)", "bold"))
        for path, diff in report.metadata_changes:
            detail = ", ".join(f"{k}: {a} -> {b}" for k, (a, b) in diff.items())
            console.print(f"  {esc(path)}  {detail}")
    for path, reason in report.unverifiable:
        console.print(f"  {console.style('? unverifiable', 'yellow')} {esc(path)}: {esc(reason)}")
    console.print()
    console.print(
        f"{len(report.added):,} added, {len(report.removed):,} removed, {len(report.changed):,} changed, "
        f"{report.in_both:,} path(s) in both"
    )
    if report.mode is CompareMode.HASH:
        console.print(f"{report.identical:,} file(s) confirmed identical by SHA-256 (or both empty)")
    elif report.mode is CompareMode.SIZE:
        console.print(f"{report.identical:,} empty file(s) identical; {report.same_size_unverified:,} file(s) have the same size but their content was not compared")
        if report.same_size_unverified:
            console.print(console.style("  use --by hash to confirm whether those are really identical", "dim"))
    else:
        console.print(console.style("path mode compares names only; sizes and contents were not examined", "dim"))
    if report.repeated_paths_old or report.repeated_paths_new:
        console.print(console.style(f"note: repeated paths found (old: {report.repeated_paths_old}, new: {report.repeated_paths_new}); the last entry for each path was used", "dim"))
