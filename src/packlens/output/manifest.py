"""Streaming JSON manifest writer. Entries are written one at a time, so memory stays flat."""

from __future__ import annotations

import textwrap
from typing import IO, Any, Callable

import packlens
from packlens.analysis.paths import ArchiveAnalyzer
from packlens.core.errors import ArchiveReadError, UnsupportedFeatureError
from packlens.core.limits import Limits
from packlens.core.models import ArchiveStats, EntryType
from packlens.formats.base import ArchiveHandler
from packlens.output.json import SCHEMA_VERSION, dumps
from packlens.utils.formatting import json_safe
from packlens.utils.hashing import hash_stream


def _block(data: Any, indent: str) -> str:
    return textwrap.indent(dumps(data, indent=2), indent)


def write_manifest(
    handler: ArchiveHandler,
    out: IO[str],
    limits: Limits,
    *,
    sha256: bool,
    on_entry: Callable[[int], None] | None = None,
) -> str | None:
    """Write a manifest to ``out``. Returns an error message if the archive was damaged mid-way.

    The document is always valid JSON: on failure it is closed with ``"complete": false``
    and an ``"error"`` field.
    """
    info = handler.info()
    stats = ArchiveStats()
    analyzer = ArchiveAnalyzer(limits)
    error: str | None = None
    out.write("{\n")
    out.write(f'  "schema_version": {SCHEMA_VERSION},\n')
    out.write(f'  "packlens_version": {dumps(packlens.__version__)},\n')
    out.write('  "command": "manifest",\n')
    archive = {
        "name": json_safe(info.name),
        "format": info.format.value,
        "compressed_size": info.compressed_size,
        "metadata": {k: json_safe(v) for k, v in info.metadata.items()},
    }
    out.write(f'  "archive": {_block(archive, "  ").lstrip()},\n')
    out.write('  "sha256_requested": ' + ("true" if sha256 else "false") + ",\n")
    out.write('  "entries": [')
    first = True

    def emit(record: dict[str, Any]) -> None:
        nonlocal first
        out.write(("\n" if first else ",\n") + _block(record, "    "))
        first = False

    try:
        if sha256:
            for entry, stream in handler.iter_data(select=lambda e: e.type is EntryType.FILE):
                stats.add(entry)
                analyzer.feed(entry)
                record = entry.to_dict()
                if stream is not None:
                    try:
                        record["sha256"], _ = hash_stream(stream)
                    except (ArchiveReadError, UnsupportedFeatureError) as exc:
                        record["sha256"] = None
                        record["sha256_error"] = json_safe(str(exc))
                emit(record)
                if on_entry:
                    on_entry(stats.entry_count)
        else:
            for entry in handler.entries():
                stats.add(entry)
                analyzer.feed(entry)
                emit(entry.to_dict())
                if on_entry:
                    on_entry(stats.entry_count)
    except ArchiveReadError as exc:
        error = str(exc)
    out.write("\n  ]" if not first else "]")
    analyzer.finish(info, stats)
    findings = [f.to_dict() for f in handler.notes() + analyzer.findings]
    summary = {
        "entries": stats.entry_count,
        "files": stats.file_count,
        "directories": stats.directory_count,
        "uncompressed_size": None if stats.size_unknown else stats.total_size,
    }
    out.write(f',\n  "summary": {_block(summary, "  ").lstrip()}')
    out.write(f',\n  "findings": {_block(findings, "  ").lstrip()}')
    out.write(f',\n  "complete": {"false" if error else "true"}')
    if error:
        out.write(f',\n  "error": {dumps(json_safe(error))}')
    out.write("\n}\n")
    return error
