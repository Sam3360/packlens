"""Opening archives: detection, handler construction and nested (``--into``) resolution."""

from __future__ import annotations

import io
import os
from typing import BinaryIO, Sequence

from packlens.core.detection import detect_format, identify_unsupported
from packlens.core.errors import EntryNotFoundError, PacklensError, UnsupportedFormatError
from packlens.core.limits import DEFAULT_LIMITS, Budget, Limits
from packlens.core.models import ArchiveEntry, EntryType
from packlens.formats import create_handler
from packlens.formats.base import ArchiveHandler

SUPPORTED_SUMMARY = "ZIP, TAR, TAR.GZ, TAR.BZ2, TAR.XZ, GZIP, BZIP2, XZ"


def open_archive_stream(
    fileobj: BinaryIO,
    name: str,
    limits: Limits = DEFAULT_LIMITS,
    budget: Budget | None = None,
    *,
    owns_file: bool = False,
    on_close: tuple = (),
) -> ArchiveHandler:
    """Detect the format of ``fileobj`` and return the matching handler.

    On failure the file object is closed when ``owns_file`` is true.
    """
    try:
        fmt = detect_format(fileobj, name)
        if fmt is None:
            fileobj.seek(0)
            head = fileobj.read(16)
            fileobj.seek(0)
            if not head:
                raise UnsupportedFormatError(f"{name}: file is empty")
            known = identify_unsupported(head)
            if known:
                raise UnsupportedFormatError(
                    f"{name}: {known} archives are not supported yet (supported: {SUPPORTED_SUMMARY})"
                )
            raise UnsupportedFormatError(
                f"{name}: not a recognised archive (supported: {SUPPORTED_SUMMARY})"
            )
        return create_handler(
            fmt, fileobj, name, limits=limits, budget=budget, owns_file=owns_file, on_close=on_close
        )
    except BaseException:
        if owns_file:
            fileobj.close()
        raise


def _find_entry(handler: ArchiveHandler, member: str) -> ArchiveEntry:
    wanted = member[2:] if member.startswith("./") else member
    match: ArchiveEntry | None = None
    for entry in handler.entries():
        candidate = entry.path[2:] if entry.path.startswith("./") else entry.path
        if candidate == wanted and entry.type is EntryType.FILE:
            match = entry  # when a path repeats, the last one wins, as it would on extraction
    if match is None:
        raise EntryNotFoundError(f"{handler.name}: no file entry named {member!r}")
    return match


def open_archive(
    path: str | os.PathLike[str],
    limits: Limits = DEFAULT_LIMITS,
    *,
    budget: Budget | None = None,
    into: Sequence[str] = (),
) -> ArchiveHandler:
    """Open an archive for reading. Use the result as a context manager.

    ``into`` names archives nested inside the archive, outermost first. Nested archives are
    held in memory (up to ``limits.max_nested_size``) and never written to disk.
    """
    path_str = os.fspath(path)
    if os.path.isdir(path_str):
        raise PacklensError(f"{path_str}: is a directory, not an archive")
    budget = budget if budget is not None else Budget(limits.max_total_bytes)
    handler = open_archive_stream(
        open(path_str, "rb"), path_str, limits, budget, owns_file=True
    )
    try:
        for member in into:
            entry = _find_entry(handler, member)
            data = handler.read_entry_bytes(entry, limits.max_nested_size)
            handler = open_archive_stream(
                io.BytesIO(data),
                f"{handler.name}!{member}",
                limits,
                budget,
                on_close=(handler.close,),
            )
    except BaseException:
        handler.close()
        raise
    return handler
