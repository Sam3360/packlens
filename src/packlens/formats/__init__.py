"""Archive format handlers."""

from __future__ import annotations

from typing import BinaryIO

from packlens.core.models import ArchiveFormat
from packlens.formats.base import ArchiveHandler
from packlens.formats.compressed import CompressedStreamHandler
from packlens.formats.tar import TarHandler
from packlens.formats.zip import ZipHandler


def create_handler(format: ArchiveFormat, fileobj: BinaryIO, name: str, **kwargs: object) -> ArchiveHandler:
    """Instantiate the handler for ``format``. This is the single place formats are registered."""
    if format is ArchiveFormat.ZIP:
        return ZipHandler(fileobj, name, **kwargs)
    if format.is_tar:
        return TarHandler(fileobj, name, format=format, **kwargs)
    if format.is_stream:
        return CompressedStreamHandler(fileobj, name, format=format, **kwargs)
    raise ValueError(f"no handler for {format}")  # pragma: no cover


__all__ = ["ArchiveHandler", "create_handler"]
