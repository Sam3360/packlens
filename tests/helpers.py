"""Programmatic fixture builders. No binary fixtures are stored in the repository."""

from __future__ import annotations

import bz2
import contextlib
import gzip
import io
import lzma
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Union


@dataclass
class Symlink:
    target: str


@dataclass
class Hardlink:
    target: str


@dataclass
class Special:
    kind: bytes  # e.g. tarfile.FIFOTYPE


Value = Union[bytes, None, Symlink, Hardlink, Special]
Entries = Union[Mapping[str, Value], Iterable[tuple[str, Value]]]

ZIP_DATE = (2024, 1, 2, 3, 4, 6)
TAR_MTIME = 1_700_000_000


def _items(entries: Entries) -> list[tuple[str, Value]]:
    return list(entries.items()) if hasattr(entries, "items") else list(entries)  # type: ignore[union-attr]


def make_zip(
    path: Path,
    entries: Entries,
    *,
    compression: int = zipfile.ZIP_DEFLATED,
    comment: bytes = b"",
) -> Path:
    with zipfile.ZipFile(path, "w", compression) as zf:
        zf.comment = comment
        for name, value in _items(entries):
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE)
            # ZipInfo rewrites os.sep to "/" in .filename, and .filename is what gets written.
            # On Windows that silently turns "a\\b" into "a/b", so store the name verbatim.
            info.filename = name
            info.compress_type = compression
            info.create_system = 3
            if isinstance(value, Symlink):
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                zf.writestr(info, value.target)
            elif value is None or name.endswith("/"):
                info.external_attr = (stat.S_IFDIR | 0o755) << 16
                zf.writestr(info, b"")
            else:
                assert isinstance(value, bytes)
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                zf.writestr(info, value)
    return path


def make_tar(path: Path, entries: Entries, *, compression: str = "") -> Path:
    mode = f"w:{compression}" if compression else "w"
    with tarfile.open(path, mode, format=tarfile.PAX_FORMAT) as tf:  # type: ignore[call-overload]
        for name, value in _items(entries):
            info = tarfile.TarInfo(name)
            info.mtime = TAR_MTIME
            info.mode = 0o644
            if isinstance(value, Symlink):
                info.type, info.linkname, info.mode = tarfile.SYMTYPE, value.target, 0o777
                tf.addfile(info)
            elif isinstance(value, Hardlink):
                info.type, info.linkname = tarfile.LNKTYPE, value.target
                tf.addfile(info)
            elif isinstance(value, Special):
                info.type = value.kind
                tf.addfile(info)
            elif value is None or name.endswith("/"):
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tf.addfile(info)
            else:
                info.size = len(value)
                tf.addfile(info, io.BytesIO(value))
    return path


def make_stream(path: Path, data: bytes, codec: str, *, name: str = "") -> Path:
    with open(path, "wb") as raw:
        if codec == "gzip":
            with gzip.GzipFile(filename=name, fileobj=raw, mode="wb", mtime=TAR_MTIME) as stream:
                stream.write(data)
        elif codec == "bzip2":
            with bz2.BZ2File(raw, "wb") as stream:  # type: ignore[assignment]
                stream.write(data)
        elif codec == "xz":
            with lzma.LZMAFile(raw, "wb") as stream:  # type: ignore[assignment]
                stream.write(data)
        else:
            raise ValueError(codec)
    return path


def truncate(path: Path, keep: int) -> Path:
    data = path.read_bytes()
    path.write_bytes(data[:keep])
    return path


def flip_byte(path: Path, offset: int) -> Path:
    data = bytearray(path.read_bytes())
    data[offset] ^= 0xFF
    path.write_bytes(bytes(data))
    return path


def run_cli(*args: str) -> tuple[int, str, str]:
    """Run the CLI in-process. Returns ``(exit code, stdout, stderr)``."""
    from packlens import cli

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(args))
    return code, out.getvalue(), err.getvalue()
