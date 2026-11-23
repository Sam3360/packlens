"""Streaming hashing helpers. Nothing here ever reads a whole entry into memory."""

from __future__ import annotations

import hashlib
from typing import Callable, Protocol

CHUNK_SIZE = 1024 * 1024


class Readable(Protocol):
    def read(self, size: int = -1) -> bytes: ...


def hash_stream(
    stream: Readable,
    algorithm: str = "sha256",
    *,
    on_chunk: Callable[[int], None] | None = None,
) -> tuple[str, int]:
    """Hash ``stream`` in chunks. Returns ``(hex digest, bytes read)``."""
    digest = hashlib.new(algorithm)
    total = 0
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
        if on_chunk is not None:
            on_chunk(len(chunk))
    return digest.hexdigest(), total
