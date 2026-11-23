"""Resource limits (hard stops) and warning thresholds (soft findings)."""

from __future__ import annotations

from dataclasses import dataclass

from packlens.core.errors import LimitExceededError

MiB = 1024**2
GiB = 1024**3


@dataclass(frozen=True)
class Limits:
    """Configuration for resource usage. ``None`` means unlimited."""

    # Hard limits: exceeding one aborts the operation with an error.
    max_entries: int | None = 1_000_000
    max_total_bytes: int | None = 10 * GiB  # decompressed bytes processed per command
    max_entry_size: int | None = 4 * GiB  # decompressed bytes read from a single entry
    max_nesting_depth: int = 3  # archives inside archives
    max_nested_size: int | None = 128 * MiB  # a nested archive is held in memory up to this size

    # Soft thresholds: exceeding one produces a warning finding.
    warn_entries: int = 100_000
    warn_entry_size: int = 1 * GiB
    warn_ratio: float = 100.0
    warn_path_depth: int = 32
    max_findings: int = 1000  # cap on stored findings, to bound memory on hostile input


DEFAULT_LIMITS = Limits()


class Budget:
    """Tracks decompressed bytes processed during one command, across nested archives."""

    def __init__(self, limit: int | None) -> None:
        self.limit = limit
        self.used = 0

    def consume(self, num_bytes: int) -> None:
        self.used += num_bytes
        if self.limit is not None and self.used > self.limit:
            raise LimitExceededError(
                "max_total_bytes", self.limit, "Total decompressed data processed", is_bytes=True
            )
