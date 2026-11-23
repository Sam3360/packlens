"""Exception hierarchy. Every error raised deliberately by Packlens derives from PacklensError."""

from __future__ import annotations

from packlens.utils.formatting import format_size


class PacklensError(Exception):
    """Base class for expected, user-reportable failures."""

    exit_code = 1


class UnsupportedFormatError(PacklensError):
    """The input is not a recognised (or not yet supported) archive format."""


class ArchiveReadError(PacklensError):
    """The archive is corrupted, truncated or otherwise malformed."""


class UnsupportedFeatureError(PacklensError):
    """The archive uses a feature Packlens cannot process (encryption, unknown codec, ...)."""


class EntryNotFoundError(PacklensError):
    """A requested entry does not exist in the archive."""


class LimitExceededError(PacklensError):
    """A configured resource limit was reached."""

    def __init__(self, limit_name: str, limit: int, what: str, *, is_bytes: bool = False) -> None:
        self.limit_name = limit_name
        self.limit = limit
        shown = format_size(limit) if is_bytes else f"{limit:,}"
        option = "--" + limit_name.replace("_", "-")
        super().__init__(
            f"{what} exceeds the configured limit of {shown} "
            f"(raise it with {option}, or use 0 for unlimited)"
        )
