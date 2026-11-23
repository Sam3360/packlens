"""Formatting and parsing helpers shared by the CLI and the output layers."""

from __future__ import annotations

import re
import unicodedata

_UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")

_SIZE_FACTORS = {
    "": 1,
    "b": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "tb": 1000**4,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "tib": 1024**4,
}
_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([A-Za-z]*)\s*$")

# Bidirectional controls can make a filename render differently from its real content.
BIDI_CONTROLS = frozenset(
    chr(c) for c in (0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069)
)


def format_size(num_bytes: int | None) -> str:
    """Format a byte count with binary units, e.g. ``1.5 MiB``."""
    if num_bytes is None:
        return "unknown"
    value = float(num_bytes)
    for unit in _UNITS:
        if abs(value) < 1024 or unit == _UNITS[-1]:
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")  # pragma: no cover


def format_ratio(uncompressed: int | None, compressed: int | None) -> str | None:
    """Return e.g. ``4.20x`` or ``None`` when a ratio is not meaningful."""
    if not uncompressed or not compressed:
        return None
    return f"{uncompressed / compressed:.2f}x"


def parse_size(text: str) -> int:
    """Parse ``500``, ``10MB`` or ``2GiB``. KB/MB/GB are decimal, KiB/MiB/GiB are binary."""
    match = _SIZE_RE.match(text)
    if not match:
        raise ValueError(f"invalid size: {text!r}")
    number, unit = match.group(1), match.group(2).lower()
    if unit not in _SIZE_FACTORS:
        raise ValueError(f"unknown size unit {unit!r} in {text!r} (use B, KB, MB, GB, KiB, MiB, GiB)")
    return int(float(number) * _SIZE_FACTORS[unit])


def parse_size_limit(text: str) -> int | None:
    """Like :func:`parse_size`, but ``0`` / ``unlimited`` means no limit (``None``)."""
    if text.strip().lower() in {"unlimited", "none"}:
        return None
    value = parse_size(text)
    return value or None


def parse_count_limit(text: str) -> int | None:
    """Parse an integer count where ``0`` / ``unlimited`` means no limit (``None``)."""
    if text.strip().lower() in {"unlimited", "none"}:
        return None
    value = int(text)
    if value < 0:
        raise ValueError("must not be negative")
    return value or None


def escape_for_terminal(text: str) -> str:
    """Make untrusted text safe to print: escape control and bidi characters and lone surrogates."""
    out: list[str] = []
    for ch in text:
        if ch in BIDI_CONTROLS or unicodedata.category(ch) in ("Cc", "Cs"):
            code = ord(ch)
            out.append(f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


def json_safe(text: str | None) -> str | None:
    """Replace lone surrogates (undecodable bytes in names) with visible escapes."""
    if text is None:
        return None
    return text.encode("utf-8", "backslashreplace").decode("utf-8")
