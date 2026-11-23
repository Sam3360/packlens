"""JSON serialisation. Output is always valid JSON, even for hostile file names."""

from __future__ import annotations

import json
from typing import Any

import packlens

SCHEMA_VERSION = 1


def envelope(command: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Wrap a command's result with schema and tool version for stable machine consumption."""
    return {"schema_version": SCHEMA_VERSION, "packlens_version": packlens.__version__, "command": command, **payload}


def dumps(data: Any, *, indent: int | None = 2) -> str:
    text = json.dumps(data, indent=indent, ensure_ascii=False)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        # Lone surrogates from undecodable names: fall back to escapes so output stays valid.
        text = json.dumps(data, indent=indent, ensure_ascii=True)
    return text
