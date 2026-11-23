from __future__ import annotations

import pytest

from packlens.utils.formatting import (
    escape_for_terminal,
    format_ratio,
    format_size,
    json_safe,
    parse_count_limit,
    parse_size,
    parse_size_limit,
)


@pytest.mark.parametrize(
    "value,expected",
    [(0, "0 B"), (1023, "1023 B"), (1024, "1.0 KiB"), (1536, "1.5 KiB"), (1024**3, "1.0 GiB"), (None, "unknown")],
)
def test_format_size(value, expected):
    assert format_size(value) == expected


@pytest.mark.parametrize(
    "text,expected",
    [("500", 500), ("10KB", 10_000), ("10KiB", 10_240), ("2GiB", 2 * 1024**3), ("1.5MB", 1_500_000), (" 3 mib ", 3 * 1024**2)],
)
def test_parse_size(text, expected):
    assert parse_size(text) == expected


@pytest.mark.parametrize("text", ["", "abc", "10XB", "-5", "1..2MB"])
def test_parse_size_rejects_garbage(text):
    with pytest.raises(ValueError):
        parse_size(text)


def test_zero_and_unlimited_mean_no_limit():
    assert parse_size_limit("0") is None and parse_size_limit("unlimited") is None
    assert parse_count_limit("0") is None and parse_count_limit("12") == 12
    with pytest.raises(ValueError):
        parse_count_limit("-1")


def test_ratio():
    assert format_ratio(1000, 250) == "4.00x"
    assert format_ratio(0, 10) is None and format_ratio(10, 0) is None and format_ratio(None, 5) is None


def test_escape_for_terminal():
    assert escape_for_terminal("plain ünï 日本") == "plain ünï 日本"
    assert escape_for_terminal("a\x1bb") == "a\\x1bb"
    assert escape_for_terminal("x\u202ey") == "x\\u202ey"
    assert escape_for_terminal("bad\udcff") == "bad\\udcff"


def test_json_safe():
    assert json_safe("ok") == "ok" and json_safe(None) is None
    assert json_safe("bad\udcff") == "bad\\udcff"
    json_safe("bad\udcff").encode("utf-8")
