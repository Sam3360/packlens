"""Seeded mutation fuzzing: damaged input may fail, but only with PacklensError, never a crash."""

from __future__ import annotations

import io
import random

import pytest

from helpers import make_stream, make_tar, make_zip
from packlens.analysis.comparison import CompareMode, compare_archives
from packlens.analysis.duplicates import find_duplicates
from packlens.analysis.inspection import inspect_archive
from packlens.analysis.integrity import verify_archive
from packlens.analysis.nested_scan import scan_nested
from packlens.core.archive import open_archive_stream
from packlens.core.errors import PacklensError
from packlens.core.limits import Limits

LIMITS = Limits(max_total_bytes=64 * 1024 * 1024, max_entries=10_000)
BASE = {"a.txt": b"hello world\n" * 40, "d/": None, "d/b.bin": bytes(range(256)) * 8, "d/c.txt": b"hello world\n" * 40}


def build(tmp_path, key):
    if key == "zip":
        return make_zip(tmp_path / "f.zip", BASE).read_bytes()
    if key.startswith("tar"):
        comp = {"tar": "", "tar.gz": "gz", "tar.bz2": "bz2", "tar.xz": "xz"}[key]
        return make_tar(tmp_path / "f.tar", BASE, compression=comp).read_bytes()
    codec = {"gzip": "gzip", "bzip2": "bzip2", "xz": "xz"}[key]
    return make_stream(tmp_path / "f.bin", bytes(range(256)) * 20, codec).read_bytes()


def mutate(data: bytes, rng: random.Random) -> bytes:
    kind = rng.choice(["flip", "truncate", "zero", "insert", "delete"])
    buf = bytearray(data)
    if kind == "flip":
        for _ in range(rng.randint(1, 4)):
            buf[rng.randrange(len(buf))] ^= rng.randint(1, 255)
    elif kind == "truncate":
        del buf[rng.randrange(1, len(buf)) :]
    elif kind == "zero":
        start = rng.randrange(len(buf))
        buf[start : start + rng.randint(1, 64)] = b"\0" * rng.randint(1, 64)
    elif kind == "insert":
        pos = rng.randrange(len(buf))
        buf[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 32)))
    else:
        start = rng.randrange(len(buf))
        del buf[start : start + rng.randint(1, 32)]
    return bytes(buf)


def exercise(data: bytes) -> None:
    """Run every analysis; a PacklensError at any point is an acceptable outcome."""
    try:
        with open_archive_stream(io.BytesIO(data), "fuzz.bin", LIMITS) as handler:
            inspect_archive(handler, LIMITS)
    except PacklensError:
        pass
    for step in ("verify", "dupes", "nested"):
        try:
            with open_archive_stream(io.BytesIO(data), "fuzz.bin", LIMITS) as handler:
                if step == "verify":
                    verify_archive(handler)
                elif step == "dupes":
                    find_duplicates(handler)
                else:
                    scan_nested(handler, LIMITS, handler.budget)
        except PacklensError:
            pass


@pytest.mark.parametrize("key", ["zip", "tar", "tar.gz", "tar.bz2", "tar.xz", "gzip", "bzip2", "xz"])
def test_mutated_archives_never_crash(tmp_path, key):
    original = build(tmp_path, key)
    rng = random.Random(f"packlens-{key}")
    for _ in range(80):
        exercise(mutate(original, rng))


def test_random_garbage_never_crashes():
    rng = random.Random(1234)
    for size in (1, 7, 100, 513, 4096):
        for _ in range(10):
            exercise(bytes(rng.randrange(256) for _ in range(size)))


def test_compare_survives_damaged_input(tmp_path):
    good = build(tmp_path, "tar.gz")
    rng = random.Random(99)
    for _ in range(30):
        bad = mutate(good, rng)
        try:
            with open_archive_stream(io.BytesIO(good), "g", LIMITS) as a, open_archive_stream(io.BytesIO(bad), "b", LIMITS) as b:
                compare_archives(a, b, CompareMode.HASH)
        except PacklensError:
            pass
