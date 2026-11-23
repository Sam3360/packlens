from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from helpers import make_stream, make_tar, make_zip  # noqa: E402

SAMPLE = {
    "README.md": b"# Sample\n",
    "src/": None,
    "src/main.py": b"print('hello')\n" * 20,
    "src/util.py": b"def f():\n    return 1\n" * 10,
    "docs/": None,
    "docs/guide.txt": b"guide text\n" * 50,
}


@pytest.fixture
def sample() -> dict:
    return dict(SAMPLE)


@pytest.fixture
def archives(tmp_path: Path) -> dict:
    """One valid archive of every supported format, all holding SAMPLE."""
    paths = {
        "zip": make_zip(tmp_path / "sample.zip", SAMPLE),
        "tar": make_tar(tmp_path / "sample.tar", SAMPLE),
        "tar.gz": make_tar(tmp_path / "sample.tar.gz", SAMPLE, compression="gz"),
        "tar.bz2": make_tar(tmp_path / "sample.tar.bz2", SAMPLE, compression="bz2"),
        "tar.xz": make_tar(tmp_path / "sample.tar.xz", SAMPLE, compression="xz"),
    }
    payload = b"stream payload\n" * 100
    paths["gzip"] = make_stream(tmp_path / "data.txt.gz", payload, "gzip", name="data.txt")
    paths["bzip2"] = make_stream(tmp_path / "data.txt.bz2", payload, "bzip2")
    paths["xz"] = make_stream(tmp_path / "data.txt.xz", payload, "xz")
    return paths
