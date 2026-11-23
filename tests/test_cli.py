from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile

import pytest

from helpers import Symlink, flip_byte, make_stream, make_tar, make_zip, run_cli, truncate

ALL_COMMANDS = ["inspect", "tree", "verify", "duplicates", "manifest"]


def test_version_and_help():
    code, out, _ = run_cli("--version")
    assert code == 0 and out.startswith("packlens ")
    code, out, _ = run_cli("--help")
    assert code == 0 and "inspect" in out and "Exit codes" in out
    for cmd in ALL_COMMANDS + ["compare"]:
        assert run_cli(cmd, "--help")[0] == 0


def test_usage_errors_exit_2():
    assert run_cli()[0] == 2
    assert run_cli("frobnicate")[0] == 2
    assert run_cli("inspect")[0] == 2
    assert run_cli("tree", "x.zip", "--depth", "abc")[0] == 2
    assert run_cli("inspect", "x.zip", "--max-entries", "lots")[0] == 2


def test_global_options_work_before_and_after_the_command(archives):
    for args in (["--quiet", "inspect", str(archives["zip"])], ["inspect", str(archives["zip"]), "--quiet"]):
        code, out, _ = run_cli(*args)
        assert code == 0 and out.count("\n") == 1  # quiet inspect is a single line


@pytest.mark.parametrize("cmd", ALL_COMMANDS)
def test_missing_file_is_a_clean_failure(tmp_path, cmd):
    code, out, err = run_cli(cmd, str(tmp_path / "nope.zip"))
    assert code == 1 and "no such file" in err and "Traceback" not in err


def test_directory_and_non_archive_inputs(tmp_path):
    (tmp_path / "plain.txt").write_text("hello")
    assert run_cli("inspect", str(tmp_path))[0] == 1
    code, _, err = run_cli("inspect", str(tmp_path / "plain.txt"))
    assert code == 1 and "not a recognised archive" in err


@pytest.mark.skipif(sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0), reason="needs a non-root POSIX user")
def test_permission_denied(tmp_path, sample):
    path = make_zip(tmp_path / "locked.zip", sample)
    path.chmod(0o000)
    try:
        code, _, err = run_cli("inspect", str(path))
    finally:
        path.chmod(0o600)
    assert code == 1 and "permission denied" in err


@pytest.mark.parametrize("key", ["zip", "tar", "tar.gz", "tar.bz2", "tar.xz", "gzip", "bzip2", "xz"])
def test_every_command_works_on_every_format(archives, key):
    path = str(archives[key])
    for cmd in ("inspect", "tree", "verify", "duplicates"):
        code, out, err = run_cli(cmd, path)
        assert code == 0, (cmd, key, err)
    assert run_cli("compare", path, path, "--by", "hash")[0] == 0


@pytest.mark.parametrize("cmd", ["inspect", "tree", "verify", "duplicates"])
def test_json_output_is_valid_and_versioned(archives, cmd):
    code, out, _ = run_cli(cmd, str(archives["tar.gz"]), "--format", "json")
    data = json.loads(out)
    assert code == 0 and data["command"] == cmd and data["schema_version"] == 1


def test_compare_json(tmp_path, sample):
    a = make_zip(tmp_path / "a.zip", sample)
    b = make_zip(tmp_path / "b.zip", {**sample, "new.txt": b"n"})
    code, out, _ = run_cli("compare", str(a), str(b), "--format", "json")
    data = json.loads(out)
    assert code == 0 and data["summary"]["added"] == 1


def test_inspect_json_shape(archives):
    data = json.loads(run_cli("inspect", str(archives["zip"]), "--format", "json")[1])
    assert data["summary"]["files"] == 4 and data["summary"]["directories"] == 2
    assert data["archive"]["format"] == "zip" and data["integrity"]["available"] is True


# -- exit codes ---------------------------------------------------------------------------


def test_verify_failure_exits_3(tmp_path):
    path = make_zip(tmp_path / "a.zip", {"f": b"hello world" * 20}, compression=0)
    flip_byte(path, path.read_bytes().index(b"hello") + 2)
    code, out, _ = run_cli("verify", str(path))
    assert code == 3 and "FAILED" in out
    assert run_cli("verify", str(path), "--format", "json")[0] == 3


def test_verify_incomplete_is_not_reported_as_passed(tmp_path):
    import lzma

    path = tmp_path / "nocheck.xz"
    path.write_bytes(lzma.compress(b"x" * 500, check=lzma.CHECK_NONE))
    code, out, _ = run_cli("verify", str(path))
    assert code == 0 and "incomplete" in out and "PASSED" not in out


def test_verify_tar_never_claims_checksums(archives):
    _, out, _ = run_cli("verify", str(archives["tar"]))
    assert "structure and readability only" in out and "checksums matched" not in out
    _, out, _ = run_cli("verify", str(archives["zip"]))
    assert "content checksums matched" in out


def test_strict_exit_code_4(tmp_path):
    clean = make_zip(tmp_path / "clean.zip", {"a.txt": b"x"})
    dirty = make_zip(tmp_path / "dirty.zip", {"../evil": b"x"})
    assert run_cli("inspect", str(dirty))[0] == 0  # warnings alone do not fail
    assert run_cli("inspect", str(dirty), "--strict")[0] == 4
    assert run_cli("inspect", str(clean), "--strict")[0] == 0


def test_notes_alone_do_not_trigger_strict(tmp_path):
    path = make_zip(tmp_path / "a.zip", {"inner.zip": b"x" * 10})
    assert run_cli("inspect", str(path), "--strict")[0] == 0


def test_damaged_archive_inspect_reports_partial_and_fails(tmp_path):
    path = make_tar(tmp_path / "a.tar", {"a.txt": b"x" * 5000, "b.txt": b"y"})
    truncate(path, 2000)
    code, out, err = run_cli("inspect", str(path))
    assert code == 1 and "incomplete" in out and "Traceback" not in err


def test_limits_cause_clean_failure(tmp_path):
    path = make_zip(tmp_path / "a.zip", {f"f{i}": b"" for i in range(20)})
    code, _, err = run_cli("inspect", str(path), "--max-entries", "5")
    assert code == 1 and "--max-entries" in err
    assert run_cli("inspect", str(path), "--max-entries", "0")[0] == 0  # 0 = unlimited


def test_size_limit_syntax(tmp_path):
    path = make_stream(tmp_path / "a.gz", b"x" * 100_000, "gzip")
    code, _, err = run_cli("verify", str(path), "--max-entry-size", "10KB")
    assert code == 1 and "--max-entry-size" in err


def test_nested_flag_and_into(tmp_path):
    inner = make_tar(tmp_path / "i.tar.gz", {"../x": b"1"}, compression="gz").read_bytes()
    outer = make_zip(tmp_path / "o.zip", {"i.tar.gz": inner})
    code, out, _ = run_cli("inspect", str(outer), "--nested")
    assert code == 0 and "Nested archives" in out and "path-traversal" in out
    data = json.loads(run_cli("inspect", str(outer), "--nested", "--format", "json")[1])
    assert data["nested"][0]["status"] == "inspected"
    code, out, _ = run_cli("tree", str(outer), "--into", "i.tar.gz")
    assert code == 0 and "x" in out
    assert run_cli("verify", str(outer), "--into", "missing.zip")[0] == 1


# -- tree ---------------------------------------------------------------------------------


def test_tree_text(archives):
    code, out, _ = run_cli("tree", str(archives["zip"]), "--depth", "1", "--ascii")
    assert code == 0 and "src/" in out and "main.py" not in out and "hidden by --depth" in out
    code, out, _ = run_cli("tree", str(archives["zip"]), "--depth", "0")
    assert code == 1


def test_tree_json_is_flat_and_safe_for_deep_paths(tmp_path):
    deep = "/".join(f"d{i}" for i in range(2500)) + "/leaf"
    path = make_tar(tmp_path / "deep.tar", {deep: b"x"})
    code, out, _ = run_cli("tree", str(path), "--format", "json")
    assert code == 0 and len(json.loads(out)["nodes"]) == 2501  # nested JSON would overflow the stack


# -- hostile names ------------------------------------------------------------------------


def test_terminal_output_escapes_control_sequences(tmp_path):
    path = make_tar(tmp_path / "evil.tar", {"\x1b[31mred\x1b[0m.txt": b"x", "a\u202etxt.exe": b"y"})
    for cmd in ("inspect", "tree", "duplicates"):
        _, out, _ = run_cli(cmd, str(path), "--no-color")
        assert "\x1b" not in out and "\u202e" not in out, cmd
    assert "\\x1b[31m" in run_cli("tree", str(path), "--no-color")[1]


def test_non_utf8_names_still_produce_valid_json(tmp_path):
    path = tmp_path / "latin1.tar"
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT, encoding="latin-1") as tf:
        info = tarfile.TarInfo("caf\u00e9.txt")
        info.size = 1
        tf.addfile(info, __import__("io").BytesIO(b"x"))
    for cmd in ("inspect", "tree", "manifest"):
        code, out, _ = run_cli(cmd, str(path), "--format", "json")
        assert code == 0
        json.loads(out)
        out.encode("utf-8")  # must be encodable
    assert "invalid-encoding" in run_cli("inspect", str(path), "--format", "json")[1]


# -- manifest -----------------------------------------------------------------------------


def test_manifest_contents(tmp_path, sample):
    import hashlib

    path = make_zip(tmp_path / "a.zip", sample)
    code, out, _ = run_cli("manifest", str(path), "--sha256")
    data = json.loads(out)
    assert code == 0 and data["complete"] is True and data["sha256_requested"] is True
    by_path = {e["path"]: e for e in data["entries"]}
    assert by_path["src/main.py"]["sha256"] == hashlib.sha256(sample["src/main.py"]).hexdigest()
    assert by_path["src/main.py"]["crc32"] and by_path["src/main.py"]["compression"] == "deflate"
    assert by_path["src/"]["type"] == "directory" and "sha256" not in by_path["src/"]
    assert data["summary"]["files"] == 4


def test_manifest_without_hashes_does_not_read_data(tmp_path, sample):
    data = json.loads(run_cli("manifest", str(make_zip(tmp_path / "a.zip", sample)))[1])
    assert all("sha256" not in e for e in data["entries"])


def test_manifest_output_file_and_overwrite_protection(tmp_path, sample):
    path = make_zip(tmp_path / "a.zip", sample)
    out_file = tmp_path / "m.json"
    code, out, _ = run_cli("manifest", str(path), "--output", str(out_file))
    assert code == 0 and out == "" and json.loads(out_file.read_text())["complete"] is True
    before = path.read_bytes()
    code, _, err = run_cli("manifest", str(path), "--output", str(path))
    assert code == 1 and "refusing" in err and path.read_bytes() == before
    assert not list(tmp_path.glob(".packlens-*"))  # no temp files left behind


def test_manifest_of_damaged_archive_is_valid_json_marked_incomplete(tmp_path):
    path = make_tar(tmp_path / "a.tar", {"a": b"x" * 4000, "b": b"y"})
    truncate(path, 1500)
    code, out, err = run_cli("manifest", str(path))
    data = json.loads(out)
    assert code == 1 and data["complete"] is False and data["error"]
    out_file = tmp_path / "m.json"
    assert run_cli("manifest", str(path), "-o", str(out_file))[0] == 1
    assert not out_file.exists()  # a partial manifest is never written to disk


def test_manifest_sha256_error_is_per_entry_for_zip(tmp_path):
    import zipfile

    path = make_zip(tmp_path / "a.zip", {"good": b"g" * 50, "bad": b"hello world" * 10}, compression=zipfile.ZIP_STORED)
    flip_byte(path, path.read_bytes().index(b"hello world") + 1)
    data = json.loads(run_cli("manifest", str(path), "--sha256")[1])
    bad = next(e for e in data["entries"] if e["path"] == "bad")
    assert bad["sha256"] is None and bad["sha256_error"]
    assert next(e for e in data["entries"] if e["path"] == "good")["sha256"]


# -- process level ------------------------------------------------------------------------


def test_module_invocation_and_exit_code(tmp_path, sample):
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, [str(__import__("pathlib").Path(__file__).parents[1] / "src"), os.environ.get("PYTHONPATH", "")]))}
    path = make_zip(tmp_path / "a.zip", sample)
    ok = subprocess.run([sys.executable, "-m", "packlens", "inspect", str(path)], capture_output=True, text=True, env=env)
    assert ok.returncode == 0 and "ZIP" in ok.stdout
    missing = subprocess.run([sys.executable, "-m", "packlens", "inspect", str(tmp_path / "x")], capture_output=True, text=True, env=env)
    assert missing.returncode == 1
    usage = subprocess.run([sys.executable, "-m", "packlens"], capture_output=True, text=True, env=env)
    assert usage.returncode == 2


def test_quiet_verify_is_silent_on_success_and_terse_on_failure(tmp_path, sample):
    good = make_zip(tmp_path / "good.zip", sample)
    assert run_cli("--quiet", "verify", str(good)) == (0, "", "")
    bad = make_zip(tmp_path / "bad.zip", {"f": b"hello world" * 20}, compression=0)
    flip_byte(bad, bad.read_bytes().index(b"hello") + 2)
    code, out, _ = run_cli("--quiet", "verify", str(bad))
    assert code == 3 and "FAILED" in out and "f" in out


def test_zip_with_prefix_can_be_fully_processed(tmp_path, sample):
    plain = make_zip(tmp_path / "plain.zip", sample)
    prefixed = tmp_path / "self-extracting.exe"
    prefixed.write_bytes(b"MZ" + b"\x00" * 300 + plain.read_bytes())
    assert run_cli("verify", str(prefixed))[0] == 0
    assert "main.py" in run_cli("tree", str(prefixed))[1]
