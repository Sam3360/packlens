"""Command-line interface. Exit codes are documented in the README and kept stable."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import os
import sys
import tempfile
from typing import Callable, Sequence

import packlens
from packlens.analysis.comparison import CompareMode, compare_archives
from packlens.analysis.duplicates import find_duplicates
from packlens.analysis.inspection import inspect_archive
from packlens.analysis.integrity import verify_archive
from packlens.analysis.nested_scan import scan_nested
from packlens.analysis.tree import build_tree, iter_tree
from packlens.core.archive import open_archive
from packlens.core.errors import ArchiveReadError, PacklensError
from packlens.core.limits import DEFAULT_LIMITS, Budget, Limits
from packlens.output import json as jsonout
from packlens.output.manifest import write_manifest
from packlens.output.terminal import (
    Console,
    Progress,
    render_compare,
    render_duplicates,
    render_inspect,
    render_tree_line,
    render_verify,
)
from packlens.utils.formatting import escape_for_terminal as esc
from packlens.utils.formatting import format_size, json_safe, parse_count_limit, parse_size_limit

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_VERIFY_FAILED = 3
EXIT_SECURITY = 4

_LIMIT_OPTIONS: tuple[tuple[str, str, Callable[[str], object], str], ...] = (
    ("max_entries", "--max-entries", parse_count_limit, "maximum number of entries (0 = unlimited)"),
    ("max_total_bytes", "--max-total-bytes", parse_size_limit, "maximum decompressed bytes processed, e.g. 2GiB (0 = unlimited)"),
    ("max_entry_size", "--max-entry-size", parse_size_limit, "maximum decompressed bytes read from one entry (0 = unlimited)"),
    ("max_nesting_depth", "--max-nesting-depth", int, "how many levels of nested archives to inspect"),
    ("max_nested_size", "--max-nested-size", parse_size_limit, "largest nested archive held in memory (0 = unlimited)"),
)


def _arg_type(parser_fn: Callable[[str], object]) -> Callable[[str], object]:
    def convert(text: str) -> object:
        try:
            return parser_fn(text)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(str(exc)) from exc

    convert.__name__ = getattr(parser_fn, "__name__", "value")
    return convert


def _global_parent() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    group = parent.add_argument_group("global options")
    group.add_argument("-q", "--quiet", action="store_true", default=argparse.SUPPRESS, help="suppress progress and informational output")
    group.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS, help="show more detail")
    group.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS, help="disable coloured output")
    return parent


def _archive_parent(*, nested_flag: bool = False) -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--into", action="append", default=[], metavar="ENTRY", help="open an archive nested inside the archive (repeatable, outermost first)")
    group = parent.add_argument_group("resource limits")
    for dest, flag, parser_fn, help_text in _LIMIT_OPTIONS:
        group.add_argument(flag, dest=dest, type=_arg_type(parser_fn), default=argparse.SUPPRESS, metavar="N", help=help_text)
    return parent


def limits_from_args(args: argparse.Namespace) -> Limits:
    overrides = {dest: getattr(args, dest) for dest, *_ in _LIMIT_OPTIONS if hasattr(args, dest)}
    if overrides.get("max_nesting_depth") is None and "max_nesting_depth" in overrides:
        overrides["max_nesting_depth"] = 0
    return dataclasses.replace(DEFAULT_LIMITS, **overrides)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packlens",
        description="Inspect archives. Understand contents. Nothing is ever extracted or modified.",
        epilog="Exit codes: 0 ok, 1 failure, 2 usage error, 3 verification failed, 4 security warnings (with --strict).",
    )
    parser.add_argument("--version", action="version", version=f"packlens {packlens.__version__}")
    glob = parser.add_argument_group("global options")
    glob.add_argument("-q", "--quiet", action="store_true", help="suppress progress and informational output")
    glob.add_argument("-v", "--verbose", action="store_true", help="show more detail")
    glob.add_argument("--no-color", action="store_true", help="disable coloured output")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True
    g, a = _global_parent(), _archive_parent()

    p = sub.add_parser("inspect", parents=[g, a], help="summarise an archive and list findings")
    p.add_argument("archive")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--strict", action="store_true", help="exit with code 4 if any warning-level finding is reported")
    p.add_argument("--nested", action="store_true", help="also inspect archives found inside the archive (in memory, within limits)")

    p = sub.add_parser("tree", parents=[g, a], help="show archive contents as a directory tree")
    p.add_argument("archive")
    p.add_argument("--depth", type=int, metavar="N", help="show at most N levels")
    p.add_argument("--ascii", action="store_true", help="use plain ASCII line drawing")
    p.add_argument("--format", choices=["text", "json"], default="text")

    p = sub.add_parser("manifest", parents=[g, a], help="write a JSON manifest of all entries")
    p.add_argument("archive")
    p.add_argument("--format", choices=["json"], default="json")
    p.add_argument("-o", "--output", metavar="FILE", help="write to FILE instead of standard output")
    p.add_argument("--sha256", action="store_true", help="include a SHA-256 hash of every file's content (reads all data)")

    _register_analysis_commands(sub, g, a)
    return parser


def _register_analysis_commands(sub: "argparse._SubParsersAction[argparse.ArgumentParser]", g: argparse.ArgumentParser, a: argparse.ArgumentParser) -> None:
    p = sub.add_parser("verify", parents=[g, a], help="check archive integrity by reading all data")
    p.add_argument("archive")
    p.add_argument("--format", choices=["text", "json"], default="text")

    p = sub.add_parser("duplicates", parents=[g, a], help="find identical files inside an archive")
    p.add_argument("archive")
    p.add_argument("--include-empty", action="store_true", help="also report groups of empty files")
    p.add_argument("--format", choices=["text", "json"], default="text")

    p = sub.add_parser("compare", parents=[g, a], help="compare two archives without extracting them")
    p.add_argument("old")
    p.add_argument("new")
    p.add_argument("--by", choices=["path", "size", "hash"], default="size", help="path: names only; size: names and sizes (default); hash: SHA-256 of content")
    p.add_argument("--metadata", action="store_true", help="also report mode and modification-time differences")
    p.add_argument("--format", choices=["text", "json"], default="text")


# -- commands ----------------------------------------------------------------------------


def cmd_inspect(args: argparse.Namespace, console: Console) -> int:
    limits = limits_from_args(args)
    progress = Progress(console, "Reading")
    with open_archive(args.archive, limits, into=args.into) as handler:
        try:
            report = inspect_archive(handler, limits, on_entry=lambda n: progress.update(n))
            if args.nested and not report.error:
                report.nested = scan_nested(handler, limits, handler.budget)
        finally:
            progress.finish()
    if args.format == "json":
        console.print(jsonout.dumps(jsonout.envelope("inspect", report.to_dict())))
    else:
        render_inspect(console, report, args.archive)
    if report.error:
        console.error(report.error)
        return EXIT_FAILURE
    if args.strict and report.warning_count:
        return EXIT_SECURITY
    return EXIT_OK


def cmd_tree(args: argparse.Namespace, console: Console) -> int:
    if args.depth is not None and args.depth < 1:
        raise PacklensError("--depth must be at least 1")
    limits = limits_from_args(args)
    ascii_only = args.ascii or not console.supports("├── └── │")
    progress = Progress(console, "Reading")
    error: str | None = None
    with open_archive(args.archive, limits, into=args.into) as handler:
        info = handler.info()

        def entries():
            nonlocal error
            count = 0
            try:
                for entry in handler.entries():
                    count += 1
                    progress.update(count)
                    yield entry
            except ArchiveReadError as exc:
                error = str(exc)

        try:
            root = build_tree(entries())
        finally:
            progress.finish()
    lines = iter_tree(root, max_depth=args.depth, ascii_only=ascii_only)
    if args.format == "json":
        nodes = []
        for line in lines:
            entry = line.node.entry
            nodes.append(
                {
                    "path": jsonout_safe(line.path),
                    "depth": line.depth,
                    "type": "directory" if line.node.is_dir else (entry.type.value if entry else "file"),
                    "size": line.node.total_size if line.node.is_dir else (entry.size if entry else None),
                    "hidden_descendants": line.hidden,
                    "link_target": jsonout_safe(entry.link_target) if entry else None,
                }
            )
        payload = {"archive": jsonout_safe(info.name), "format": info.format.value, "nodes": nodes, "error": jsonout_safe(error)}
        console.print(jsonout.dumps(jsonout.envelope("tree", payload)))
    else:
        console.print(console.style(esc(info.name), "bold") + f"  ({format_size(root.total_size)})")
        for line in lines:
            console.print(render_tree_line(console, line))
    if error:
        console.error(error)
        return EXIT_FAILURE
    return EXIT_OK


def jsonout_safe(text: str | None) -> str | None:
    return json_safe(text)


def cmd_manifest(args: argparse.Namespace, console: Console) -> int:
    limits = limits_from_args(args)
    progress = Progress(console, "Writing manifest")
    with open_archive(args.archive, limits, into=args.into) as handler:
        if args.output:
            try:
                if os.path.exists(args.output) and os.path.samefile(args.output, args.archive):
                    raise PacklensError("refusing to overwrite the archive being inspected")
            except OSError:
                pass
            directory = os.path.dirname(os.path.abspath(args.output))
            fd, tmp = tempfile.mkstemp(prefix=".packlens-", suffix=".tmp", dir=directory)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                    error = write_manifest(handler, handle, limits, sha256=args.sha256, on_entry=progress.update)
                if error:
                    raise PacklensError(f"{error} (no output file was written)")
                os.replace(tmp, args.output)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
            finally:
                progress.finish()
            console.note(f"Manifest written to {args.output}")
            return EXIT_OK
        try:
            error = write_manifest(handler, console.out, limits, sha256=args.sha256, on_entry=progress.update)
        finally:
            progress.finish()
    if error:
        console.error(f"{error} (manifest is marked incomplete)")
        return EXIT_FAILURE
    return EXIT_OK


def cmd_verify(args: argparse.Namespace, console: Console) -> int:
    limits = limits_from_args(args)
    progress = Progress(console, "Verifying")

    def show(entry, result) -> None:  # per-entry lines in verbose text mode
        if console.verbose and args.format == "text":
            progress.finish()
            console.print(f"  {result.status.value:<11} {esc(entry.path)}")

    with open_archive(args.archive, limits, into=args.into) as handler:
        try:
            report = verify_archive(handler, on_result=show, on_entry=progress.update)
        finally:
            progress.finish()
    if args.format == "json":
        console.print(jsonout.dumps(jsonout.envelope("verify", report.to_dict())))
    else:
        render_verify(console, report)
    return EXIT_VERIFY_FAILED if report.verdict == "failed" else EXIT_OK


def cmd_duplicates(args: argparse.Namespace, console: Console) -> int:
    limits = limits_from_args(args)
    progress = Progress(console, "Hashing")
    with open_archive(args.archive, limits, into=args.into) as handler:
        try:
            report = find_duplicates(handler, include_empty=args.include_empty, on_progress=progress.update)
        finally:
            progress.finish()
    if args.format == "json":
        console.print(jsonout.dumps(jsonout.envelope("duplicates", report.to_dict())))
    else:
        render_duplicates(console, report)
    if report.error:
        console.error(report.error)
        return EXIT_FAILURE
    return EXIT_OK


def cmd_compare(args: argparse.Namespace, console: Console) -> int:
    limits = limits_from_args(args)
    budget = Budget(limits.max_total_bytes)
    with contextlib.ExitStack() as stack:
        old = stack.enter_context(open_archive(args.old, limits, budget=budget, into=args.into))
        new = stack.enter_context(open_archive(args.new, limits, budget=budget, into=args.into))
        report = compare_archives(old, new, CompareMode(args.by), include_metadata=args.metadata)
    if args.format == "json":
        console.print(jsonout.dumps(jsonout.envelope("compare", report.to_dict())))
    else:
        render_compare(console, report)
    return EXIT_OK


COMMANDS: dict[str, Callable[[argparse.Namespace, Console], int]] = {
    "inspect": cmd_inspect,
    "tree": cmd_tree,
    "manifest": cmd_manifest,
    "verify": cmd_verify,
    "duplicates": cmd_duplicates,
    "compare": cmd_compare,
}


# -- entry point -------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse exits for --help, --version and usage errors
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    for stream in (sys.stdout, sys.stderr):
        # A name the console encoding cannot represent must never crash the program.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(errors="backslashreplace")
    console = Console(
        quiet=getattr(args, "quiet", False),
        verbose=getattr(args, "verbose", False),
        color=False if getattr(args, "no_color", False) else None,
    )
    try:
        return COMMANDS[args.command](args, console)
    except PacklensError as exc:
        console.error(esc(str(exc)))
        return exc.exit_code
    except FileNotFoundError as exc:
        console.error(f"cannot open {esc(str(exc.filename))}: no such file")
        return EXIT_FAILURE
    except PermissionError as exc:
        console.error(f"cannot read {esc(str(exc.filename))}: permission denied")
        return EXIT_FAILURE
    except IsADirectoryError as exc:
        console.error(f"{esc(str(exc.filename))} is a directory")
        return EXIT_FAILURE
    except BrokenPipeError:
        with contextlib.suppress(Exception):
            sys.stdout = open(os.devnull, "w")
        return EXIT_OK
    except KeyboardInterrupt:
        console.error("interrupted")
        return 130
    except OSError as exc:
        console.error(f"I/O error: {esc(str(exc))}")
        return EXIT_FAILURE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
