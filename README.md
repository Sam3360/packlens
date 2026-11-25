# Packlens

Inspect archives. Understand contents.

Packlens is a command-line tool that shows what is inside an archive, checks its integrity,
compares it with another archive and points out anything unusual, without extracting a single
file to disk. It uses only the Python standard library.

```console
$ packlens inspect backup.zip
Archive       backup.zip
Format        ZIP
Contents      6 files, 3 directories, 1 symlink
Uncompressed  7.5 KiB
Compressed    1.6 KiB (archive size on disk)
Ratio         4.71x
Integrity     available: Per-entry CRC-32 checks (requires reading all entry data)
              run `packlens verify backup.zip` to perform the checks

Findings: 2 warning(s), 1 note(s)
  These are observations about the archive, not conclusions about intent.
  warning path-traversal x1
      ../outside.txt: path climbs out of the extraction directory ('..'); extracting naively could write outside it
  warning symlink-escape x1
      project/current: symbolic link to '/etc/passwd' points outside the extraction directory
  note nested-archive x1
      old-backup.tar.gz: file looks like a nested tar.gz archive
```

## Principles

- Inspection never requires extraction, and the source archive is opened read-only.
- Names, metadata and contents are untrusted input. Output is escaped so a hostile file name
  cannot inject terminal escape sequences, and JSON output is always valid.
- Security findings are warnings about what *would* happen under naive extraction, never claims
  about intent.
- Verification says exactly what it checked. A TAR file has no content checksums, so `verify`
  reports "structure and readability only" for it rather than "verified".
- Entry data is streamed in chunks; memory use does not grow with entry size.

Packlens never executes anything from an archive, never makes network requests and needs no
elevated privileges.

## Installation

```bash
pip install packlens
```

Requires Python 3.10 or newer. Packlens has no runtime dependencies. To install from a clone:

```bash
git clone https://github.com/Sam3360/packlens
cd packlens
pip install -e ".[dev]"
```

## Quick start

```bash
packlens inspect backup.zip                 # summary and findings
packlens tree backup.tar.gz --depth 2       # directory view
packlens verify backup.zip                  # integrity check
packlens compare old.zip new.zip --by hash  # what changed
packlens manifest backup.zip --sha256 -o manifest.json
packlens duplicates backup.zip
packlens inspect backup.zip --nested        # also look inside archives within it
packlens tree backup.zip --into old-backup.tar.gz   # open a nested archive
```

## Supported formats

| Format | Detected by content | Notes |
| --- | --- | --- |
| ZIP | yes | including ZIP64 and zips with a prefix (self-extractors); names are reported exactly as stored, so a backslash in a name is visible on every platform |
| TAR | yes | ustar, GNU and pax headers |
| TAR.GZ / TGZ | yes | |
| TAR.BZ2 / TBZ2 | yes | |
| TAR.XZ / TXZ | yes | |
| GZIP, BZIP2, XZ | yes | exposed as one logical entry holding the decompressed payload |

Formats are detected from content; file names are only a hint for empty archives and damaged
compressed streams. 7z, RAR and Zstandard are recognised so the error message can say so, but
they are **not supported yet**. Handlers live in `src/packlens/formats/` behind a common
interface (`ArchiveHandler`), so adding one does not touch the core.

## Commands

Global options (accepted before or after the command): `-q/--quiet`, `-v/--verbose`,
`--no-color`, `--version`, `--help`.

Options shared by every command that opens an archive:

- `--into ENTRY` opens an archive stored inside the archive. Repeat it to go deeper.
- Resource limits: `--max-entries`, `--max-total-bytes`, `--max-entry-size`,
  `--max-nesting-depth`, `--max-nested-size` (see [Resource limits](#resource-limits)).

### inspect

Shows the format, entry counts, sizes, compression ratio, metadata, whether integrity checks
exist, and findings. `--format json` for machine output, `--nested` to inspect archives found
inside, `--strict` to exit with code 4 when any warning-level finding is reported.

### tree

Directory view with sizes. Directories are merged (an explicit `a/` entry and the implied parent
of `a/b.txt` appear once), `--depth N` limits the levels shown and summarises what is hidden,
`--ascii` forces plain line drawing, `--format json` gives a flat list of nodes. Paths that are
repeated or stored as both file and directory are marked. Very deep paths are handled
iteratively.

### verify

Reads every entry and lets the format's own checks run:

| Format | What is checked |
| --- | --- |
| ZIP | CRC-32 of every entry, declared size, local header consistency |
| TAR | header checksums, member readability, declared sizes, end-of-archive marker |
| TAR + gzip/bzip2/xz | the above plus the compression stream's checksum |
| GZIP / BZIP2 / XZ | the stream checksum (xz streams created without a check are reported as incomplete) |

Each check is **passed**, **failed** or **unavailable** (for example an encrypted ZIP entry or an
unsupported ZIP compression method). The overall result is `passed`, `failed` or `incomplete`.

```console
$ packlens verify backup.zip
Archive   backup.zip (ZIP)
Checks    Per-entry CRC-32 checks (requires reading all entry data)
Entries   10 total: 7 passed, 0 failed, 0 unavailable, 3 with no data to check
Read      7.5 KiB decompressed
Structure passed: all headers and the end of the archive are well-formed

PASSED: content checksums matched for every readable entry.
```

Python's `tarfile` treats a corrupted header after the first member as the end of the archive.
Packlens inspects the block where reading stopped, so truncation and damage between members are
reported instead of silently ignored.

### compare

```console
$ packlens compare old.zip new.zip
Comparing old.zip -> new.zip  (by size)

  + added   new.txt  1 B
  - removed gone.txt  1 B
  ~ changed a.txt  (size: 5 -> 6 bytes)
  ~ changed b.txt  (content differs (CRC-32 mismatch))

1 added, 1 removed, 2 changed, 2 path(s) in both
```

`--by path` compares names only. `--by size` (default) compares names and sizes, and also CRC-32
when both archives are ZIPs. `--by hash` streams both archives and compares SHA-256 (only for
files whose sizes already match). A matching size is never reported as "identical": it is
counted separately as "same size, content not compared" unless `--by hash` proves otherwise (two
empty files are always identical). `--metadata` also reports mode and modification-time
differences (2 s tolerance; ZIP and TAR timestamps are not compared with each other because ZIP
timestamps carry no time zone).

### manifest

Writes a JSON manifest: path, type, size, compressed size, modification time, compression
method, CRC-32, mode, link target, plus an optional SHA-256 (`--sha256`). The manifest also
contains a summary and the findings. It is written incrementally, so large archives do not
accumulate in memory. If the archive turns out to be damaged part-way, stdout still receives
valid JSON with `"complete": false` and an `"error"`; with `--output`, no file is written. The
output file is never allowed to be the archive being read.

### duplicates

Groups files by size, hashes only candidates that share a size, and streams each file once.
Duplicate **content** (same SHA-256) and repeated **paths** (the same name stored more than once)
are reported separately. Empty files are excluded unless `--include-empty`.

## Security analysis

`inspect` (and `manifest`) report these findings. They describe what would happen if the archive
were extracted naively and are not a malware verdict.

| Code | Meaning |
| --- | --- |
| `absolute-path`, `windows-drive-path` | path starts with `/`, `\` or a drive letter |
| `path-traversal` | `..` components that climb above the extraction root |
| `parent-reference` | `..` that stays inside the root |
| `backslash-separator` | backslash in a name (a separator on Windows) |
| `control-characters`, `bidi-control`, `invalid-encoding` | control characters, text-direction overrides, non-UTF-8 names |
| `deep-nesting` | very deep directory nesting |
| `duplicate-path`, `type-conflict`, `case-collision` | repeated paths, file/directory clashes, names differing only by case or Unicode form |
| `symlink`, `symlink-escape`, `hardlink`, `hardlink-escape` | links, and whether their target leaves the root |
| `special-file`, `special-permissions` | devices/FIFOs; setuid or setgid bits |
| `large-entry`, `high-compression-ratio`, `high-total-ratio`, `many-entries` | possible resource-exhaustion indicators |
| `encrypted-entry` | contents cannot be checked |
| `nested-archive` | a file that looks like an archive (note only) |

Nested archives are *not* inspected unless you pass `--nested` (or `--into`). They are read into
memory, never written to disk, and bounded by the limits below. They are found by name and by
content signature, so a renamed archive is still noticed.

Heuristic thresholds (ratio 100x, 1 GiB entries, 100,000 entries, 32 path levels) are fields on
`packlens.core.limits.Limits`.

## Resource limits

Limits stop an operation with exit code 1 and a message naming the option to raise. Use `0` (or
`unlimited`) for no limit. Sizes accept `10MB` (decimal) and `10MiB` (binary).

| Option | Default | Meaning |
| --- | --- | --- |
| `--max-entries` | 1,000,000 | entries per archive (ZIP counts are checked before parsing) |
| `--max-total-bytes` | 10 GiB | decompressed bytes processed in one command, across nested archives |
| `--max-entry-size` | 4 GiB | decompressed bytes read from one entry |
| `--max-nesting-depth` | 3 | levels of nested archives to inspect |
| `--max-nested-size` | 128 MiB | largest nested archive held in memory |

A compressed TAR or a standalone stream has to be decompressed to be listed, so these limits also
protect `inspect` against decompression bombs. For a compressed stream that exceeds a limit,
`inspect` still works and reports the uncompressed size as unknown.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | operation failed: unreadable or unsupported input, damaged archive that could not be listed fully, resource limit reached |
| 2 | invalid arguments or usage |
| 3 | `verify` found a failed check |
| 4 | `inspect --strict` reported at least one warning-level finding |

`verify` exits 0 for an `incomplete` result (nothing failed, but some checks could not run); the
text and JSON output say so explicitly. `compare` exits 0 whether or not differences are found.

## Output modes

- Text output is the default. `--format json` is available on every command except `manifest`,
  which always emits JSON. JSON documents carry `schema_version` and `packlens_version`.
- `--quiet` suppresses progress and informational output: `inspect` prints one line, `verify`
  prints nothing on success. Requested data (trees, manifests, comparisons) is still printed.
- `--verbose` shows more samples per finding and lists every entry during `verify`.
- Progress is shown on stderr only when it is a terminal.

## Known limitations

- 7z, RAR and Zstandard are not supported. Multi-volume ZIPs are not supported.
- ZIP: encrypted entries and compression methods unsupported by Python can be listed but not
  verified. Zstandard-compressed ZIP entries can only be verified on Python 3.14 or newer, where
  the standard library can decode them; on older versions they are reported as "unavailable". Python's `zipfile` holds the whole entry table in memory: a
  100,000-entry ZIP peaked at about 130 MiB in our test, so very large archives need
  proportionally more memory.
- Compressed TARs have no random access: listing needs one decompression pass and hashing needs
  another.
- A damaged ZIP whose central directory is gone is reported as unreadable; no recovery by
  scanning local headers is attempted.
- A TAR file only proves structure, never content integrity.
- Link-escape analysis resolves paths lexically; it does not know what exists on a target
  filesystem.
- Tested on Linux, Windows and macOS through the CI workflow.

## Development

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

Test archives are built programmatically in `tests/helpers.py`; no binary fixtures are stored.
`tests/test_robustness.py` mutates every format with seeded random corruption and asserts that only
deliberate Packlens errors ever escape. `tests/test_properties.py` uses Hypothesis and is skipped
when it is not installed.

Layout:

```text
src/packlens/
  cli.py             argument parsing, exit codes
  core/              models, limits, format detection, opening archives
  formats/           ArchiveHandler interface and the ZIP / TAR / stream handlers
  analysis/          integrity, paths/metadata, duplicates, comparison, tree, nested
  output/            terminal and JSON rendering, streaming manifest writer
  utils/             hashing and formatting helpers
```

## Contributing

Issues and pull requests are welcome at <https://github.com/Sam3360/packlens>. Please keep to the
project's priorities: correctness and security before features, no new runtime dependencies without
a strong reason, and tests for every behaviour change. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
