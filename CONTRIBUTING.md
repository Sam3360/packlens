# Contributing to Packlens

Thanks for helping. A few ground rules keep the project reliable.

## Priorities

1. Correctness and security over feature count.
2. Treat everything from an archive (names, metadata, contents) as untrusted.
3. Standard library only at runtime. Propose any dependency in an issue first.
4. Never extract, execute or modify anything; never make network requests.

## Setup

```bash
git clone https://github.com/Sam3360/packlens
cd packlens
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Making changes

- Add or update tests with every behaviour change. Build fixtures in code (`tests/helpers.py`);
  do not commit binary archives.
- If you fix a crash found on malformed input, add a regression test that reproduces it.
- Keep format-specific code inside `src/packlens/formats/`. A new format is a new
  `ArchiveHandler` registered in `formats/__init__.py` plus detection in `core/detection.py`.
  Do not advertise a format in the README until its implementation and tests are complete.
- Anything printed from archive-derived text must go through `escape_for_terminal`; anything put
  in JSON must go through `json_safe`.
- Keep exit codes stable; update the README table if you must change one.
- Use type hints, avoid broad `except Exception`, and catch specific error types.

## Reporting security problems

Please report vulnerabilities privately through GitHub's security advisories for this repository
rather than in a public issue.
