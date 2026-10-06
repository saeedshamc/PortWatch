# Contributing to PortWatch

Thanks for considering a contribution! This guide covers the setup and
the checks every change must pass.

## Development setup

```bash
git clone https://github.com/saeedshamc/PortWatch
cd PortWatch
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pip install -e .
```

## Checks every change must pass

Run all of these before committing (CI runs the same set):

```bash
python -m pytest          # tests + coverage gate (>= 90%)
ruff check portwatch tests
mypy
```

A quick summary of the rules:

- **Tests** live in `tests/`, one module per source module. Remote-scan
  tests use real local listeners (ephemeral ports), never the internet.
- **Lint** uses ruff with `E, W, F, I, UP, B` at 100-char lines
  (configured in `pyproject.toml`).
- **Types** are checked with mypy over `portwatch/`; the package ships a
  `py.typed` marker, so annotations are part of the public interface.
- **Coverage** must stay at or above 90% (`fail_under` in
  `pyproject.toml`).

## Compatibility

Python 3.10+ on Windows, macOS and Linux. Avoid features newer than
3.10 and platform-specific behavior without a guard. Anything touching
Windows console encoding or line endings is especially sensitive — see
`docs/EXPORT.md` for the invariants.

## Commits

Use short imperative subjects ("Add flag X", "Fix Y crash"), with a
body explaining why the change was needed. Keep each commit
self-contained: one logical change, tests included.

## Docs

User-visible changes (new flags, new output fields, exit codes) must
update `README.md` and `docs/USAGE.md` in the same change.
