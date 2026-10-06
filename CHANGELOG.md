# Changelog

All notable changes to PortWatch are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-06

### Added

- **CSV output** (`-f csv`): RFC 4180 rows with a header line — local mode
  emits one row per listening socket, remote mode one row per open port
  (`host,port,service,banner`).
- **NDJSON output** (`-f ndjson`): one JSON object per line, suited to
  rolling logs, `grep`, and `jq -c` pipelines.
- **Packaging**: `pyproject.toml` with pip-installable metadata, a
  `portwatch` console script, and a dynamic version — the project can now
  be installed with `pip install .` and published to PyPI.
- **Code quality gates**: ruff linting (E, W, F, I, UP, B), mypy type
  checking over `portwatch/`, and pytest-cov with a 90% minimum coverage
  gate; each runs as its own CI job.
- **Security policy** (`SECURITY.md`) with private vulnerability
  reporting, and a contribution guide (`CONTRIBUTING.md`).

### Fixed

- Type-safety issue in local scanning where `conn.laddr` is now handled
  for every shape psutil can report (`addr`, plain tuples, or empty).
- Narrowing issue in scan diffing that could pass `None` records to the
  service classifier.

## [0.1.0] - 2026-09-26

### Added

- Local scan mode: enumerates listening TCP/UDP sockets with owning
  process (PID, name, executable, command line) via psutil.
- Remote scan mode: asynchronous concurrent TCP connect scanner with
  configurable concurrency and timeout, per-host DNS resolution, and
  CIDR subnet expansion capped at 4096 hosts.
- Banner grabbing for greeting services (SSH, FTP, SMTP, POP3, IMAP,
  VNC, Redis, MySQL) plus an optional HTTP HEAD probe (`--probe`) for
  silent web servers; service fingerprinting with well-known-port
  fallback.
- Diff mode: compares two saved JSON scans and reports newly opened,
  newly closed, and service-changed ports; exit code 2 on any change so
  it can gate scripts and CI jobs.
- Table and JSON output formats; `-o/--output` writes files as UTF-8
  with LF line endings on every platform.
- Robust console output on legacy Windows codepages (unencodable
  characters are replaced instead of crashing) and validation of
  non-finite or non-positive timeouts.
- Documentation: `README.md`, `docs/USAGE.md`, `docs/EXPORT.md`.
- Test suite and GitHub Actions CI running on Linux, Windows, and macOS
  with Python 3.10 and 3.13.

[0.2.0]: https://github.com/saeedshamc/PortWatch/releases/tag/v0.2.0
[0.1.0]: https://github.com/saeedshamc/PortWatch/releases/tag/v0.1.0
