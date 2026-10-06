"""Command-line interface for PortWatch."""

from __future__ import annotations

import argparse
import csv
import io
import json
import math
import sys
from collections.abc import Sequence
from typing import IO

from portwatch import __version__
from portwatch.diffing import compare_files, exit_code_for, render_diff_table
from portwatch.local_scan import LocalScanError, scan_local_ports
from portwatch.models import PortRecord, RemoteScanResult
from portwatch.remote_scan import scan_targets_sync
from portwatch.targets import (
    DEFAULT_PORT_SPEC,
    MAX_CIDR_HOSTS,
    TargetError,
    expand_targets,
    parse_port_spec,
)

#: Formats that stream one record per line instead of a single document.
LINE_FORMATS = ("ndjson",)

#: Formats accepted by ``--format``.
OUTPUT_FORMATS = ("table", "json", "csv", "ndjson")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portwatch",
        description="Cross-platform port scanning toolkit: enumerate local "
        "listening ports or scan remote TCP ports.",
    )
    parser.add_argument(
        "--mode",
        choices=("local", "remote", "diff"),
        default="local",
        help="scan mode: local listening sockets, remote TCP connect scan, or "
        "diff of two saved scan files (default: local)",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        metavar="TARGET",
        help="remote mode: IPs, hostnames or CIDR subnets "
        f"(e.g. 10.0.0.1 myhost.local 192.168.1.0/24; subnets capped at {MAX_CIDR_HOSTS} hosts); "
        "diff mode: exactly two saved scan JSON files (old then new)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default=DEFAULT_PORT_SPEC,
        help=f"remote mode only: port spec, e.g. 80,443,8000-8010 (default: {DEFAULT_PORT_SPEC})",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=100,
        help="remote mode only: maximum simultaneous connections (default: 100)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.0,
        help="remote mode only: per-connection timeout in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="remote mode only: send an HTTP HEAD request to open ports before "
        "reading the banner (identifies silent web servers)",
    )
    parser.add_argument(
        "--protocol",
        choices=("inet", "tcp", "udp"),
        default="inet",
        help="local mode only: socket protocols to list (default: inet = TCP+UDP)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=OUTPUT_FORMATS,
        default="table",
        dest="output_format",
        help="output format: table, json, csv (spreadsheet-friendly), or "
        "ndjson (one JSON object per line for logs and grep) (default: table)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        dest="output_file",
        help="also write the result to FILE as UTF-8 with LF line endings; "
        "the same output is still printed to the console",
    )
    parser.add_argument("--version", action="version", version=f"portwatch {__version__}")
    return parser


def _render_local_table(records: Sequence[PortRecord]) -> str:
    headers = ("PROTO", "ADDRESS", "PORT", "PID", "PROCESS", "EXECUTABLE")
    rows = [
        (
            record.protocol,
            record.local_address,
            str(record.local_port),
            str(record.pid) if record.pid is not None else "-",
            record.process_name or "-",
            record.executable or "-",
        )
        for record in records
    ]
    return _format_table(headers, rows)


def _render_remote_table(results: Sequence[RemoteScanResult]) -> str:
    headers = ("HOST", "PORT", "SERVICE", "BANNER")
    rows = []
    for result in results:
        if result.open_ports:
            for port in result.open_ports:
                rows.append(
                    (
                        result.host,
                        str(port.port),
                        port.service or "?",
                        _truncate(port.banner or "", 60),
                    )
                )
        else:
            rows.append((result.host, "-", "-", "-"))
    table = _format_table(headers, rows)
    scanned = sum(result.ports_scanned for result in results)
    open_count = sum(len(result.open_ports) for result in results)
    return f"{table}\n\n{len(results)} target(s), {scanned} port(s) scanned, {open_count} open"


def _format_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    lines = [
        "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)),
        "  ".join("-" * width for width in widths),
    ]
    for row in rows:
        lines.append("  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)))
    return "\n".join(lines)


#: Column order for local-mode CSV output.
_LOCAL_CSV_FIELDS = (
    "protocol",
    "local_address",
    "local_port",
    "pid",
    "process_name",
    "executable",
    "command_line",
)

#: Column order for remote-mode CSV and NDJSON output (one row per open port).
_REMOTE_CSV_FIELDS = ("host", "port", "service", "banner")


def _csv_document(rows: Sequence[dict[str, object]], fields: Sequence[str]) -> str:
    """Render rows as RFC 4180 CSV with LF line endings (project convention)."""
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer, fieldnames=list(fields), extrasaction="ignore", lineterminator="\n"
    )
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().rstrip("\r\n")


def _remote_open_rows(results: Sequence[RemoteScanResult]) -> list[dict[str, object]]:
    """Flatten remote results to one row per open port (shared by CSV/NDJSON)."""
    rows: list[dict[str, object]] = []
    for result in results:
        for port in result.open_ports:
            rows.append(
                {
                    "host": result.host,
                    "port": port.port,
                    "service": port.service or "",
                    "banner": port.banner or "",
                }
            )
    return rows


def _render_local(records: Sequence[PortRecord], output_format: str) -> str:
    """Render local scan records in the requested output format."""
    if output_format == "csv":
        return _csv_document([record.as_dict() for record in records], _LOCAL_CSV_FIELDS)
    if output_format == "ndjson":
        return "\n".join(json.dumps(record.as_dict()) for record in records)
    if output_format == "json":
        return json.dumps([record.as_dict() for record in records], indent=2)
    return _render_local_table(records)


def _render_remote(results: Sequence[RemoteScanResult], output_format: str) -> str:
    """Render remote scan results in the requested output format."""
    if output_format == "csv":
        return _csv_document(_remote_open_rows(results), _REMOTE_CSV_FIELDS)
    if output_format == "ndjson":
        return "\n".join(json.dumps(row) for row in _remote_open_rows(results))
    if output_format == "json":
        return json.dumps([result.as_dict() for result in results], indent=2)
    return _render_remote_table(results)


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 3] + "..."


def _write(text: str, stream: IO[str] | None = None) -> None:
    """Print text, replacing characters the output stream cannot encode.

    Legacy console codepages (e.g. Windows cp437/cp1252) cannot represent
    every character that may appear in banners or process names; without
    this guard the scan result would be lost to a UnicodeEncodeError.
    """
    stream = stream if stream is not None else sys.stdout
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        text.encode(encoding, errors="strict")
    except (UnicodeEncodeError, LookupError):
        text = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
    print(text, file=stream)


def _print_json(payload: object) -> None:
    _write(json.dumps(payload, indent=2))


def _open_output(path: str) -> IO[str]:
    """Open an output file as UTF-8 with LF line endings on every platform.

    Text mode translates ``\\n`` to the platform line ending by default;
    ``newline="\\n"`` disables that so files are byte-identical across
    Windows, macOS and Linux. Encoding is pinned to UTF-8 regardless of the
    console codepage.
    """
    return open(path, "w", encoding="utf-8", newline="\n")


def _emit(
    text: str,
    output_file: str | None,
    stdout: IO[str],
    stderr: IO[str],
) -> None:
    """Print a rendered result to the console and optionally save it to a file."""
    _write(text, stream=stdout)
    if output_file:
        try:
            handle = _open_output(output_file)
        except OSError as exc:
            print(f"error: cannot write {output_file!r}: {exc}", file=stderr)
            raise SystemExit(2) from None
        with handle:
            _write(text, stream=handle)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be a positive finite number")

    try:
        if args.mode == "diff":
            if len(args.targets) != 2:
                parser.error(
                    "diff mode requires exactly two saved scan files: "
                    "portwatch --mode diff OLD.json NEW.json"
                )
            diff = compare_files(args.targets[0], args.targets[1])
            if args.output_format == "json":
                rendered = json.dumps(diff.as_dict(), indent=2)
            else:
                rendered = render_diff_table(diff)
            _emit(rendered, args.output_file, sys.stdout, sys.stderr)
            return exit_code_for(diff)

        if args.mode == "local":
            records = scan_local_ports(protocol=args.protocol)
            rendered = _render_local(records, args.output_format)
            _emit(rendered, args.output_file, sys.stdout, sys.stderr)
            return 0

        if not args.targets:
            parser.error("remote mode requires at least one target")
        ports = parse_port_spec(args.ports)
        targets = expand_targets(args.targets)
        results = scan_targets_sync(
            targets,
            ports,
            concurrency=args.concurrency,
            timeout=args.timeout,
            grab_banner=True,
            probe=args.probe,
        )
        rendered = _render_remote(results, args.output_format)
        _emit(rendered, args.output_file, sys.stdout, sys.stderr)
        return 0
    except (TargetError, LocalScanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
