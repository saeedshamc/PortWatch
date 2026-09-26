"""Command-line interface for PortWatch."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from portwatch import __version__
from portwatch.local_scan import LocalScanError, scan_local_ports
from portwatch.models import PortRecord, RemoteScanResult
from portwatch.remote_scan import scan_targets_sync
from portwatch.targets import DEFAULT_PORT_SPEC, MAX_CIDR_HOSTS, TargetError, expand_targets, parse_port_spec


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portwatch",
        description="Cross-platform port scanning toolkit: enumerate local "
        "listening ports or scan remote TCP ports.",
    )
    parser.add_argument(
        "--mode",
        choices=("local", "remote"),
        default="local",
        help="scan mode: local listening sockets or remote TCP connect scan "
        "(default: local)",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        metavar="TARGET",
        help="remote mode only: IPs, hostnames or CIDR subnets "
        f"(e.g. 10.0.0.1 myhost.local 192.168.1.0/24; subnets capped at {MAX_CIDR_HOSTS} hosts)",
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
        choices=("table", "json"),
        default="table",
        dest="output_format",
        help="output format (default: table)",
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


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 3] + "..."


def _print_json(payload: object) -> None:
    print(json.dumps(payload, indent=2))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.mode == "local":
            records = scan_local_ports(protocol=args.protocol)
            if args.output_format == "json":
                _print_json([record.as_dict() for record in records])
            else:
                print(_render_local_table(records))
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
        if args.output_format == "json":
            _print_json([result.as_dict() for result in results])
        else:
            print(_render_remote_table(results))
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
