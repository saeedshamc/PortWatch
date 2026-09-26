"""Comparison of saved PortWatch JSON scans.

Two previously saved remote scans (``-f json -o file.json``) can be diffed
to report which ports opened and which closed between them. Local-scan
files (a flat array of listener records) are supported too.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


class DiffError(ValueError):
    """Raised when a saved scan file cannot be used for a diff."""


def load_scan(path: str) -> tuple[str, dict[int, dict[str, Any]]]:
    """Read a saved PortWatch JSON scan and index its open ports by port.

    Returns ``(label, ports)`` where ``label`` describes the scan for error
    messages (the target host for remote scans, "local" otherwise) and
    ``ports`` maps each open port number to its record, which for remote
    scans contains ``service`` and ``banner``.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise DiffError(f"cannot read {path!r}: {exc}") from None
    except json.JSONDecodeError as exc:
        raise DiffError(f"{path!r} is not valid JSON: {exc}") from None

    if not isinstance(data, list):
        raise DiffError(f"{path!r} does not contain a PortWatch scan (expected a JSON array)")

    remote = [entry for entry in data if isinstance(entry, dict) and "open_ports" in entry]
    if remote:
        if len(remote) != 1:
            raise DiffError(
                f"{path!r} contains {len(remote)} targets; diff compares one host per file"
            )
        entry = remote[0]
        host = str(entry.get("host") or "unknown")
        ports: dict[int, dict[str, Any]] = {}
        for record in entry.get("open_ports") or []:
            if isinstance(record, dict) and isinstance(record.get("port"), int):
                ports[record["port"]] = {
                    "service": record.get("service"),
                    "banner": record.get("banner"),
                }
        return host, ports

    local = [entry for entry in data if isinstance(entry, dict) and "local_port" in entry]
    if local:
        ports = {}
        for record in local:
            port = record.get("local_port")
            if isinstance(port, int):
                ports[port] = {
                    "service": f"{record.get('protocol', '?').lower()}/{record.get('process_name') or '?'}",
                    "banner": record.get("executable"),
                }
        return "local", ports

    raise DiffError(f"{path!r} contains no recognizable PortWatch records")


@dataclass
class ScanDiff:
    """Result of comparing two saved scans of the same host."""

    host: str
    opened: list[dict[str, Any]] = field(default_factory=list)
    closed: list[dict[str, Any]] = field(default_factory=list)
    unchanged: list[dict[str, Any]] = field(default_factory=list)
    changed_service: list[dict[str, Any]] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.opened or self.closed or self.changed_service)

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "opened": self.opened,
            "closed": self.closed,
            "unchanged_count": len(self.unchanged),
            "changed_service": self.changed_service,
        }


def _service(record: dict[str, Any]) -> str:
    return str(record.get("service") or "?")


def diff_scans(old: tuple[str, dict[int, dict[str, Any]]],
               new: tuple[str, dict[int, dict[str, Any]]]) -> ScanDiff:
    """Compare two indexed scans and classify every port transition."""
    old_host, old_ports = old
    new_host, new_ports = new
    host = new_host if new_host != "unknown" else old_host
    result = ScanDiff(host=host)

    for port in sorted(set(old_ports) | set(new_ports)):
        was = old_ports.get(port)
        now = new_ports.get(port)
        if was is None and now is not None:
            result.opened.append({"port": port, "service": _service(now), "banner": now.get("banner")})
        elif was is not None and now is None:
            result.closed.append({"port": port, "service": _service(was), "banner": was.get("banner")})
        elif _service(was) != _service(now):
            result.changed_service.append(
                {"port": port, "old_service": _service(was), "new_service": _service(now)}
            )
            result.unchanged.append({"port": port, "service": _service(now), "banner": now.get("banner")})
        else:
            result.unchanged.append({"port": port, "service": _service(now), "banner": now.get("banner")})
    return result


def compare_files(old_path: str, new_path: str) -> ScanDiff:
    """Load two saved scans and diff them, checking they cover the same host."""
    old = load_scan(old_path)
    new = load_scan(new_path)
    if old[0] != new[0] and "local" not in (old[0], new[0]):
        raise DiffError(
            f"scans cover different hosts ({old[0]!r} vs {new[0]!r}); "
            "diff requires both files from the same target"
        )
    return diff_scans(old, new)


def render_diff_table(diff: ScanDiff) -> str:
    """Human-readable table of the changes between two scans."""
    lines: list[str] = [f"Port changes for {diff.host}:", ""]

    def section(title: str, rows: list[tuple[int, str]], empty_note: str) -> None:
        lines.append(title)
        if rows:
            for port, detail in rows:
                lines.append(f"  {port:<6} {detail}")
        else:
            lines.append(f"  {empty_note}")
        lines.append("")

    section(
        "NEWLY OPENED:",
        [(item["port"], _service_text(item)) for item in diff.opened],
        "(none)",
    )
    section(
        "NEWLY CLOSED:",
        [(item["port"], _service_text(item)) for item in diff.closed],
        "(none)",
    )
    section(
        "SERVICE CHANGED:",
        [(item["port"], f"{item['old_service']} -> {item['new_service']}") for item in diff.changed_service],
        "(none)",
    )
    summary = (
        f"{len(diff.opened)} opened, {len(diff.closed)} closed, "
        f"{len(diff.changed_service)} service change(s), {len(diff.unchanged)} unchanged"
    )
    lines.append(summary)
    return "\n".join(lines)


def _service_text(item: dict[str, Any]) -> str:
    service = item.get("service") or "?"
    banner = item.get("banner")
    if banner:
        return f"{service}  ({str(banner)[:40]})"
    return service


def exit_code_for(diff: ScanDiff) -> int:
    """2 when differences exist (CI-friendly), 0 when the scans match."""
    return 2 if diff.has_changes else 0
