"""Enumeration of listening ports and their owning processes via psutil."""

from __future__ import annotations

import psutil

from portwatch.models import PortRecord


class LocalScanError(RuntimeError):
    """Raised when listening sockets cannot be enumerated."""


#: Maps a user-facing protocol filter to the psutil ``kind`` strings to query.
_KIND_MAP: dict[str, list[str]] = {
    "tcp": ["tcp"],
    "udp": ["udp"],
    "inet": ["tcp", "udp"],
}


def _describe_process(pid: int | None) -> tuple[str | None, str | None, str | None]:
    """Return (name, executable, command_line) for a PID, tolerating access denial."""
    if pid is None or pid <= 0:
        return None, None, None
    try:
        proc = psutil.Process(pid)
        name = proc.name()
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return "(defunct)", None, None
    except psutil.AccessDenied:
        return "(no access)", None, None
    try:
        exe = proc.exe() or None
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        exe = None
    try:
        cmdline = " ".join(proc.cmdline()) or None
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        cmdline = None
    return name, exe, cmdline


def scan_local_ports(protocol: str = "inet") -> list[PortRecord]:
    """List listening TCP/IPv4+IPv6 sockets and their owning processes.

    ``protocol`` may be ``"inet"`` (TCP + UDP), ``"tcp"`` or ``"udp"``.
    """
    protocols = _KIND_MAP.get(protocol)
    if protocols is None:
        raise LocalScanError(f"unsupported protocol filter: {protocol!r}")

    records: list[PortRecord] = []
    seen: set[tuple[str, str, int]] = set()
    for proto in protocols:
        try:
            connections = psutil.net_connections(kind=proto)
        except psutil.AccessDenied:
            raise LocalScanError(
                "insufficient permissions to enumerate system-wide sockets; "
                "try running from an elevated prompt"
            ) from None
        for conn in connections:
            # psutil types laddr as ``addr | tuple[str, int] | tuple[()]``;
            # only the two-element shapes carry a listening address.
            match conn.laddr:
                case (str() as ip, int() as port):
                    pass
                case _:
                    continue
            key = (proto, ip, port)
            if key in seen:
                continue
            seen.add(key)
            name, exe, cmdline = _describe_process(conn.pid)
            records.append(
                PortRecord(
                    protocol=proto.upper(),
                    local_address=ip,
                    local_port=port,
                    pid=conn.pid,
                    process_name=name,
                    executable=exe,
                    command_line=cmdline,
                )
            )
    records.sort(key=lambda r: (r.protocol, r.local_port, r.local_address))
    return records
