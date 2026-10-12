"""Data structures shared across PortWatch modules."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class PortRecord:
    """A listening socket on the local machine and its owning process."""

    protocol: str
    local_address: str
    local_port: int
    pid: int | None = None
    process_name: str | None = None
    executable: str | None = None
    command_line: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TlsInfo:
    """Certificate and protocol details captured during a TLS handshake.

    Populated when ``--tls`` is used against an open port. Because the
    handshake is performed without validating the chain (a scanner must
    report certificates it does not trust), ``verified`` records whether the
    certificate actually chains to a trusted root, so an untrusted cert is
    never mistaken for a valid one.
    """

    protocol: str | None = None
    cipher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    subject_alt_names: list[str] = field(default_factory=list)
    verified: bool = False
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PortResult:
    """Outcome of probing a single port on a remote target."""

    host: str
    port: int
    open: bool
    error: str | None = None
    banner: str | None = None
    service: str | None = None
    tls: TlsInfo | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RemoteScanResult:
    """Aggregated scan results for one target host."""

    host: str
    resolved_ip: str | None = None
    ports_scanned: int = 0
    open_ports: list[PortResult] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanEvent:
    """A progress notification emitted while a remote scan runs.

    Passed to the ``on_event`` callback of :func:`scan_remote`. ``kind`` is
    one of ``start``, ``resolve``, ``open``, ``progress`` or ``done``; the
    remaining fields carry whatever is relevant for that kind and default to
    neutral values, so handlers can switch on ``kind`` and read only what
    they need.
    """

    kind: str
    host: str | None = None
    port: int | None = None
    service: str | None = None
    banner: str | None = None
    resolved_ip: str | None = None
    addresses: int = 0
    scanned: int = 0
    total: int = 0
    open_count: int = 0
    targets: int = 0
    ports: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
