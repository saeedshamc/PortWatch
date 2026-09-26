"""Data structures shared across PortWatch modules."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class PortRecord:
    """A listening socket on the local machine and its owning process."""

    protocol: str
    local_address: str
    local_port: int
    pid: Optional[int] = None
    process_name: Optional[str] = None
    executable: Optional[str] = None
    command_line: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PortResult:
    """Outcome of probing a single port on a remote target."""

    host: str
    port: int
    open: bool
    error: Optional[str] = None
    banner: Optional[str] = None
    service: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RemoteScanResult:
    """Aggregated scan results for one target host."""

    host: str
    resolved_ip: Optional[str] = None
    ports_scanned: int = 0
    open_ports: list[PortResult] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
