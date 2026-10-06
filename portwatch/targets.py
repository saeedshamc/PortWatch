"""Parsing of port specifications and scan targets."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

#: Default remote-scan range when --ports is not given.
DEFAULT_PORT_SPEC = "1-1024"

#: Refuse to expand subnets larger than this many hosts by default.
MAX_CIDR_HOSTS = 4096


class TargetError(ValueError):
    """Raised when a port specification or target cannot be parsed."""


def parse_port_spec(spec: str) -> list[int]:
    """Parse a port specification into a sorted, de-duplicated list of ports.

    Accepted forms: ``80``, ``80-90``, ``1-1024,8080,3000-3005``.
    """
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_text, _, hi_text = part.partition("-")
            try:
                lo, hi = int(lo_text), int(hi_text)
            except ValueError:
                raise TargetError(f"invalid port range: {part!r}") from None
            if not (1 <= lo <= hi <= 65535):
                raise TargetError(f"port range out of bounds: {part!r}")
            ports.update(range(lo, hi + 1))
        else:
            try:
                port = int(part)
            except ValueError:
                raise TargetError(f"invalid port: {part!r}") from None
            if not (1 <= port <= 65535):
                raise TargetError(f"port out of range: {port}")
            ports.add(port)
    if not ports:
        raise TargetError("empty port specification")
    return sorted(ports)


@dataclass(frozen=True)
class Target:
    """A single host to scan, as given on the command line."""

    raw: str
    host: str
    is_ip: bool


def expand_targets(inputs: Iterable[str], max_cidr_hosts: int = MAX_CIDR_HOSTS) -> list[Target]:
    """Expand CLI target inputs into individual hosts.

    Accepts single IPv4/IPv6 addresses, hostnames, and CIDR subnets. Subnets
    are capped so a typo cannot trigger a million-address sweep. Duplicates
    are removed while preserving first-seen order.
    """
    targets: dict[str, Target] = {}
    for raw in inputs:
        entry = raw.strip()
        if not entry:
            continue
        if "/" in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                raise TargetError(f"invalid CIDR subnet: {entry!r}") from None
            if network.num_addresses > max_cidr_hosts + 2:
                raise TargetError(
                    f"subnet {entry!r} spans more than {max_cidr_hosts} hosts; "
                    "refusing to expand"
                )
            hosts = (
                list(network.hosts())
                if network.num_addresses > 1
                else [network.network_address]
            )
            for address in hosts:
                targets.setdefault(str(address), Target(raw=entry, host=str(address), is_ip=True))
        else:
            try:
                ipaddress.ip_address(entry)
                targets.setdefault(entry, Target(raw=entry, host=entry, is_ip=True))
            except ValueError:
                targets.setdefault(entry, Target(raw=entry, host=entry, is_ip=False))
    if not targets:
        raise TargetError("no targets given")
    return list(targets.values())
