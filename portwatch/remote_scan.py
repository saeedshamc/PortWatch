"""Concurrent asynchronous TCP connect scanner."""

from __future__ import annotations

import asyncio
import socket
from typing import Iterable, Optional, Sequence

from portwatch.banner import build_http_probe, grab_banner as _grab_banner, identify_service
from portwatch.models import PortResult, RemoteScanResult
from portwatch.targets import Target


async def _resolve_addresses(target: Target) -> list[str]:
    """Resolve a target to the list of IP addresses its hostname maps to.

    IP targets return a single-element list unchanged; unresolvable hostnames
    return an empty list.
    """
    if target.is_ip:
        return [target.host]
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            target.host, None, family=0, type=socket.SOCK_STREAM
        )
    except OSError:
        return []
    addresses: list[str] = []
    for _family, _type, _proto, _canonname, sockaddr in infos:
        address = str(sockaddr[0])
        if address not in addresses:
            addresses.append(address)
    return addresses


async def _probe_port(
    host: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
    grab_banner: bool,
    probe: bool,
) -> PortResult:
    """Attempt one TCP connection; optionally read an identifying banner."""
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
        except (OSError, asyncio.TimeoutError) as exc:
            name = type(exc).__name__
            if isinstance(exc, asyncio.TimeoutError):
                detail = "timed out"
            elif name == "ConnectionRefusedError":
                detail = "connection refused"
            else:
                detail = str(exc) or name.lower()
            return PortResult(host=host, port=port, open=False, error=detail)

        banner = None
        service = None
        if grab_banner or probe:
            if probe:
                try:
                    writer.write(build_http_probe(host, port))
                    await asyncio.wait_for(writer.drain(), timeout=timeout)
                except (OSError, asyncio.TimeoutError):
                    pass
            if grab_banner:
                raw = await _grab_banner(reader, timeout=timeout)
                if raw:
                    banner = raw
                    service = identify_service(banner, port=port)
            if service is None:
                service = identify_service(None, port=port)
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return PortResult(host=host, port=port, open=True, banner=banner, service=service)


async def scan_remote(
    targets: Sequence[Target],
    ports: Sequence[int],
    concurrency: int = 100,
    timeout: float = 2.0,
    grab_banner: bool = True,
    probe: bool = False,
) -> list[RemoteScanResult]:
    """Scan each target's ports concurrently and group results per host.

    Each target is resolved once; every port is then probed against the
    resolved address, so DNS is queried a single time per host regardless of
    port count. ``concurrency`` bounds the number of in-flight connection
    attempts and ``timeout`` limits each individual TCP connect (and banner
    read). With ``probe=True`` an HTTP HEAD request is sent before reading
    the banner so silent services (e.g. web servers) can be identified.
    Unresolvable hostnames are reported with no open ports.
    """
    if concurrency < 1:
        raise ValueError("concurrency must be >= 1")
    if timeout <= 0:
        raise ValueError("timeout must be > 0")
    semaphore = asyncio.Semaphore(concurrency)

    async def scan_target(target: Target) -> RemoteScanResult:
        host_key = target.raw if not target.is_ip else target.host
        addresses = await _resolve_addresses(target)
        resolved = addresses[0] if addresses else None
        if resolved is None:
            return RemoteScanResult(
                host=host_key, resolved_ip=None, ports_scanned=len(ports), open_ports=[]
            )
        results = await asyncio.gather(
            *(
                _probe_port(resolved, port, timeout, semaphore, grab_banner, probe)
                for port in ports
            )
        )
        open_ports = [result for result in results if result.open]
        open_ports.sort(key=lambda r: r.port)
        return RemoteScanResult(
            host=host_key,
            resolved_ip=resolved,
            ports_scanned=len(ports),
            open_ports=open_ports,
        )

    return list(await asyncio.gather(*(scan_target(t) for t in targets)))


def scan_targets_sync(
    targets: Iterable[Target],
    ports: Sequence[int],
    concurrency: int = 100,
    timeout: float = 2.0,
    grab_banner: bool = True,
    probe: bool = False,
) -> list[RemoteScanResult]:
    """Synchronous entry point that runs the async scanner on a fresh loop."""
    return asyncio.run(
        scan_remote(
            list(targets),
            list(ports),
            concurrency=concurrency,
            timeout=timeout,
            grab_banner=grab_banner,
            probe=probe,
        )
    )
