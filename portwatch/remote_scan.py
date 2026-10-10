"""Concurrent asynchronous TCP connect scanner."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Callable, Iterable, Sequence

from portwatch.banner import build_http_probe, identify_service
from portwatch.banner import grab_banner as _grab_banner
from portwatch.models import PortResult, RemoteScanResult, ScanEvent
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
    resolve_all: bool = False,
    on_event: Callable[[ScanEvent], None] | None = None,
) -> list[RemoteScanResult]:
    """Scan each target's ports concurrently and group results per host.

    Each target is resolved once; every port is then probed against the
    resolved address, so DNS is queried a single time per host regardless of
    port count. By default only the first resolved address is scanned; pass
    ``resolve_all=True`` to probe *every* address a hostname maps to (A and
    AAAA records alike), which yields one :class:`RemoteScanResult` per
    address sharing the same ``host``. ``concurrency`` bounds the number of
    in-flight connection attempts and ``timeout`` limits each individual TCP
    connect (and banner read). With ``probe=True`` an HTTP HEAD request is
    sent before reading the banner so silent services (e.g. web servers) can
    be identified. Unresolvable hostnames are reported with no open ports.

    If ``on_event`` is provided it is called synchronously with a
    :class:`ScanEvent` as the scan progresses: a ``start`` event once at the
    beginning, a ``resolve`` event per target, a ``progress`` event after
    every port probe, an ``open`` event for each open port, and a final
    ``done`` event. Because asyncio runs on a single thread the callback is
    never invoked concurrently.
    """
    if concurrency < 1:
        raise ValueError("concurrency must be >= 1")
    if timeout <= 0:
        raise ValueError("timeout must be > 0")
    semaphore = asyncio.Semaphore(concurrency)

    def emit(event: ScanEvent) -> None:
        if on_event is not None:
            on_event(event)

    emit(ScanEvent(kind="start", targets=len(targets), ports=len(ports)))

    # Phase 1: resolve every target up front so the progress total is exact.
    resolved_units: list[tuple[str, str | None]] = []
    for target in targets:
        host_key = target.raw if not target.is_ip else target.host
        addresses = await _resolve_addresses(target)
        emit(
            ScanEvent(
                kind="resolve",
                host=host_key,
                resolved_ip=addresses[0] if addresses else None,
                addresses=len(addresses),
            )
        )
        if not addresses:
            resolved_units.append((host_key, None))
        elif resolve_all:
            resolved_units.extend((host_key, address) for address in addresses)
        else:
            resolved_units.append((host_key, addresses[0]))

    scannable = [unit for unit in resolved_units if unit[1] is not None]
    total_planned = len(scannable) * len(ports)
    scanned = 0  # mutated from probes; asyncio is single-threaded so this is safe.
    open_count = 0

    async def scan_unit(host_key: str, address: str) -> RemoteScanResult:
        nonlocal scanned, open_count

        async def probe_one(port: int) -> PortResult:
            nonlocal scanned, open_count
            result = await _probe_port(address, port, timeout, semaphore, grab_banner, probe)
            scanned += 1
            emit(
                ScanEvent(
                    kind="progress",
                    host=host_key,
                    resolved_ip=address,
                    port=result.port,
                    scanned=scanned,
                    total=total_planned,
                )
            )
            if result.open:
                open_count += 1
                emit(
                    ScanEvent(
                        kind="open",
                        host=host_key,
                        resolved_ip=address,
                        port=result.port,
                        service=result.service,
                        banner=result.banner,
                        open_count=open_count,
                    )
                )
            return result

        results = await asyncio.gather(*(probe_one(port) for port in ports))
        open_ports = [result for result in results if result.open]
        open_ports.sort(key=lambda r: r.port)
        return RemoteScanResult(
            host=host_key,
            resolved_ip=address,
            ports_scanned=len(ports),
            open_ports=open_ports,
        )

    async def scan_unit_or_empty(host_key: str, address: str | None) -> RemoteScanResult:
        if address is None:
            return RemoteScanResult(
                host=host_key, resolved_ip=None, ports_scanned=len(ports), open_ports=[]
            )
        return await scan_unit(host_key, address)

    results = list(
        await asyncio.gather(*(scan_unit_or_empty(h, a) for h, a in resolved_units))
    )
    emit(
        ScanEvent(
            kind="done",
            scanned=scanned,
            total=total_planned,
            open_count=open_count,
            targets=len(targets),
            ports=len(ports),
        )
    )
    return results


def scan_targets_sync(
    targets: Iterable[Target],
    ports: Sequence[int],
    concurrency: int = 100,
    timeout: float = 2.0,
    grab_banner: bool = True,
    probe: bool = False,
    resolve_all: bool = False,
    on_event: Callable[[ScanEvent], None] | None = None,
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
            resolve_all=resolve_all,
            on_event=on_event,
        )
    )
