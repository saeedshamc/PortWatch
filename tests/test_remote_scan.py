"""Tests for the asynchronous remote scanner against real local listeners."""

import asyncio
import socket
import threading
from contextlib import closing

import pytest

from portwatch.models import PortResult
from portwatch.remote_scan import _probe_port, scan_remote, scan_targets_sync
from portwatch.targets import expand_targets


def _listener() -> tuple[socket.socket, int]:
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    return server, server.getsockname()[1]


def _accept_and_close(server: socket.socket) -> None:
    def run():
        try:
            conn, _ = server.accept()
            conn.close()
        except OSError:
            pass

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


class TestScanTargetsSync:
    def test_finds_open_port_and_filters_closed(self):
        server, port = _listener()
        try:
            thread = _accept_and_close(server)
            results = scan_targets_sync(
                expand_targets(["127.0.0.1"]),
                [port, port + 1],
                concurrency=10,
                timeout=2.0,
                grab_banner=False,
            )
            thread.join(timeout=5)
            result = results[0]
            assert result.ports_scanned == 2
            assert result.resolved_ip == "127.0.0.1"
            assert [p.port for p in result.open_ports] == [port]
            assert result.open_ports[0].open is True
        finally:
            server.close()

    def test_hostname_target_reports_host_key(self):
        server, port = _listener()
        try:
            thread = _accept_and_close(server)
            results = scan_targets_sync(
                expand_targets(["localhost"]),
                [port],
                concurrency=5,
                timeout=2.0,
                grab_banner=False,
            )
            thread.join(timeout=5)
            result = results[0]
            assert result.host == "localhost"
            assert result.resolved_ip is not None
            # Only the first resolved address is probed; the listener above
            # is IPv4, so the port must be open whenever that address won.
            if result.resolved_ip == "127.0.0.1":
                assert [p.port for p in result.open_ports] == [port]
        finally:
            server.close()

    def test_all_closed_ports_yield_empty_open_list(self):
        results = scan_targets_sync(
            expand_targets(["127.0.0.1"]),
            [1],
            concurrency=5,
            timeout=1.0,
            grab_banner=False,
        )
        assert results[0].open_ports == []
        assert results[0].ports_scanned == 1

    def test_multiple_targets_keep_order(self):
        server, port = _listener()
        try:
            thread = _accept_and_close(server)
            results = scan_targets_sync(
                expand_targets(["127.0.0.1", "localhost"]),
                [port],
                concurrency=10,
                timeout=2.0,
                grab_banner=False,
            )
            thread.join(timeout=5)
            assert [r.host for r in results] == ["127.0.0.1", "localhost"]
            assert {r.host for r in results if r.open_ports} == {"127.0.0.1"}
        finally:
            server.close()

    def test_unresolvable_host_reports_nothing_open(self):
        results = scan_targets_sync(
            expand_targets(["no-such-host.invalid"]),
            [80],
            concurrency=5,
            timeout=1.0,
            grab_banner=False,
        )
        assert results[0].resolved_ip is None
        assert results[0].open_ports == []


class TestResolveAll:
    def test_resolve_all_scans_every_address(self):
        # localhost resolves to both 127.0.0.1 and ::1; bind only the IPv4
        # listener so only that address reports the open port.
        server, port = _listener()
        try:
            thread = _accept_and_close(server)
            results = scan_targets_sync(
                expand_targets(["localhost"]),
                [port],
                concurrency=10,
                timeout=2.0,
                grab_banner=False,
                resolve_all=True,
            )
            thread.join(timeout=5)
            # One result per resolved address, all labelled with the hostname.
            assert len(results) == 2
            assert {r.host for r in results} == {"localhost"}
            assert {r.resolved_ip for r in results} == {"127.0.0.1", "::1"}
            # The IPv4 listener is open on 127.0.0.1; ::1 has nothing.
            by_ip = {r.resolved_ip: r for r in results}
            assert [p.port for p in by_ip["127.0.0.1"].open_ports] == [port]
            assert by_ip["::1"].open_ports == []
        finally:
            server.close()

    def test_default_scans_only_first_address(self):
        server, port = _listener()
        try:
            thread = _accept_and_close(server)
            results = scan_targets_sync(
                expand_targets(["localhost"]),
                [port],
                concurrency=10,
                timeout=2.0,
                grab_banner=False,
                resolve_all=False,
            )
            thread.join(timeout=5)
            # Exactly one result regardless of how many addresses exist.
            assert len(results) == 1
            assert results[0].host == "localhost"
            assert results[0].resolved_ip is not None
        finally:
            server.close()

    def test_resolve_all_ip_target_is_single_result(self):
        results = scan_targets_sync(
            expand_targets(["127.0.0.1"]),
            [1],
            concurrency=5,
            timeout=0.5,
            grab_banner=False,
            resolve_all=True,
        )
        # An IP literal has exactly one address, so resolve_all changes nothing.
        assert len(results) == 1
        assert results[0].resolved_ip == "127.0.0.1"


class TestScanEvents:
    def test_event_kinds_and_order(self):
        server, port = _listener()
        try:
            thread = _accept_and_close(server)
            events = []
            scan_targets_sync(
                expand_targets(["127.0.0.1"]),
                [port, port + 1],
                concurrency=10,
                timeout=2.0,
                grab_banner=False,
                on_event=events.append,
            )
            thread.join(timeout=5)
            kinds = [e.kind for e in events]
            assert kinds[0] == "start"
            assert kinds[-1] == "done"
            assert "resolve" in kinds
            assert "progress" in kinds
            # One progress event per probed port (2 ports).
            assert sum(1 for k in kinds if k == "progress") == 2
            # The open listener must produce exactly one "open" event.
            assert sum(1 for k in kinds if k == "open") == 1
            start = events[0]
            assert start.targets == 1 and start.ports == 2
            done = events[-1]
            assert done.scanned == 2 and done.open_count == 1 and done.total == 2
        finally:
            server.close()

    def test_no_callback_still_scans(self):
        server, port = _listener()
        try:
            thread = _accept_and_close(server)
            results = scan_targets_sync(
                expand_targets(["127.0.0.1"]),
                [port],
                concurrency=5,
                timeout=2.0,
                grab_banner=False,
                on_event=None,
            )
            thread.join(timeout=5)
            assert results[0].open_ports
        finally:
            server.close()

    def test_unresolvable_emits_resolve_with_none_ip(self):
        events = []
        scan_targets_sync(
            expand_targets(["no-such-host.invalid"]),
            [80],
            concurrency=5,
            timeout=1.0,
            grab_banner=False,
            on_event=events.append,
        )
        resolve = next(e for e in events if e.kind == "resolve")
        assert resolve.resolved_ip is None
        assert resolve.host == "no-such-host.invalid"
        # No ports were probed, so no progress events fired.
        assert not [e for e in events if e.kind == "progress"]


class TestScanRemoteAsync:
    def test_concurrency_limit_respected(self):
        server, port = _listener()
        peak = 0
        current = 0
        lock = threading.Lock()

        def handler():
            nonlocal peak, current
            try:
                while True:
                    server.settimeout(0.5)
                    try:
                        conn, _ = server.accept()
                    except TimeoutError:
                        break
                    with lock:
                        current += 1
                        peak = max(peak, current)
                    conn.close()
                    with lock:
                        current -= 1
            except OSError:
                pass

        thread = threading.Thread(target=handler, daemon=True)
        thread.start()
        try:
            asyncio.run(
                scan_remote(
                    expand_targets(["127.0.0.1"]),
                    [port] * 20,
                    concurrency=3,
                    timeout=2.0,
                    grab_banner=False,
                )
            )
            thread.join(timeout=10)
            assert peak <= 3
        finally:
            server.close()

    def test_invalid_concurrency_raises(self):
        with pytest.raises(ValueError):
            asyncio.run(
                scan_remote(
                    expand_targets(["127.0.0.1"]),
                    [80],
                    concurrency=0,
                    timeout=1.0,
                )
            )

    def test_invalid_timeout_raises(self):
        with pytest.raises(ValueError):
            asyncio.run(
                scan_remote(
                    expand_targets(["127.0.0.1"]),
                    [80],
                    concurrency=1,
                    timeout=0.0,
                )
            )


class TestProbePort:
    def test_closed_port_returns_refused_error(self):
        with closing(socket.socket()) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]  # unbound: nothing listening

        async def run():
            return await _probe_port(
                "127.0.0.1", port, timeout=1.0, semaphore=asyncio.Semaphore(2),
                grab_banner=False, probe=False,
            )

        result = asyncio.run(run())
        assert result.open is False
        assert result.error is not None

    def test_open_port_reports_open_without_banner(self):
        server, port = _listener()
        try:
            thread = _accept_and_close(server)

            async def run():
                return await _probe_port(
                    "127.0.0.1", port, timeout=2.0, semaphore=asyncio.Semaphore(2),
                    grab_banner=False, probe=False,
                )

            result = asyncio.run(run())
            thread.join(timeout=5)
            assert isinstance(result, PortResult)
            assert result.open is True
            assert result.banner is None
        finally:
            server.close()
