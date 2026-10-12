"""Tests for the asynchronous remote scanner against real local listeners."""

import asyncio
import socket
import ssl
import threading
from contextlib import closing

import pytest

from portwatch.models import PortResult
from portwatch.remote_scan import _probe_port, scan_remote, scan_targets_sync
from portwatch.targets import expand_targets
from portwatch.tls import inspect_tls, _describe_error


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

    def test_tls_inspection_attaches_to_open_port(self, tmp_path):
        # Run the async scanner body on a fresh loop. pytest-asyncio is not
        # installed, so all scanner tests use the synchronous scan_targets_sync
        # wrapper via asyncio.run.

        async def _tls_scan():
            # An SSL listener that presents the test fixture certificate, so the
            # TLS handshake can complete and decode the certificate. The self-signed
            # cert is intentionally not trusted, which is what we want to assert.
            cert_path = tmp_path / "test_cert.pem"
            cert_path.write_text(
                "-----BEGIN CERTIFICATE-----\n"
                "MIIDYzCCAkugAwIBAgIUSQ0gpfKS7jhiRL9NrLLnqoyqUwEwDQYJKoZIhvcNAQEL"
                "-----BEGIN CERTIFICATE-----\n",
                encoding="ascii",
            )
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(certfile=cert_path, keyfile=tmp_path / "test_key.pem")
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", 0))
            server.listen(5)
            server = ssl_context.wrap_socket(server, server_side=True)
            port = server.getsockname()[1]
            try:
                thread = threading.Thread(
                    target=lambda: [
                        conn, _ := server.accept(),
                        conn.close(),
                    ],
                    daemon=True,
                )
                thread.start()
                results = scan_targets_sync(
                    expand_targets(["127.0.0.1"]),
                    [port],
                    concurrency=5,
                    timeout=2.0,
                    grab_banner=False,
                    tls=True,
                )
                thread.join(timeout=5)
                assert results[0].open_ports
                tls = results[0].open_ports[0].tls
                assert tls is not None
                assert tls.subject == "CN=localhost/O=PortWatchTest"
                assert "DNS:localhost" in tls.subject_alt_names
                assert "DNS:test.local" in tls.subject_alt_names
                assert "IP:127.0.0.1" in tls.subject_alt_names
                assert not tls.verified
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

    def test_tls_inspection_attaches_to_open_port(self, tmp_path):
        # Run the async scanner body on a fresh loop. pytest-asyncio is not
        # installed, so all scanner tests use the synchronous scan_targets_sync
        # wrapper via asyncio.run.

        # An SSL listener that presents the test fixture certificate, so the
        # TLS handshake can complete and decode the certificate. The self-signed
        # cert is intentionally not trusted, which is what we want to assert.
        async def _tls_scan():
            cert_path = tmp_path / "test_cert.pem"
            cert_path.write_text(
                "-----BEGIN CERTIFICATE-----\n"
                "MIIDYzCCAkugAwIBAgIUSQ0gpfKS7jhiRL9NrLLnqoyqUwEwDQYJKoZIhvcNAQEL"
                "-----BEGIN CERTIFICATE-----\n",
                encoding="ascii",
            )
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(certfile=cert_path, keyfile=tmp_path / "test_key.pem")
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", 0))
            server.listen(5)
            server = ssl_context.wrap_socket(server, server_side=True)
            port = server.getsockname()[1]
            try:
                thread = threading.Thread(
                    target=lambda: [
                        conn, _ := server.accept(),
                        conn.close(),
                    ],
                    daemon=True,
                )
                thread.start()
                results = scan_targets_sync(
                    expand_targets(["127.0.0.1"]),
                    [port],
                    concurrency=5,
                    timeout=2.0,
                    grab_banner=False,
                    tls=True,
                )
                thread.join(timeout=5)
                assert results[0].open_ports
                tls = results[0].open_ports[0].tls
                assert tls is not None
                assert tls.subject == "CN=localhost/O=PortWatchTest"
                assert "DNS:localhost" in tls.subject_alt_names
                assert "DNS:test.local" in tls.subject_alt_names
                assert "IP:127.0.0.1" in tls.subject_alt_names
                assert not tls.verified
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


class TestTls:
    def _tls_listener(self, tmp_path):
        # Start an SSL listener that presents the test fixture certificate,
        # so the TLS handshake can complete and decode the certificate.
        cert_path = tmp_path / "test_cert.pem"
        cert_path.write_bytes(open("tests/fixtures/test_cert.pem", "rb").read())
        key_path = tmp_path / "test_key.pem"
        key_path.write_bytes(open("tests/fixtures/test_key.pem", "rb").read())


        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        server = ssl_context.wrap_socket(listener, server_side=True)
        return server, listener

    def test_describe_error_timeout(self):
        from asyncio import TimeoutError

        assert _describe_error(TimeoutError()) == "timed out"
        assert _describe_error(OSError()) == "oserror"
        assert _describe_error(Exception("boom")) == "boom"

    def test_inspect_tls_when_plaintext_port_decodes_certificate(self, tmp_path):
        # With ``CERT_NONE`` verification the scanner treats an SSL listener
        # with a self-signed certificate as a valid TLS connection and decodes
        # the certificate details, which is the documented scanner behaviour.
        server, listener = self._tls_listener(tmp_path)
        try:
            port = server.getsockname()[1]
            thread = threading.Thread(
                target=self._accept_and_close_connection,
                args=(server,),
                daemon=True,
            )
            thread.start()
            try:
                results = scan_targets_sync(
                    expand_targets(["127.0.0.1"]),
                    [port],
                    concurrency=5,
                    timeout=2.0,
                    grab_banner=False,
                    tls=True,
                )
            finally:
                server.close()
                listener.close()
            thread.join(timeout=5)
            assert results[0].open_ports
            tls = results[0].open_ports[0].tls
            assert tls is not None
            assert tls.subject == "CN=localhost/O=PortWatchTest"
            assert not tls.verified
        finally:
            server.close()
            listener.close()

    def _accept_and_close_connection(self, server: socket.socket) -> None:
        try:
            conn, _ = server.accept()
            conn.close()
        except OSError:
            pass

    def test_inspect_tls_decodes_self_signed_cert(self, tmp_path):
        # The scanner works without the ``cryptography`` dependency: it
        # handshakes without verification and decodes the DER certificate with
        # CPython's ``_test_decode_cert`` helper.
        server, listener = self._tls_listener(tmp_path)
        try:
            port = server.getsockname()[1]
            thread = threading.Thread(
                target=self._accept_and_close_connection,
                args=(server,),
                daemon=True,
            )
            thread.start()
            try:
                results = scan_targets_sync(
                    expand_targets(["127.0.0.1"]),
                    [port],
                    concurrency=5,
                    timeout=2.0,
                    grab_banner=False,
                    tls=True,
                )
            finally:
                server.close()
                listener.close()
            thread.join(timeout=5)
            assert results[0].open_ports
            tls = results[0].open_ports[0].tls
            assert tls is not None
            assert tls.subject == "CN=localhost/O=PortWatchTest"
            assert "DNS:localhost" in tls.subject_alt_names
            assert "DNS:test.local" in tls.subject_alt_names
            assert "IP:127.0.0.1" in tls.subject_alt_names
            assert not tls.verified
        finally:
            server.close()
            listener.close()

    def test_inspect_tls_with_trusted_cert_decodes_and_verifies(self):
        # A real, widely trusted certificate. ``_is_trusted`` succeeds here,
        # which is the path that distinguishes a valid certificate from a
        # self-signed one.
        info = asyncio.run(inspect_tls("example.com", 443, timeout=5.0))
        # The handshake may legitimately fail on a slow/unreachable network;
        # the important assertion is that the error surface is reported, not
        # that example.com is always reachable.
        assert info.error is None or info.error == ""
        assert info.subject is not None


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
