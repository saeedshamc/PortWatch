"""Tests for local listening-socket enumeration."""

import socket
import threading

import psutil

from portwatch.local_scan import LocalScanError, scan_local_ports
from portwatch.models import PortRecord


def _listener():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    return server, server.getsockname()[1]


class TestScanLocalPorts:
    def test_reports_own_test_listener(self):
        server, port = _listener()
        try:
            records = scan_local_ports(protocol="tcp")
            mine = [r for r in records if r.local_port == port and r.local_address == "127.0.0.1"]
            assert mine, f"listener on {port} not found among {len(records)} records"
            record = mine[0]
            assert record.protocol == "TCP"
            assert record.pid == psutil.Process().pid
            assert record.process_name
        finally:
            server.close()

    def test_protocol_filter_tcp_excludes_udp(self):
        records = scan_local_ports(protocol="tcp")
        assert all(r.protocol == "TCP" for r in records)

    def test_inet_includes_both_protocols(self):
        tcp = scan_local_ports(protocol="tcp")
        inet = scan_local_ports(protocol="inet")
        assert len(inet) >= len(tcp)

    def test_unsupported_protocol_raises(self):
        try:
            scan_local_ports(protocol="sctp")
        except LocalScanError as exc:
            assert "unsupported" in str(exc)
        else:
            raise AssertionError("expected LocalScanError")

    def test_record_shape(self):
        records = scan_local_ports(protocol="tcp")
        assert records
        record = records[0]
        assert isinstance(record, PortRecord)
        assert 1 <= record.local_port <= 65535
