"""Tests for banner grabbing and service identification."""

import asyncio

import pytest

from portwatch.banner import MAX_BANNER_LENGTH, build_http_probe, grab_banner, identify_service


class FakeReader:
    """Mimics asyncio.StreamReader for grab_banner tests."""

    def __init__(self, *chunks: bytes):
        self._chunks = list(chunks)

    async def read(self, size: int) -> bytes:
        if self._chunks:
            return self._chunks.pop(0)
        await asyncio.sleep(3600)  # simulate a silent server
        return b""


class TestIdentifyService:
    @pytest.mark.parametrize(
        ("banner", "expected"),
        [
            ("SSH-2.0-OpenSSH_9.6", "ssh"),
            ("HTTP/1.1 200 OK", "http"),
            ("220 ProFTPD Server ready", "ftp"),
            ("220 mail.example.com ESMTP Postfix", "smtp"),
            ("+OK POP3 server ready", "pop3"),
            ("* OK IMAP4rev1 ready", "imap"),
            ("RFB 003.008", "vnc"),
            ("-ERR unknown command", "redis"),
        ],
    )
    def test_banner_patterns(self, banner, expected):
        assert identify_service(banner) == expected

    def test_unknown_banner_without_port(self):
        assert identify_service("HELLO WORLD") is None

    def test_none_banner_without_port(self):
        assert identify_service(None) is None

    @pytest.mark.parametrize(
        ("port", "expected"),
        [(22, "ssh"), (80, "http"), (443, "https"), (6379, "redis")],
    )
    def test_port_fallback(self, port, expected):
        assert identify_service(None, port=port) == expected

    def test_banner_beats_port_fallback(self):
        assert identify_service("SSH-2.0-dropbear", port=8080) == "ssh"

    def test_port_fallback_for_unknown_banner(self):
        assert identify_service("GIBBERISH", port=22) == "ssh"


class TestBuildHttpProbe:
    def test_contains_head_request_fields(self):
        probe = build_http_probe("10.0.0.5", 8080).decode("ascii")
        assert probe.startswith("HEAD / HTTP/1.0\r\n")
        assert "Host: 10.0.0.5" in probe
        assert probe.endswith("\r\n\r\n")

    def test_ipv6_host_is_bracketed(self):
        probe = build_http_probe("::1", 80).decode("ascii")
        assert "Host: [::1]" in probe


class TestGrabBanner:
    def test_reads_and_normalizes_greeting(self):
        banner = asyncio.run(grab_banner(FakeReader(b"SSH-2.0-Test_1.0\r\n"), timeout=1.0))
        assert banner == "SSH-2.0-Test_1.0"

    def test_multiline_banner_collapses_to_one_line(self):
        banner = asyncio.run(
            grab_banner(FakeReader(b"220 host ESMTP\r\n250-EXT\r\n"), timeout=1.0)
        )
        assert banner == "220 host ESMTP 250-EXT"

    def test_binary_payload_becomes_replacement_characters(self):
        banner = asyncio.run(grab_banner(FakeReader(b"\x16\x03\x01\xff\xfe"), timeout=1.0))
        assert banner is not None
        assert "\ufffd" in banner

    def test_oversized_banner_is_truncated(self):
        payload = b"A" * (MAX_BANNER_LENGTH * 4)
        banner = asyncio.run(grab_banner(FakeReader(payload), timeout=1.0))
        assert banner is not None
        assert len(banner) == MAX_BANNER_LENGTH

    def test_silent_server_times_out_to_none(self):
        banner = asyncio.run(grab_banner(FakeReader(), timeout=0.1))
        assert banner is None

    def test_empty_response_is_none(self):
        class EmptyReader(FakeReader):
            async def read(self, size: int) -> bytes:
                return b""

        assert asyncio.run(grab_banner(EmptyReader(), timeout=1.0)) is None
