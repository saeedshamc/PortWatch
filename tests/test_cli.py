"""Tests for the command-line interface."""

import io
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from portwatch.cli import build_parser, main


@pytest.fixture()
def http_port():
    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


class TestParser:
    def test_defaults(self):
        args = build_parser().parse_args([])
        assert args.mode == "local"
        assert args.output_format == "table"
        assert args.protocol == "inet"
        assert args.concurrency == 100
        assert args.timeout == 2.0
        assert args.probe is False
        assert args.targets == []

    def test_remote_flags_parse(self):
        args = build_parser().parse_args(
            ["--mode", "remote", "10.0.0.1", "10.0.0.0/30",
             "-p", "80,443", "-c", "50", "-t", "1.5", "--probe", "-f", "json"]
        )
        assert args.mode == "remote"
        assert args.targets == ["10.0.0.1", "10.0.0.0/30"]
        assert args.ports == "80,443"
        assert args.concurrency == 50
        assert args.timeout == 1.5
        assert args.probe is True
        assert args.output_format == "json"

    def test_bad_mode_rejected(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--mode", "wizard"])

    def test_timeout_must_be_finite(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["--mode", "remote", "127.0.0.1", "-p", "80", "-t", "nan"])
        assert excinfo.value.code == 2
        assert "finite" in capsys.readouterr().err

    def test_timeout_must_be_positive(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["--mode", "remote", "127.0.0.1", "-p", "80", "-t", "-1"])
        assert excinfo.value.code == 2
        assert "positive" in capsys.readouterr().err

    def test_remote_requires_targets(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["--mode", "remote"])
        assert excinfo.value.code == 2
        assert "target" in capsys.readouterr().err


class TestLocalMode:
    def test_table_output_mentions_protocols(self, capsys):
        assert main(["--protocol", "tcp"]) == 0
        out = capsys.readouterr().out
        assert "PROTO" in out and "PID" in out

    def test_json_output_is_valid(self, capsys):
        assert main(["--protocol", "tcp", "-f", "json"]) == 0
        records = json.loads(capsys.readouterr().out)
        assert isinstance(records, list)
        assert all("local_port" in record for record in records)


class TestRemoteMode:
    def test_table_finds_http_service(self, http_port, capsys):
        code = main(["--mode", "remote", "127.0.0.1", "-p", str(http_port),
                     "--probe", "-c", "10", "-t", "2"])
        assert code == 0
        out = capsys.readouterr().out
        assert "http" in out
        assert "1 port(s) scanned, 1 open" in out

    def test_json_finds_open_port(self, http_port, capsys):
        code = main(["--mode", "remote", "127.0.0.1", "-p", str(http_port),
                     "-f", "json", "-c", "10", "-t", "2"])
        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload[0]["host"] == "127.0.0.1"
        assert payload[0]["ports_scanned"] == 1
        assert payload[0]["open_ports"][0]["port"] == http_port
        assert payload[0]["open_ports"][0]["open"] is True

    def test_bad_port_spec_exit_code(self, capsys):
        assert main(["--mode", "remote", "127.0.0.1", "-p", "99999"]) == 2
        assert "error" in capsys.readouterr().err.lower()

    def test_invalid_cidr_exit_code(self, capsys):
        assert main(["--mode", "remote", "300.300.300.300/24"]) == 2
        assert "error" in capsys.readouterr().err.lower()


class TestOutputFile:
    def test_json_file_is_utf8_lf(self, tmp_path, capsys, http_port):
        target = tmp_path / "out.json"
        code = main(["--mode", "remote", "127.0.0.1", "-p", str(http_port),
                     "--probe", "-f", "json", "-o", str(target)])
        assert code == 0
        data = target.read_bytes()
        assert b"\r\n" not in data
        payload = json.loads(data.decode("utf-8"))
        assert payload[0]["open_ports"][0]["port"] == http_port

    def test_table_file_matches_console(self, tmp_path, capsys):
        target = tmp_path / "out.txt"
        code = main(["--protocol", "tcp", "-o", str(target)])
        assert code == 0
        data = target.read_bytes()
        assert b"\r\n" not in data
        assert "PROTO" in data.decode("utf-8")
        assert "PROTO" in capsys.readouterr().out

    def test_console_receives_output_alongside_file(self, tmp_path, capsys):
        target = tmp_path / "out.txt"
        code = main(["--protocol", "tcp", "-o", str(target)])
        assert code == 0
        assert capsys.readouterr().out.strip()

    def test_unwritable_path_exits_cleanly(self, tmp_path, capsys):
        blocker = tmp_path / "file.txt"
        blocker.write_text("blocker", encoding="utf-8")
        target = blocker / "nested" / "out.txt"  # parent is a file
        with pytest.raises(SystemExit) as excinfo:
            main(["--protocol", "tcp", "-o", str(target)])
        assert excinfo.value.code == 2
        assert "cannot write" in capsys.readouterr().err


class TestOutputEncoding:
    class _Cp437Stream(io.StringIO):
        """String stream that pretends to use a legacy Windows codepage."""

        encoding = "cp437"

    def test_unencodable_banner_is_replaced_not_fatal(self):
        from portwatch.cli import _write

        stream = self._Cp437Stream()
        _write("banner \ufffd\ufffd end", stream=stream)
        assert "\ufffd" not in stream.getvalue()
        assert "??" in stream.getvalue()

    def test_encodable_text_passes_through(self):
        from portwatch.cli import _write

        stream = self._Cp437Stream()
        _write("plain ascii banner", stream=stream)
        assert stream.getvalue() == "plain ascii banner\n"
