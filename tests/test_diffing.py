"""Tests for saved-scan diffing."""

import json

import pytest

from portwatch.diffing import (
    DiffError,
    ScanDiff,
    compare_files,
    diff_scans,
    exit_code_for,
    load_scan,
    render_diff_table,
)


def write_remote(path, host, ports):
    payload = [
        {
            "host": host,
            "resolved_ip": "127.0.0.1",
            "ports_scanned": 100,
            "open_ports": [
                {"host": host, "port": port, "open": True, "error": None,
                 "banner": banner, "service": service}
                for port, service, banner in ports
            ],
        }
    ]
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def write_local(path, ports):
    payload = [
        {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": port,
         "pid": 4, "process_name": name, "executable": exe, "command_line": None}
        for port, name, exe in ports
    ]
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class TestLoadScan:
    def test_remote_scan_indexed_by_port(self, tmp_path):
        path = write_remote(tmp_path / "old.json", "10.0.0.5",
                            [(22, "ssh", "SSH-2.0"), (80, "http", None)])
        label, ports = load_scan(str(path))
        assert label == "10.0.0.5"
        assert set(ports) == {22, 80}
        assert ports[22]["service"] == "ssh"

    def test_local_scan_flat_array(self, tmp_path):
        path = write_local(tmp_path / "old.json", [(445, "srv", None)])
        label, ports = load_scan(str(path))
        assert label == "local"
        assert set(ports) == {445}
        assert "srv" in ports[445]["service"]

    def test_missing_file(self, tmp_path):
        with pytest.raises(DiffError, match="cannot read"):
            load_scan(str(tmp_path / "nope.json"))

    def test_invalid_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(DiffError, match="not valid JSON"):
            load_scan(str(path))

    def test_non_array_root(self, tmp_path):
        path = tmp_path / "obj.json"
        path.write_text('{"host": "x"}', encoding="utf-8")
        with pytest.raises(DiffError, match="JSON array"):
            load_scan(str(path))

    def test_unrecognized_records(self, tmp_path):
        path = tmp_path / "empty.json"
        path.write_text("[]", encoding="utf-8")
        with pytest.raises(DiffError, match="no recognizable"):
            load_scan(str(path))

    def test_multi_target_file_rejected(self, tmp_path):
        path = tmp_path / "two.json"
        path.write_text(
            json.dumps([
                {"host": "a", "open_ports": []},
                {"host": "b", "open_ports": []},
            ]),
            encoding="utf-8",
        )
        with pytest.raises(DiffError, match="one host per file"):
            load_scan(str(path))


class TestDiffScans:
    def test_opened_closed_unchanged(self):
        old = ("h", {22: {"service": "ssh"}, 80: {"service": "http"}, 445: {"service": "smb"}})
        new = ("h", {22: {"service": "ssh"}, 8080: {"service": "http"}, 445: {"service": "smb"}})
        diff = diff_scans(old, new)
        assert [i["port"] for i in diff.opened] == [8080]
        assert [i["port"] for i in diff.closed] == [80]
        assert [i["port"] for i in diff.unchanged] == [22, 445]
        assert diff.changed_service == []
        assert diff.has_changes is True

    def test_service_change_detected(self):
        old = ("h", {8080: {"service": "http"}})
        new = ("h", {8080: {"service": "redis"}})
        diff = diff_scans(old, new)
        assert diff.changed_service == [
            {"port": 8080, "old_service": "http", "new_service": "redis"}
        ]
        assert diff.has_changes is True

    def test_identical_scans_no_changes(self):
        old = ("h", {22: {"service": "ssh"}})
        diff = diff_scans(old, old)
        assert diff.has_changes is False
        assert diff.unchanged[0]["port"] == 22

    def test_ports_sorted_in_output(self):
        old = ("h", {})
        new = ("h", {9000: {"service": None}, 21: {"service": "ftp"}})
        diff = diff_scans(old, new)
        assert [i["port"] for i in diff.opened] == [21, 9000]

    def test_as_dict_shape(self):
        old = ("h", {80: {"service": "http"}})
        new = ("h", {})
        payload = diff_scans(old, new).as_dict()
        assert payload["closed"] == [{"port": 80, "service": "http", "banner": None}]
        assert payload["unchanged_count"] == 0
        assert payload["host"] == "h"


class TestCompareFiles:
    def test_end_to_end_remote(self, tmp_path):
        old = write_remote(tmp_path / "old.json", "10.0.0.5",
                           [(22, "ssh", "SSH-2.0"), (80, "http", None)])
        new = write_remote(tmp_path / "new.json", "10.0.0.5", [(22, "ssh", "SSH-2.0")])
        diff = compare_files(str(old), str(new))
        assert diff.host == "10.0.0.5"
        assert [i["port"] for i in diff.closed] == [80]

    def test_local_files_diff(self, tmp_path):
        old = write_local(tmp_path / "old.json", [(445, "srv", None)])
        new = write_local(tmp_path / "new.json", [(445, "srv", None), (3389, "rdp", None)])
        diff = compare_files(str(old), str(new))
        assert diff.host == "local"
        assert [i["port"] for i in diff.opened] == [3389]

    def test_different_hosts_rejected(self, tmp_path):
        old = write_remote(tmp_path / "old.json", "10.0.0.5", [(22, "ssh", None)])
        new = write_remote(tmp_path / "new.json", "10.0.0.9", [(22, "ssh", None)])
        with pytest.raises(DiffError, match="different hosts"):
            compare_files(str(old), str(new))

    def test_local_vs_remote_allowed(self, tmp_path):
        old = write_local(tmp_path / "old.json", [(80, "srv", None)])
        new = write_remote(tmp_path / "new.json", "10.0.0.5", [(80, "http", None)])
        diff = compare_files(str(old), str(new))
        assert [i["port"] for i in diff.opened] == []


class TestRenderingAndExitCode:
    def test_table_contains_sections_and_summary(self):
        diff = ScanDiff(host="h",
                        opened=[{"port": 8080, "service": "http", "banner": None}],
                        closed=[{"port": 22, "service": "ssh", "banner": None}],
                        unchanged=[{"port": 445, "service": "smb", "banner": None}])
        text = render_diff_table(diff)
        assert "NEWLY OPENED:" in text and "NEWLY CLOSED:" in text
        assert "8080" in text and "22" in text
        assert "1 opened, 1 closed" in text

    def test_exit_codes(self):
        diff = ScanDiff(host="h", opened=[{"port": 1}])
        assert exit_code_for(diff) == 2
        clean = ScanDiff(host="h", unchanged=[{"port": 1}])
        assert exit_code_for(clean) == 0
