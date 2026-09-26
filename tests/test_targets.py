"""Tests for port specification and target parsing."""

import pytest

from portwatch.targets import (
    MAX_CIDR_HOSTS,
    TargetError,
    expand_targets,
    parse_port_spec,
)


class TestParsePortSpec:
    def test_single_port(self):
        assert parse_port_spec("80") == [80]

    def test_range(self):
        assert parse_port_spec("80-83") == [80, 81, 82, 83]

    def test_mixed_list_is_sorted_and_deduplicated(self):
        assert parse_port_spec("8080,80,443,80") == [80, 443, 8080]

    def test_whitespace_tolerated(self):
        assert parse_port_spec(" 80 , 81 - 82 ") == [80, 81, 82]

    def test_full_range_bounds(self):
        assert parse_port_spec("1-65535") == list(range(1, 65536))

    @pytest.mark.parametrize(
        "bad",
        ["", "0", "65536", "abc", "10-1", "80-", "-80", "80-65536"],
    )
    def test_invalid_specs_raise(self, bad):
        with pytest.raises(TargetError):
            parse_port_spec(bad)


class TestExpandTargets:
    def test_single_ip(self):
        targets = expand_targets(["10.0.0.1"])
        assert len(targets) == 1
        assert targets[0].host == "10.0.0.1"
        assert targets[0].is_ip is True

    def test_hostname_is_not_treated_as_ip(self):
        targets = expand_targets(["myserver.local"])
        assert targets[0].is_ip is False
        assert targets[0].host == "myserver.local"

    def test_ipv6_address(self):
        targets = expand_targets(["::1"])
        assert targets[0].host == "::1"
        assert targets[0].is_ip is True

    def test_cidr_expands_to_hosts(self):
        targets = expand_targets(["192.168.1.0/30"])
        assert [t.host for t in targets] == ["192.168.1.1", "192.168.1.2"]

    def test_cidr_duplicates_removed_preserving_order(self):
        targets = expand_targets(["10.0.0.1", "10.0.0.1", "10.0.0.1/32"])
        hosts = [t.host for t in targets]
        assert hosts == ["10.0.0.1"]

    def test_oversized_cidr_is_rejected(self):
        with pytest.raises(TargetError, match="refusing"):
            expand_targets(["10.0.0.0/8"], max_cidr_hosts=MAX_CIDR_HOSTS)

    def test_oversized_cidr_allowed_with_higher_cap(self):
        targets = expand_targets(["10.1.0.0/16"], max_cidr_hosts=70000)
        assert len(targets) == 65534

    def test_invalid_cidr_raises(self):
        with pytest.raises(TargetError):
            expand_targets(["10.0.0.0/99"])

    def test_empty_input_raises(self):
        with pytest.raises(TargetError):
            expand_targets([])
