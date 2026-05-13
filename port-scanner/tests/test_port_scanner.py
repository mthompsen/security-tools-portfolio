"""Unit tests for port_scanner.

Tests focus on port parsing logic, service mapping, and async scanning
behavior using a local test server to validate connection handling without
external network dependencies.
"""

from __future__ import annotations

import asyncio

import port_scanner
import pytest

# ----------------------------------------------------------------------------
# Port specification parsing
# ----------------------------------------------------------------------------


class TestParsePortSpec:
    def test_single_port(self):
        assert port_scanner.parse_port_spec("80") == [80]

    def test_comma_separated_list(self):
        assert port_scanner.parse_port_spec("22,80,443") == [22, 80, 443]

    def test_simple_range(self):
        assert port_scanner.parse_port_spec("1-5") == [1, 2, 3, 4, 5]

    def test_mixed_range_and_list(self):
        result = port_scanner.parse_port_spec("22,80-82,443")
        assert result == [22, 80, 81, 82, 443]

    def test_deduplicates_overlapping(self):
        result = port_scanner.parse_port_spec("80,80-82,81")
        assert result == [80, 81, 82]

    def test_sorts_output(self):
        result = port_scanner.parse_port_spec("443,22,80")
        assert result == [22, 80, 443]

    def test_handles_whitespace(self):
        result = port_scanner.parse_port_spec(" 22 , 80 , 443 ")
        assert result == [22, 80, 443]

    def test_rejects_zero(self):
        with pytest.raises(ValueError):
            port_scanner.parse_port_spec("0")

    def test_rejects_above_65535(self):
        with pytest.raises(ValueError):
            port_scanner.parse_port_spec("70000")

    def test_rejects_inverted_range(self):
        with pytest.raises(ValueError):
            port_scanner.parse_port_spec("100-50")

    def test_rejects_non_numeric(self):
        with pytest.raises(ValueError):
            port_scanner.parse_port_spec("abc")


# ----------------------------------------------------------------------------
# Target resolution
# ----------------------------------------------------------------------------


class TestResolveTarget:
    def test_accepts_ipv4_literal(self):
        assert port_scanner.resolve_target("127.0.0.1") == "127.0.0.1"

    def test_accepts_localhost_hostname(self):
        # localhost should resolve consistently
        resolved = port_scanner.resolve_target("localhost")
        assert resolved in ("127.0.0.1", "::1")

    def test_rejects_invalid_hostname(self):
        # Use a deliberately invalid TLD that no DNS would resolve
        with pytest.raises(ValueError):
            port_scanner.resolve_target("this-host-does-not-exist-at-all.invalid")


# ----------------------------------------------------------------------------
# Service mapping
# ----------------------------------------------------------------------------


class TestServiceMapping:
    @pytest.mark.parametrize(
        "port,expected",
        [
            (22, "SSH"),
            (80, "HTTP"),
            (443, "HTTPS"),
            (3306, "MySQL"),
            (3389, "RDP"),
            (5432, "PostgreSQL"),
            (6379, "Redis"),
        ],
    )
    def test_known_ports_map_correctly(self, port, expected):
        assert port_scanner.COMMON_SERVICES[port] == expected

    def test_unknown_port_not_in_mapping(self):
        # Port 12345 is not in the well-known services list
        assert 12345 not in port_scanner.COMMON_SERVICES


# ----------------------------------------------------------------------------
# Async scanning behavior
# ----------------------------------------------------------------------------


@pytest.fixture
async def echo_server():
    """Start a local TCP echo server on a random port for testing."""
    server = await asyncio.start_server(
        lambda r, w: w.close(),  # immediately close
        host="127.0.0.1",
        port=0,  # OS-assigned
    )
    port = server.sockets[0].getsockname()[1]
    yield port
    server.close()
    await server.wait_closed()


class TestScanPort:
    @pytest.mark.asyncio
    async def test_open_port_detected(self, echo_server):
        port = echo_server
        sem = asyncio.Semaphore(1)
        result = await port_scanner.scan_port(
            "127.0.0.1",
            port,
            timeout=2.0,
            sem=sem,
            banner_grab=False,
        )
        assert result.state == "open"
        assert result.port == port

    @pytest.mark.asyncio
    async def test_closed_port_detected(self):
        # Port 1 is reserved and should be closed/refused on any sane system
        sem = asyncio.Semaphore(1)
        result = await port_scanner.scan_port(
            "127.0.0.1",
            1,
            timeout=2.0,
            sem=sem,
            banner_grab=False,
        )
        # Either closed (ECONNREFUSED) or filtered (no response) is acceptable
        assert result.state in ("closed", "filtered")

    @pytest.mark.asyncio
    async def test_timeout_classified_as_filtered(self, monkeypatch):
        """Force a timeout by monkey-patching asyncio.open_connection."""

        async def fake_open_connection(*args, **kwargs):
            await asyncio.sleep(10)  # longer than test timeout

        monkeypatch.setattr(
            "port_scanner.asyncio.open_connection",
            fake_open_connection,
        )

        sem = asyncio.Semaphore(1)
        result = await port_scanner.scan_port(
            "127.0.0.1",
            9999,
            timeout=0.05,
            sem=sem,
            banner_grab=False,
        )
        assert result.state == "filtered"


class TestScanHost:
    @pytest.mark.asyncio
    async def test_scan_multiple_ports(self, echo_server):
        # Scan the open port plus some likely-closed ones
        open_port = echo_server
        results = await port_scanner.scan_host(
            host="127.0.0.1",
            ports=[open_port, 1, 2],
            timeout=1.0,
            concurrency=10,
            banner_grab=False,
        )
        assert len(results) == 3
        open_results = [r for r in results if r.state == "open"]
        assert len(open_results) == 1
        assert open_results[0].port == open_port

    @pytest.mark.asyncio
    async def test_concurrency_limit_respected(self):
        # This is a smoke test; we just verify it doesn't crash with a
        # concurrency limit lower than the port count
        results = await port_scanner.scan_host(
            host="127.0.0.1",
            ports=[1, 2, 3, 4, 5],
            timeout=0.5,
            concurrency=2,
            banner_grab=False,
        )
        assert len(results) == 5


# ----------------------------------------------------------------------------
# Top-ports list integrity
# ----------------------------------------------------------------------------


class TestTopPorts:
    def test_top_100_contains_common_ports(self):
        # Sanity check: the top-100 list should include the obvious ones
        for port in (22, 80, 443, 3389):
            assert port in port_scanner.NMAP_TOP_100

    def test_top_100_all_valid_ports(self):
        for port in port_scanner.NMAP_TOP_100:
            assert 1 <= port <= 65535
