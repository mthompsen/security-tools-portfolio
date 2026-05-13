#!/usr/bin/env python3
"""
port_scanner.py - Concurrent TCP port scanner.

Scans a target host (or hosts) for open TCP ports using async I/O for
high concurrency without the overhead of threading. Identifies common
services by port number.

Usage:
  python port_scanner.py <target> [--ports 1-1024 | --top-ports N | --port-list 22,80,443]
                                   [--timeout 1.0]
                                   [--concurrency 500]
                                   [--banner-grab]
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import socket
import sys
import time
from dataclasses import dataclass

# ----------------------------------------------------------------------------
# Common service mappings (port -> well-known service)
# Drawn from IANA assignments; not exhaustive.
# ----------------------------------------------------------------------------

COMMON_SERVICES: dict[int, str] = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-server",
    68: "DHCP-client",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    111: "RPC",
    119: "NNTP",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-ns",
    138: "NetBIOS-dgm",
    139: "NetBIOS-ssn",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    464: "Kerberos-pw",
    465: "SMTPS",
    514: "syslog",
    515: "LPD",
    587: "SMTP-submission",
    631: "IPP",
    636: "LDAPS",
    873: "rsync",
    989: "FTPS-data",
    990: "FTPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle",
    1701: "L2TP",
    1723: "PPTP",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel-SSL",
    2222: "SSH-alt",
    2375: "Docker",
    2376: "Docker-TLS",
    3000: "Node-dev",
    3128: "Squid",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    4444: "Metasploit-default",
    5000: "UPnP/Flask-dev",
    5432: "PostgreSQL",
    5601: "Kibana",
    5672: "AMQP",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    6443: "Kubernetes-API",
    6660: "IRC",
    6661: "IRC",
    6662: "IRC",
    6663: "IRC",
    6664: "IRC",
    6665: "IRC",
    6666: "IRC",
    6667: "IRC",
    6668: "IRC",
    6669: "IRC",
    7000: "Cassandra",
    7001: "WebLogic",
    8000: "HTTP-alt",
    8008: "HTTP-alt",
    8080: "HTTP-proxy",
    8081: "HTTP-alt",
    8086: "InfluxDB",
    8088: "HTTP-alt",
    8443: "HTTPS-alt",
    8888: "HTTP-alt",
    9000: "PHP-FPM/Jenkins",
    9042: "Cassandra-CQL",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9300: "Elasticsearch-node",
    9418: "Git",
    11211: "memcached",
    15672: "RabbitMQ-mgmt",
    27017: "MongoDB",
    27018: "MongoDB-shard",
    50000: "SAP",
    50070: "Hadoop-NN",
    50075: "Hadoop-DN",
}

# nmap's "top 100" most-commonly-open ports (abbreviated)
NMAP_TOP_100 = [
    7,
    9,
    13,
    21,
    22,
    23,
    25,
    26,
    37,
    53,
    79,
    80,
    81,
    88,
    106,
    110,
    111,
    113,
    119,
    135,
    139,
    143,
    144,
    179,
    199,
    389,
    427,
    443,
    444,
    445,
    465,
    513,
    514,
    515,
    543,
    544,
    548,
    554,
    587,
    631,
    646,
    873,
    990,
    993,
    995,
    1025,
    1026,
    1027,
    1028,
    1029,
    1110,
    1433,
    1720,
    1723,
    1755,
    1900,
    2000,
    2001,
    2049,
    2121,
    2717,
    3000,
    3128,
    3306,
    3389,
    3986,
    4899,
    5000,
    5009,
    5051,
    5060,
    5101,
    5190,
    5357,
    5432,
    5631,
    5666,
    5800,
    5900,
    6000,
    6001,
    6646,
    7070,
    8000,
    8008,
    8009,
    8080,
    8081,
    8443,
    8888,
    9100,
    9999,
    10000,
    32768,
    49152,
    49153,
    49154,
    49155,
    49156,
    49157,
]


# ----------------------------------------------------------------------------
# Data types
# ----------------------------------------------------------------------------


@dataclass
class ScanResult:
    port: int
    state: str  # 'open', 'closed', 'filtered'
    service: str | None = None
    banner: str | None = None


# ----------------------------------------------------------------------------
# Port parsing
# ----------------------------------------------------------------------------


def parse_port_spec(spec: str) -> list[int]:
    """Parse a port specification like '22,80,443' or '1-1024' into a list."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end or start < 1 or end > 65535:
                raise ValueError(f"invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if port < 1 or port > 65535:
                raise ValueError(f"invalid port: {port}")
            ports.add(port)
    return sorted(ports)


# ----------------------------------------------------------------------------
# Scanning logic
# ----------------------------------------------------------------------------


async def scan_port(
    host: str,
    port: int,
    timeout: float,
    sem: asyncio.Semaphore,
    banner_grab: bool,
) -> ScanResult:
    """Attempt a TCP connect on host:port. Returns scan state."""
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return ScanResult(port=port, state="filtered")
        except (ConnectionRefusedError, OSError):
            return ScanResult(port=port, state="closed")
        except Exception:
            return ScanResult(port=port, state="filtered")

        banner = None
        if banner_grab:
            try:
                # Some services send a banner immediately; others need a prompt
                banner_bytes = await asyncio.wait_for(reader.read(256), timeout=1.0)
                if banner_bytes:
                    banner = banner_bytes.decode("utf-8", errors="replace").strip()
                    # Truncate to single line
                    if "\n" in banner:
                        banner = banner.split("\n")[0]
                    if len(banner) > 80:
                        banner = banner[:77] + "..."
            except (asyncio.TimeoutError, OSError):
                pass

        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

        return ScanResult(
            port=port,
            state="open",
            service=COMMON_SERVICES.get(port),
            banner=banner,
        )


async def scan_host(
    host: str,
    ports: list[int],
    timeout: float,
    concurrency: int,
    banner_grab: bool,
) -> list[ScanResult]:
    """Scan all specified ports on a single host with bounded concurrency."""
    sem = asyncio.Semaphore(concurrency)
    tasks = [scan_port(host, port, timeout, sem, banner_grab) for port in ports]
    results = await asyncio.gather(*tasks)
    return results


# ----------------------------------------------------------------------------
# Target resolution
# ----------------------------------------------------------------------------


def resolve_target(target: str) -> str:
    """Validate a target as a hostname or IP. Returns the resolved address."""
    # Try as IP first
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # Try as hostname
    try:
        resolved = socket.gethostbyname(target)
        return resolved
    except socket.gaierror as e:
        raise ValueError(f"could not resolve target: {target} ({e})") from e


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------


def report(target: str, resolved: str, results: list[ScanResult], elapsed: float) -> None:
    """Print scan results in a readable table."""
    print("=" * 70)
    print(f"SCAN RESULTS for {target}", end="")
    if target != resolved:
        print(f" ({resolved})", end="")
    print()
    print("=" * 70)

    open_ports = [r for r in results if r.state == "open"]
    closed = sum(1 for r in results if r.state == "closed")
    filtered = sum(1 for r in results if r.state == "filtered")

    print(f"Scanned:  {len(results):,} ports in {elapsed:.2f}s")
    print(f"Open:     {len(open_ports)}")
    print(f"Closed:   {closed}")
    print(f"Filtered: {filtered}")
    print()

    if not open_ports:
        print("No open ports found.")
        return

    print(f"{'PORT':<8} {'STATE':<10} {'SERVICE':<25} BANNER")
    print("-" * 70)
    for r in open_ports:
        service = r.service or "?"
        banner = r.banner or ""
        print(f"{r.port:<8} {r.state:<10} {service:<25} {banner}")


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Async TCP port scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python port_scanner.py scanme.nmap.org\n"
            "  python port_scanner.py 192.168.1.1 --ports 1-1024\n"
            "  python port_scanner.py example.com --top-ports 100 --banner-grab\n"
            "  python port_scanner.py 10.0.0.5 --port-list 22,80,443,3306,8080\n"
            "\n"
            "Note: only scan hosts you have explicit authorization to scan."
        ),
    )
    parser.add_argument("target", help="Hostname or IP address to scan.")

    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        "--ports",
        help='Port range, e.g. "1-1024" or "22-25,80,443".',
    )
    port_group.add_argument(
        "--top-ports",
        type=int,
        help="Scan the top N most common ports (max 100).",
    )
    port_group.add_argument(
        "--port-list",
        help='Comma-separated list, e.g. "22,80,443".',
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Per-port connect timeout in seconds (default: 1.0).",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=500,
        help="Maximum concurrent connections (default: 500).",
    )
    parser.add_argument(
        "--banner-grab",
        action="store_true",
        help="Attempt to read a banner from open ports.",
    )

    args = parser.parse_args()

    # Resolve target
    try:
        resolved = resolve_target(args.target)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    # Determine port list
    if args.ports:
        try:
            ports = parse_port_spec(args.ports)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    elif args.top_ports:
        n = max(1, min(args.top_ports, len(NMAP_TOP_100)))
        ports = sorted(NMAP_TOP_100[:n])
    elif args.port_list:
        try:
            ports = parse_port_spec(args.port_list)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    else:
        # Default: top 100 common ports
        ports = sorted(NMAP_TOP_100)

    print(
        f"Scanning {args.target} ({resolved}) — {len(ports)} ports, "
        f"concurrency={args.concurrency}, timeout={args.timeout}s"
    )

    start = time.monotonic()
    results = asyncio.run(
        scan_host(
            host=resolved,
            ports=ports,
            timeout=args.timeout,
            concurrency=args.concurrency,
            banner_grab=args.banner_grab,
        )
    )
    elapsed = time.monotonic() - start

    report(args.target, resolved, results, elapsed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
