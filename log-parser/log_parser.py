#!/usr/bin/env python3
"""
log_parser.py - Security-focused log analysis tool.

Parses common web server log formats and extracts indicators relevant to
security analysis: failed authentication, suspicious user agents, request
anomalies, and basic frequency analysis.

Supports:
  - Apache/Nginx combined log format
  - Common log format (CLF)
  - syslog (basic)

Usage:
  python log_parser.py <logfile> [--format auto|combined|clf|syslog]
                                  [--threshold N]
                                  [--show-all]
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# ----------------------------------------------------------------------------
# Log format definitions
# ----------------------------------------------------------------------------

# Apache/Nginx combined log format:
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"
COMBINED_LOG_PATTERN = re.compile(
    r"(?P<ip>\S+)\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r"(?P<status>\d+)\s+"
    r"(?P<size>\S+)\s+"
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"'
)

# Common log format (no referer/user agent)
CLF_PATTERN = re.compile(
    r"(?P<ip>\S+)\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r"(?P<status>\d+)\s+"
    r"(?P<size>\S+)"
)

# Basic syslog: Mar 12 14:23:45 hostname process[pid]: message
SYSLOG_PATTERN = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)"
)


# Suspicious user-agent indicators (case-insensitive substring match)
SUSPICIOUS_UA_PATTERNS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "wpscan",
    "dirbuster",
    "gobuster",
    "hydra",
    "metasploit",
    "burpsuite",
    "curl/",
    "wget/",
    "python-requests",
    "go-http-client",
    "libwww-perl",
]

# Paths commonly probed by automated scanners
SUSPICIOUS_PATH_PATTERNS = [
    "/wp-admin",
    "/wp-login",
    "/.env",
    "/.git",
    "/admin",
    "/phpmyadmin",
    "/.aws/credentials",
    "/etc/passwd",
    "/web.config",
    "/server-status",
    "/wp-config.php",
    "/.ssh/",
    "/api/v1/auth",
    "/.htaccess",
]

# Status codes worth flagging at scale
ATTACK_INDICATOR_STATUSES = {401, 403, 404, 500, 502, 503}


# ----------------------------------------------------------------------------
# Data structures
# ----------------------------------------------------------------------------


@dataclass
class LogEntry:
    """Normalized representation of a log line across formats."""

    raw: str
    source_ip: str | None = None
    timestamp: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    user_agent: str | None = None
    message: str | None = None  # for syslog-style entries


@dataclass
class AnalysisResult:
    total_lines: int = 0
    parsed_lines: int = 0
    failed_auth_count: int = 0
    suspicious_ua_hits: int = 0
    suspicious_path_hits: int = 0
    ip_counter: Counter = None
    status_counter: Counter = None
    suspicious_ips: dict = None  # ip -> list of reasons
    sample_failures: list = None

    def __post_init__(self):
        if self.ip_counter is None:
            self.ip_counter = Counter()
        if self.status_counter is None:
            self.status_counter = Counter()
        if self.suspicious_ips is None:
            self.suspicious_ips = defaultdict(list)
        if self.sample_failures is None:
            self.sample_failures = []


# ----------------------------------------------------------------------------
# Parsing
# ----------------------------------------------------------------------------


def detect_format(sample_lines: list[str]) -> str:
    """Heuristically detect log format from sample lines."""
    for line in sample_lines:
        if COMBINED_LOG_PATTERN.match(line):
            return "combined"
        if CLF_PATTERN.match(line):
            return "clf"
        if SYSLOG_PATTERN.match(line):
            return "syslog"
    return "unknown"


def parse_line(line: str, fmt: str) -> LogEntry | None:
    """Parse a single log line into a LogEntry based on format."""
    line = line.strip()
    if not line:
        return None

    if fmt == "combined":
        m = COMBINED_LOG_PATTERN.match(line)
        if not m:
            return None
        return LogEntry(
            raw=line,
            source_ip=m.group("ip"),
            timestamp=m.group("timestamp"),
            method=m.group("method"),
            path=m.group("path"),
            status=int(m.group("status")),
            user_agent=m.group("user_agent"),
        )

    if fmt == "clf":
        m = CLF_PATTERN.match(line)
        if not m:
            return None
        return LogEntry(
            raw=line,
            source_ip=m.group("ip"),
            timestamp=m.group("timestamp"),
            method=m.group("method"),
            path=m.group("path"),
            status=int(m.group("status")),
        )

    if fmt == "syslog":
        m = SYSLOG_PATTERN.match(line)
        if not m:
            return None
        return LogEntry(
            raw=line,
            timestamp=m.group("timestamp"),
            message=m.group("message"),
        )

    return None


def iter_log_lines(path: Path) -> Iterator[str]:
    """Yield lines from a log file, handling encoding gracefully."""
    with path.open("r", encoding="utf-8", errors="replace") as f:
        yield from f


# ----------------------------------------------------------------------------
# Analysis
# ----------------------------------------------------------------------------


def analyze(entries: Iterator[LogEntry]) -> AnalysisResult:
    """Walk parsed entries and accumulate security-relevant findings."""
    result = AnalysisResult()

    for entry in entries:
        result.total_lines += 1
        if entry is None:
            continue
        result.parsed_lines += 1

        if entry.source_ip:
            result.ip_counter[entry.source_ip] += 1

        if entry.status is not None:
            result.status_counter[entry.status] += 1

            # Failed auth signal: 401 status
            if entry.status == 401:
                result.failed_auth_count += 1
                result.suspicious_ips[entry.source_ip].append("401 failed auth")
                if len(result.sample_failures) < 5:
                    result.sample_failures.append(entry.raw)

        # Suspicious user agent
        if entry.user_agent:
            ua_lower = entry.user_agent.lower()
            for sus in SUSPICIOUS_UA_PATTERNS:
                if sus in ua_lower:
                    result.suspicious_ua_hits += 1
                    if entry.source_ip:
                        result.suspicious_ips[entry.source_ip].append(f"suspicious UA: {sus}")
                    break

        # Suspicious path probes
        if entry.path:
            for sus in SUSPICIOUS_PATH_PATTERNS:
                if sus in entry.path:
                    result.suspicious_path_hits += 1
                    if entry.source_ip:
                        result.suspicious_ips[entry.source_ip].append(
                            f"probed sensitive path: {entry.path}"
                        )
                    break

        # Syslog: look for common auth failure phrases
        if entry.message:
            msg_lower = entry.message.lower()
            if any(
                phrase in msg_lower
                for phrase in (
                    "authentication failure",
                    "failed password",
                    "invalid user",
                    "permission denied",
                )
            ):
                result.failed_auth_count += 1
                if len(result.sample_failures) < 5:
                    result.sample_failures.append(entry.raw)

    return result


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------


def report(result: AnalysisResult, threshold: int, show_all: bool) -> None:
    """Print a human-readable security summary of the analysis."""
    print("=" * 70)
    print("LOG ANALYSIS REPORT")
    print("=" * 70)
    print(f"Generated: {datetime.now().isoformat(timespec='seconds')}")
    print()

    # Parse statistics
    parse_rate = (result.parsed_lines / result.total_lines * 100) if result.total_lines else 0
    print("Parse statistics")
    print("-" * 70)
    print(f"  Total lines:     {result.total_lines:,}")
    print(f"  Parsed:          {result.parsed_lines:,} ({parse_rate:.1f}%)")
    print(f"  Unique source IPs: {len(result.ip_counter):,}")
    print()

    # Security signals
    print("Security signals")
    print("-" * 70)
    print(f"  Failed authentication events: {result.failed_auth_count:,}")
    print(f"  Suspicious user-agent hits:   {result.suspicious_ua_hits:,}")
    print(f"  Suspicious path probes:       {result.suspicious_path_hits:,}")
    print()

    # Top talkers (potentially indicating scanning or brute force)
    if result.ip_counter:
        print(f"Top source IPs by request volume (threshold: {threshold})")
        print("-" * 70)
        shown = 0
        for shown, (ip, count) in enumerate(result.ip_counter.most_common(), start=1):
            if count < threshold and not show_all:
                shown -= 1  # this iteration didn't actually print
                break
            marker = " [FLAGGED]" if ip in result.suspicious_ips else ""
            print(f"  {ip:<40} {count:>8,} requests{marker}")
            if shown >= 20 and not show_all:
                remaining = len(result.ip_counter) - shown
                if remaining > 0:
                    print(f"  ... and {remaining:,} more (use --show-all to display)")
                break
        print()

    # Status code breakdown
    if result.status_counter:
        print("HTTP status distribution")
        print("-" * 70)
        for status, count in sorted(result.status_counter.items()):
            indicator = " <-- attack indicator" if status in ATTACK_INDICATOR_STATUSES else ""
            print(f"  {status}: {count:>8,}{indicator}")
        print()

    # Flagged IPs with reasons
    if result.suspicious_ips:
        print(f"Flagged source IPs ({len(result.suspicious_ips)} total)")
        print("-" * 70)
        flagged_sorted = sorted(
            result.suspicious_ips.items(),
            key=lambda kv: result.ip_counter[kv[0]],
            reverse=True,
        )
        for ip, reasons in flagged_sorted[:10]:
            unique_reasons = sorted(set(reasons))
            print(f"  {ip} ({result.ip_counter[ip]:,} requests)")
            for reason in unique_reasons[:5]:
                print(f"      - {reason}")
            if len(unique_reasons) > 5:
                print(f"      - (+{len(unique_reasons) - 5} more indicators)")
        if len(flagged_sorted) > 10:
            print(f"  ... and {len(flagged_sorted) - 10} more flagged IPs")
        print()

    # Sample failures
    if result.sample_failures:
        print("Sample failure entries")
        print("-" * 70)
        for raw in result.sample_failures:
            truncated = raw if len(raw) <= 120 else raw[:117] + "..."
            print(f"  {truncated}")
        print()


# ----------------------------------------------------------------------------
# CLI entry point
# ----------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse web/syslog logs and surface security-relevant signals.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("logfile", type=Path, help="Path to the log file.")
    parser.add_argument(
        "--format",
        choices=["auto", "combined", "clf", "syslog"],
        default="auto",
        help="Log format (default: auto-detect).",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=10,
        help="Minimum request count to list a source IP (default: 10).",
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Show all IPs and entries instead of truncating output.",
    )

    args = parser.parse_args()

    if not args.logfile.exists():
        print(f"error: file not found: {args.logfile}", file=sys.stderr)
        return 1

    # Detect format if auto
    fmt = args.format
    if fmt == "auto":
        sample = []
        with args.logfile.open("r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                sample.append(line.strip())
                if i >= 19:
                    break
        fmt = detect_format(sample)
        if fmt == "unknown":
            print(
                "error: could not auto-detect log format. Specify with --format.",
                file=sys.stderr,
            )
            return 2
        print(f"[detected format: {fmt}]")

    # Parse and analyze
    entries = (parse_line(line, fmt) for line in iter_log_lines(args.logfile))
    result = analyze(entries)
    report(result, args.threshold, args.show_all)

    return 0


if __name__ == "__main__":
    sys.exit(main())
