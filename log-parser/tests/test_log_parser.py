"""Unit tests for log_parser.

These tests cover parsing logic, format detection, and the analysis pipeline.
Network-dependent or filesystem-heavy operations are tested via small
synthetic fixtures kept inline.
"""

from __future__ import annotations

from pathlib import Path

import log_parser
import pytest

# ----------------------------------------------------------------------------
# Sample log lines used as fixtures
# ----------------------------------------------------------------------------

NORMAL_COMBINED = (
    '192.168.1.10 - - [12/May/2026:10:23:01 +0000] '
    '"GET /index.html HTTP/1.1" 200 1234 "-" '
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
)

SQLMAP_PROBE = (
    '203.0.113.42 - - [12/May/2026:10:24:15 +0000] '
    '"GET /admin HTTP/1.1" 401 0 "-" "sqlmap/1.5.2#stable"'
)

CLF_LINE = (
    '192.168.1.10 - - [12/May/2026:10:23:01 +0000] '
    '"GET /index.html HTTP/1.1" 200 1234'
)

SYSLOG_LINE = (
    'Mar 12 14:23:45 server01 sshd[12345]: '
    'Failed password for invalid user admin from 203.0.113.42 port 22 ssh2'
)


# ----------------------------------------------------------------------------
# Format detection
# ----------------------------------------------------------------------------

class TestDetectFormat:
    def test_detects_combined_format(self):
        assert log_parser.detect_format([NORMAL_COMBINED]) == 'combined'

    def test_detects_clf_format(self):
        assert log_parser.detect_format([CLF_LINE]) == 'clf'

    def test_detects_syslog_format(self):
        assert log_parser.detect_format([SYSLOG_LINE]) == 'syslog'

    def test_returns_unknown_for_garbage(self):
        assert log_parser.detect_format(['this is not a log line']) == 'unknown'

    def test_returns_unknown_for_empty_input(self):
        assert log_parser.detect_format([]) == 'unknown'

    def test_combined_takes_precedence_over_clf(self):
        # A combined-format line also matches CLF prefix; combined should win
        assert log_parser.detect_format([NORMAL_COMBINED]) == 'combined'


# ----------------------------------------------------------------------------
# Single-line parsing
# ----------------------------------------------------------------------------

class TestParseLine:
    def test_parses_combined_line_correctly(self):
        entry = log_parser.parse_line(NORMAL_COMBINED, 'combined')
        assert entry is not None
        assert entry.source_ip == '192.168.1.10'
        assert entry.method == 'GET'
        assert entry.path == '/index.html'
        assert entry.status == 200
        assert 'Mozilla' in entry.user_agent

    def test_parses_clf_line_correctly(self):
        entry = log_parser.parse_line(CLF_LINE, 'clf')
        assert entry is not None
        assert entry.source_ip == '192.168.1.10'
        assert entry.status == 200
        assert entry.user_agent is None  # CLF has no UA field

    def test_parses_syslog_line_correctly(self):
        entry = log_parser.parse_line(SYSLOG_LINE, 'syslog')
        assert entry is not None
        assert 'Failed password' in entry.message
        assert entry.source_ip is None  # syslog format has no structured IP field

    def test_returns_none_for_empty_line(self):
        assert log_parser.parse_line('', 'combined') is None
        assert log_parser.parse_line('   \n', 'combined') is None

    def test_returns_none_for_unparseable_line(self):
        assert log_parser.parse_line('garbage', 'combined') is None

    def test_returns_none_for_unknown_format(self):
        assert log_parser.parse_line(NORMAL_COMBINED, 'unknown-format') is None

    def test_status_is_integer(self):
        entry = log_parser.parse_line(NORMAL_COMBINED, 'combined')
        assert isinstance(entry.status, int)


# ----------------------------------------------------------------------------
# Analysis pipeline
# ----------------------------------------------------------------------------

class TestAnalyze:
    def test_counts_total_and_parsed_lines(self):
        entries = [
            log_parser.parse_line(NORMAL_COMBINED, 'combined'),
            log_parser.parse_line(SQLMAP_PROBE, 'combined'),
            None,  # simulated unparseable line
        ]
        result = log_parser.analyze(iter(entries))
        assert result.total_lines == 3
        assert result.parsed_lines == 2

    def test_flags_sqlmap_user_agent(self):
        entries = [log_parser.parse_line(SQLMAP_PROBE, 'combined')]
        result = log_parser.analyze(iter(entries))
        assert result.suspicious_ua_hits == 1
        assert '203.0.113.42' in result.suspicious_ips

    def test_counts_401_as_failed_auth(self):
        entries = [log_parser.parse_line(SQLMAP_PROBE, 'combined')]
        result = log_parser.analyze(iter(entries))
        assert result.failed_auth_count == 1

    def test_flags_sensitive_path_probe(self):
        env_probe = (
            '203.0.113.42 - - [12/May/2026:10:24:15 +0000] '
            '"GET /.env HTTP/1.1" 404 0 "-" "Mozilla/5.0"'
        )
        entries = [log_parser.parse_line(env_probe, 'combined')]
        result = log_parser.analyze(iter(entries))
        assert result.suspicious_path_hits == 1

    def test_does_not_flag_legitimate_traffic(self):
        entries = [log_parser.parse_line(NORMAL_COMBINED, 'combined')]
        result = log_parser.analyze(iter(entries))
        assert result.suspicious_ua_hits == 0
        assert result.suspicious_path_hits == 0
        assert result.failed_auth_count == 0
        assert '192.168.1.10' not in result.suspicious_ips

    def test_aggregates_ip_request_counts(self):
        entries = [
            log_parser.parse_line(NORMAL_COMBINED, 'combined'),
            log_parser.parse_line(NORMAL_COMBINED, 'combined'),
            log_parser.parse_line(SQLMAP_PROBE, 'combined'),
        ]
        result = log_parser.analyze(iter(entries))
        assert result.ip_counter['192.168.1.10'] == 2
        assert result.ip_counter['203.0.113.42'] == 1

    def test_syslog_failed_password_counted(self):
        entries = [log_parser.parse_line(SYSLOG_LINE, 'syslog')]
        result = log_parser.analyze(iter(entries))
        assert result.failed_auth_count == 1

    def test_status_codes_accumulated(self):
        entries = [
            log_parser.parse_line(NORMAL_COMBINED, 'combined'),
            log_parser.parse_line(SQLMAP_PROBE, 'combined'),
        ]
        result = log_parser.analyze(iter(entries))
        assert result.status_counter[200] == 1
        assert result.status_counter[401] == 1


# ----------------------------------------------------------------------------
# Suspicious pattern detection
# ----------------------------------------------------------------------------

class TestSuspiciousPatterns:
    @pytest.mark.parametrize('user_agent', [
        'sqlmap/1.5.2',
        'Nikto/2.1.6',
        'Mozilla/5.0 nmap',
        'masscan/1.0',
        'python-requests/2.28.1',
        'curl/7.68.0',
    ])
    def test_detects_known_scanner_user_agents(self, user_agent):
        line = (
            f'1.2.3.4 - - [12/May/2026:10:00:00 +0000] '
            f'"GET / HTTP/1.1" 200 0 "-" "{user_agent}"'
        )
        entries = [log_parser.parse_line(line, 'combined')]
        result = log_parser.analyze(iter(entries))
        assert result.suspicious_ua_hits == 1, f'Failed to flag UA: {user_agent}'

    @pytest.mark.parametrize('path', [
        '/wp-admin',
        '/wp-login.php',
        '/.env',
        '/.git/config',
        '/phpmyadmin',
        '/admin',
        '/.aws/credentials',
    ])
    def test_detects_sensitive_path_probes(self, path):
        line = (
            f'1.2.3.4 - - [12/May/2026:10:00:00 +0000] '
            f'"GET {path} HTTP/1.1" 404 0 "-" "Mozilla/5.0"'
        )
        entries = [log_parser.parse_line(line, 'combined')]
        result = log_parser.analyze(iter(entries))
        assert result.suspicious_path_hits == 1, f'Failed to flag path: {path}'


# ----------------------------------------------------------------------------
# End-to-end: file reading
# ----------------------------------------------------------------------------

class TestFileReading:
    def test_iter_log_lines_reads_file(self, tmp_path: Path):
        log_file = tmp_path / 'test.log'
        log_file.write_text(f'{NORMAL_COMBINED}\n{SQLMAP_PROBE}\n')
        lines = list(log_parser.iter_log_lines(log_file))
        assert len(lines) == 2

    def test_iter_log_lines_handles_bad_encoding(self, tmp_path: Path):
        # Write some bytes that are not valid UTF-8
        log_file = tmp_path / 'test.log'
        log_file.write_bytes(b'192.168.1.1 - - [date] "GET /\xff HTTP/1.1" 200 0 "-" "ua"\n')
        # Should not raise, just substitute replacement chars
        lines = list(log_parser.iter_log_lines(log_file))
        assert len(lines) == 1
