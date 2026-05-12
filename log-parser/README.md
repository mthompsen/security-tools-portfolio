# log-parser

Security-focused log analysis tool for web server and syslog files. Parses common log formats, then surfaces indicators of compromise: failed authentication, suspicious user agents, sensitive-path probing, and traffic anomalies by source IP.

## Supported formats

- **Apache/Nginx combined log format** — the most common web server log format
- **Common Log Format (CLF)** — the older variant without referer/user-agent
- **Syslog** — basic Unix syslog format

The tool auto-detects format by default; override with `--format` if detection fails.

## Usage

```bash
python log_parser.py /var/log/nginx/access.log
python log_parser.py /var/log/auth.log --format syslog
python log_parser.py access.log --threshold 50 --show-all
```

### Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `logfile` | Path to the log file (positional, required). | — |
| `--format` | Log format: `auto`, `combined`, `clf`, `syslog`. | `auto` |
| `--threshold` | Minimum request count for an IP to be listed. | `10` |
| `--show-all` | Disable output truncation. | off |

## What it detects

| Signal | Method |
|--------|--------|
| Failed authentication | HTTP 401 responses, syslog phrases like "authentication failure", "failed password", "invalid user" |
| Suspicious user agents | Substring match against known scanner/tool UAs (sqlmap, nikto, nmap, masscan, dirbuster, curl, python-requests, etc.) |
| Sensitive path probing | Requests to `/wp-admin`, `/.env`, `/.git`, `/admin`, `/phpmyadmin`, `/etc/passwd`, etc. |
| Volume anomalies | Top source IPs by request count, with flags overlaid |
| Status code anomalies | Distribution of HTTP status codes, with attack-indicator statuses (401/403/404/5xx) called out |

## Sample output

```
======================================================================
LOG ANALYSIS REPORT
======================================================================

Parse statistics
----------------------------------------------------------------------
  Total lines:     12,847
  Parsed:          12,801 (99.6%)
  Unique source IPs: 1,243

Security signals
----------------------------------------------------------------------
  Failed authentication events: 47
  Suspicious user-agent hits:   312
  Suspicious path probes:       89

Top source IPs by request volume (threshold: 10)
----------------------------------------------------------------------
  203.0.113.42                                  1,847 requests [FLAGGED]
  198.51.100.7                                    523 requests [FLAGGED]
  ...
```

## Limitations

This is a learning tool, not a production SIEM. Real environments use Splunk, Elastic, Sentinel, etc. Specifically:

- No streaming/tailing support (whole-file analysis only)
- No GeoIP enrichment
- No correlation across multiple log files
- No state persistence between runs
- Pattern lists are static; in production these would come from threat intelligence feeds

## Extension ideas

- Add GeoIP enrichment with `geoip2` library
- Pipe results to JSON output for downstream tooling
- Track failed auth attempts per IP over time windows to detect brute force
- Cross-reference source IPs against threat intel feeds (AbuseIPDB, Spamhaus)
- Add support for AWS CloudTrail, Azure activity logs

## Requirements

Python 3.10+, no external dependencies (uses only the standard library).
