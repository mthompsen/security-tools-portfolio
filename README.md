# Security Tools Portfolio

[![CI](https://github.com/masonthompsen/security-tools-portfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/masonthompsen/security-tools-portfolio/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

A collection of foundational security utilities written in Python. Each tool is self-contained, documented, and tested. Built as learning exercises and as the kind of small, focused tooling that gets used in real defensive work.

## Tools

| Tool | Description | Path |
|------|-------------|------|
| `log-parser` | Parses common web server log formats (Apache/Nginx combined, syslog) and extracts security-relevant indicators: failed auth attempts, suspicious user agents, request anomalies. | [`log-parser/`](./log-parser/) |
| `port-scanner` | TCP connect scanner with configurable concurrency, timeout handling, and service identification for common ports. | [`port-scanner/`](./port-scanner/) |
| `password-checker` | Password strength analyzer using entropy calculation, common-pattern detection, and optional check against the Have I Been Pwned breach corpus via k-anonymity API. | [`password-checker/`](./password-checker/) |

## Why these tools?

These three address the foundational triad of defensive security work:

- **Log parsing** is the foundation of detection. SIEM, SOC, and incident response all start with reading logs.
- **Port scanning** is the foundation of network reconnaissance, both offensive (recon) and defensive (asset inventory, attack surface management).
- **Password analysis** is the foundation of credential security, which remains the #1 attack vector in real breaches.

Each tool is intentionally limited in scope. They are not replacements for `grep`, `nmap`, or `zxcvbn` — they are illustrative implementations that demonstrate the underlying concepts and serve as starting points for extension.

## Quick start

```bash
# Clone the repo
git clone https://github.com/masonthompsen/security-tools-portfolio.git
cd security-tools-portfolio

# Run any tool directly (no installation needed - standard library only)
python log-parser/log_parser.py --help
python port-scanner/port_scanner.py --help
python password-checker/password_checker.py --help
```

## Development setup

For running tests and contributing:

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run the full test suite
pytest

# Run with coverage report
pytest --cov

# Lint the codebase
ruff check .

# Type-check
mypy log-parser port-scanner password-checker
```

## Testing

The codebase ships with **104 unit tests** covering parsing logic, pattern detection, async scanning behavior, entropy calculation, and the HIBP integration (mocked, no network calls in tests).

```text
$ pytest
============================= test session starts ==============================
collected 104 items

log-parser/tests/test_log_parser.py ....................................
port-scanner/tests/test_port_scanner.py .............................
password-checker/tests/test_password_checker.py .......................

============================= 104 passed in 0.22s ==============================
```

Tests run on Python 3.10, 3.11, and 3.12 via GitHub Actions on every push.

## Repository structure

```text
security-tools-portfolio/
├── .github/workflows/
│   └── ci.yml              # GitHub Actions CI configuration
├── log-parser/
│   ├── log_parser.py       # Main implementation
│   ├── test_access.log     # Synthetic test data
│   ├── README.md           # Tool-specific documentation
│   └── tests/              # Unit tests
├── port-scanner/
│   ├── port_scanner.py
│   ├── README.md
│   └── tests/
├── password-checker/
│   ├── password_checker.py
│   ├── README.md
│   └── tests/
├── pyproject.toml          # Project configuration (ruff, mypy, pytest)
├── LICENSE                 # MIT
└── README.md               # This file
```

## Design principles

A few choices that run through all three tools:

- **Standard library only** for runtime dependencies. Lower install friction, no supply-chain risk, runs anywhere Python runs.
- **Type hints throughout** using PEP 604 syntax (`list[int]`, `Optional[str]`). Static-checkable with `mypy`.
- **Dataclasses for structured data** rather than ad-hoc tuples or dictionaries.
- **Async I/O where appropriate** (port scanner) rather than threading, for high concurrency without thread overhead.
- **Iterator-based processing** (log parser) rather than loading entire files into memory.
- **Defensive parsing**: malformed input returns `None` rather than raising exceptions.
- **Privacy-preserving network calls**: the password checker uses k-anonymity for HIBP, so the password itself never leaves the machine.

## Ethical use

These tools are for learning, defensive analysis, and authorized testing only.

- **Only scan hosts you own or have explicit written authorization to scan.** Unauthorized port scanning may violate computer crime law (e.g., the U.S. Computer Fraud and Abuse Act).
- **Only analyze passwords you own.** The password checker is for evaluating your own credentials or those of consenting users.
- **Use synthetic or sanitized logs for testing.** Real production logs may contain PII or other sensitive data.

Recommended legal practice environments:

- [TryHackMe](https://tryhackme.com/)
- [HackTheBox](https://www.hackthebox.com/)
- [scanme.nmap.org](http://scanme.nmap.org/) (explicitly permits scanning)
- Self-hosted vulnerable VMs (Metasploitable, DVWA, OWASP Juice Shop)

## Author

Mason Thompsen — Computer Science student focused on cybersecurity, San Antonio TX. Building toward a career in cloud security architecture.

## License

MIT — see [LICENSE](./LICENSE).
