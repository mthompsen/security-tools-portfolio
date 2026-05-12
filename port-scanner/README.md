# port-scanner

Concurrent TCP port scanner using async I/O. Scans a target host for open ports, identifies common services by port number, and optionally grabs banners from open services.

## Usage

```bash
# Scan top 100 common ports (default)
python port_scanner.py example.com

# Scan a specific range
python port_scanner.py 192.168.1.1 --ports 1-1024

# Scan a specific list
python port_scanner.py 10.0.0.5 --port-list 22,80,443,3306,8080

# Scan with banner grabbing
python port_scanner.py scanme.nmap.org --top-ports 50 --banner-grab
```

### Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `target` | Hostname or IP address (positional, required). | — |
| `--ports` | Port range/spec like `1-1024` or `22-25,80,443`. | — |
| `--top-ports N` | Scan the top N most common ports. | — |
| `--port-list` | Comma-separated list like `22,80,443`. | — |
| `--timeout` | Per-port connect timeout (seconds). | `1.0` |
| `--concurrency` | Maximum concurrent connections. | `500` |
| `--banner-grab` | Attempt banner read on open ports. | off |

If no port specification is given, the scanner defaults to the top 100 commonly-open ports.

## How it works

The scanner uses Python's `asyncio` to dispatch up to N concurrent TCP connect attempts. Each attempt opens a socket to the target port and classifies the result:

- **Open** — connection succeeded
- **Closed** — connection refused (RST received)
- **Filtered** — connection timed out (likely firewall drop)

For open ports, the scanner looks up the port number in an IANA-derived service map and optionally attempts to read up to 256 bytes from the socket to capture any banner the service sends. SSH, FTP, SMTP, and HTTP servers often respond with identifying strings on connect, which can reveal software versions.

## Sample output

```
======================================================================
SCAN RESULTS for scanme.nmap.org (45.33.32.156)
======================================================================
Scanned:  100 ports in 2.34s
Open:     3
Closed:   95
Filtered: 2

PORT     STATE      SERVICE                   BANNER
----------------------------------------------------------------------
22       open       SSH                       SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80       open       HTTP
443      open       HTTPS
```

## Legal and ethical use

**Only scan targets you own or have explicit written authorization to scan.** Unauthorized port scanning is illegal in many jurisdictions and is a violation of computer crime law (e.g., the U.S. Computer Fraud and Abuse Act). For learning, use:

- Your own networks
- Dedicated practice targets like `scanme.nmap.org` (which explicitly permits scanning)
- Vulnerable-by-design VMs (Metasploitable, DVWA, OWASP Juice Shop)
- HackTheBox, TryHackMe, and similar legal practice environments

## Limitations

This is a learning tool. Real-world scanning uses `nmap`, `masscan`, or `rustscan`. Specifically, this implementation lacks:

- UDP scanning (TCP only)
- OS fingerprinting
- Service version detection beyond simple banner grabbing
- SYN scanning (uses full TCP connect, more visible to defenders)
- IPv6 support (only IPv4)
- Stealth/timing options (no `nmap -T0` equivalent)

## Extension ideas

- Add UDP scanning (more complex due to lack of connection state)
- Implement SYN scanning using raw sockets (requires root)
- Output to JSON for integration with other tools
- Add target ranges (CIDR notation for subnet scans)
- Probe-based service detection (send known requests for HTTP, TLS, etc.)
- TLS certificate inspection for HTTPS ports

## Requirements

Python 3.10+, no external dependencies (uses only the standard library).
