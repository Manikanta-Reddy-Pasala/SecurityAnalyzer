# Security Analyzer

Comprehensive security assessment toolkit for auditing UAT/staging environments, binary services, VPN configurations, authentication mechanisms, and system payload exposure.

## Quick Start

```bash
git clone <repo-url>
cd SecurityAnalyzer
pip install -r requirements.txt
```

## Tools

### 1. Security Scanner (8 scanners)

Audits network, SSH, services, infrastructure, VPN, authentication, payload exposure, and binary security.

```bash
# Full scan (needs SSH access)
python -m security_analyzer --host <IP> --user <user> --key /path/to/key.pem

# Network-only scan (no SSH needed)
python -m security_analyzer --host <IP> --network-only

# Using config file
export SCAN_HOST=<IP>
export SCAN_SSH_USER=<user>
export SCAN_SSH_KEY_PATH=/path/to/key.pem
python -m security_analyzer --config configs/sample_config.yaml

# Custom output directory
python -m security_analyzer --host <IP> --network-only --output ./my-reports
```

**What it checks:**

| Scanner | Checks |
|---------|--------|
| Network | Port scan, TLS validation, exposed databases, public IP, VPN requirement |
| SSH | Key strength, sshd_config, password auth, root login, fail2ban, sudo NOPASSWD |
| Service | Root services, auth probing, Docker containers, secrets in env/config, OS patches |
| Infrastructure | IMDSv1/v2, security groups, IAM roles, disk encryption, logging, SELinux |
| VPN | VPN presence (WireGuard/OpenVPN/IPSec), config security, split tunneling, DNS leaks |
| Auth | Default creds, JWT vulnerabilities, CORS, session cookies, rate limiting, MFA, security headers |
| Payload Exposure | Debug endpoints, error page leaks, stack traces, source code, /proc, core dumps, actuators |
| Binary Security | ASLR, PIE, stack canaries, NX bit, RELRO, FORTIFY_SOURCE, SUID binaries, vulnerable libs |

**Output:** Generates 3 report formats in `./reports/`:
- `security-report.html` - visual report with severity bars
- `security-report.md` - markdown for git/review
- `security-report.json` - machine-readable for CI/CD

### 2. Binary Fuzzer (service fuzzer)

Tests 13 attack categories against a binary service.

```bash
# Discover open ports first, then test all of them
python -m security_analyzer.binary_fuzzer --host <IP> --discover

# Target a specific port
python -m security_analyzer.binary_fuzzer --host <IP> --port 8080

# Quick test (buffer overflow + format string only)
python -m security_analyzer.binary_fuzzer --host <IP> --port 8080 --quick

# Longer timeout for slow services
python -m security_analyzer.binary_fuzzer --host <IP> --port 8080 --timeout 10

# Quiet mode (no per-test output)
python -m security_analyzer.binary_fuzzer --host <IP> --port 8080 --quiet
```

**Attack categories:**

| # | Category | Payloads |
|---|----------|----------|
| 1 | Buffer Overflow | 256B-1MB, NUL-interspersed, ROP chain, heap spray, off-by-one |
| 2 | Format String | `%x` `%n` `%s` `%p` leak/write, direct parameter, in HTTP headers |
| 3 | Integer Overflow | INT32/64 MAX+1, UINT_MAX, negative, NaN, Infinity |
| 4 | Command Injection | `;id`, `\|cat /etc/passwd`, `` \`whoami\` ``, `$(env)` via TCP/HTTP |
| 5 | Path Traversal | `../etc/passwd`, `/proc/self/maps`, SSH keys, double-encoded |
| 6 | Protocol Fuzzing | Binary garbage, gRPC frames, protobuf, msgpack, malformed HTTP |
| 7 | DoS | Slowloris, huge Content-Length, chunked abuse, JSON/XML bombs, ReDoS |
| 8 | Memory Corruption | Heap spray, vtable overwrite, GOT patterns, tcache poison |
| 9 | Race Conditions | 20 parallel identical requests, mixed method concurrency |
| 10 | Deserialization | XXE file read/SSRF, JSON proto pollution, billion laughs, pickle |
| 11 | HTTP Abuse | CL.TE/TE.CL smuggling, CRLF injection, 64KB URL, SSRF headers |
| 12 | Auth Bypass | 30+ endpoints, JWT none algo, Basic brute, API key guessing |
| 13 | Info Disclosure | `.git/config`, error pages, core dumps, source code, version info |

**Output:** `reports/binary-fuzzer-report.md` and `reports/binary-fuzzer-report.json`

## Running Both Together

```bash
# Step 1: Full infrastructure audit
python -m security_analyzer --host <IP> --user <user> --key /path/to/key.pem

# Step 2: Fuzz service ports
python -m security_analyzer.binary_fuzzer --host <IP> --port <PORT>

# Or let it discover ports automatically
python -m security_analyzer.binary_fuzzer --host <IP> --discover
```

## Config File

Copy and edit `configs/sample_config.yaml` for reusable settings. Uses environment variables:

```yaml
target:
  host: "${SCAN_HOST}"
  ssh_user: "${SCAN_SSH_USER}"
  ssh_key_path: "${SCAN_SSH_KEY_PATH}"
```

## Reports

| File | Description |
|------|-------------|
| `reports/security-report.html` | Visual HTML report |
| `reports/security-report.md` | Markdown scan results |
| `reports/security-report.json` | JSON for automation |
| `reports/binary-fuzzer-report.md` | Fuzzer findings |
| `reports/binary-fuzzer-report.json` | Fuzzer full data |

## Security

- Never commit SSH keys, passwords, or `.env` files (blocked by `.gitignore`)
- Reports with `*.json` and `*.html` are gitignored (may contain sensitive scan data)
- Rotate any credentials that were exposed during testing
