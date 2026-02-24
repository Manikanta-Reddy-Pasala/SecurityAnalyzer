# Saturn Security Analyzer

Security assessment toolkit for auditing UAT/staging environments and fuzzing C++ binary services.

## Quick Start

```bash
git clone https://github.com/Manikanta-Reddy-Pasala/SecurityAnalyzer.git
cd SecurityAnalyzer
pip install -r requirements.txt
```

## Tools

### 1. Security Scanner (4 scanners)

Audits network, SSH, services, and AWS infrastructure.

```bash
# Full scan (needs SSH access)
python -m saturn_analyzer --host <IP> --user ec2-user --key /path/to/key.pem

# Network-only scan (no SSH needed)
python -m saturn_analyzer --host <IP> --network-only

# Using config file
export SATURN_HOST=<IP>
export SATURN_SSH_USER=ec2-user
export SATURN_SSH_KEY_PATH=/path/to/key.pem
python -m saturn_analyzer --config configs/sample_config.yaml

# Custom output directory
python -m saturn_analyzer --host <IP> --network-only --output ./my-reports
```

**What it checks:**

| Scanner | Checks |
|---------|--------|
| Network | Port scan, TLS validation, exposed databases, public IP, VPN requirement |
| SSH | Key strength, sshd_config, password auth, root login, fail2ban, sudo NOPASSWD |
| Service | Saturn process, auth probing, Docker containers, secrets in env/config, OS patches |
| Infrastructure | IMDSv1/v2, security groups, IAM roles, disk encryption, logging, SELinux |

**Output:** Generates 3 report formats in `./reports/`:
- `security-report.html` - visual report with severity bars
- `security-report.md` - markdown for git/review
- `security-report.json` - machine-readable for CI/CD

### 2. Saturn Breaker (C++ binary fuzzer)

Tests 13 attack categories against a C++ binary service.

```bash
# Discover open ports first, then test all of them
python -m saturn_analyzer.saturn_breaker --host <IP> --discover

# Target a specific port
python -m saturn_analyzer.saturn_breaker --host <IP> --port 8080

# Quick test (buffer overflow + format string only)
python -m saturn_analyzer.saturn_breaker --host <IP> --port 8080 --quick

# Longer timeout for slow services
python -m saturn_analyzer.saturn_breaker --host <IP> --port 8080 --timeout 10

# Quiet mode (no per-test output)
python -m saturn_analyzer.saturn_breaker --host <IP> --port 8080 --quiet
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

**Output:** `reports/saturn-breaker-report.md` and `reports/saturn-breaker-report.json`

## Running Both Together

```bash
# Step 1: Full infrastructure audit
python -m saturn_analyzer --host <IP> --user ec2-user --key /path/to/key.pem

# Step 2: Find Saturn's port from the service scan output, then fuzz it
python -m saturn_analyzer.saturn_breaker --host <IP> --port <SATURN_PORT>

# Or let it discover ports automatically
python -m saturn_analyzer.saturn_breaker --host <IP> --discover
```

## Config File

Copy and edit `configs/sample_config.yaml` for reusable settings. Uses environment variables:

```yaml
target:
  host: "${SATURN_HOST}"
  ssh_user: "${SATURN_SSH_USER}"
  ssh_key_path: "${SATURN_SSH_KEY_PATH}"
```

## Reports

| File | Description |
|------|-------------|
| `reports/security-report.html` | Visual HTML report |
| `reports/security-report.md` | Markdown scan results |
| `reports/security-report.json` | JSON for automation |
| `reports/saturn-breaker-report.md` | Breaker findings |
| `reports/saturn-breaker-report.json` | Breaker full data |
| `reports/UAT-SECURITY-AUDIT-REPORT.md` | Manual audit report |

## Security

- Never commit SSH keys, passwords, or `.env` files (blocked by `.gitignore`)
- Reports with `*.json` and `*.html` are gitignored (may contain sensitive scan data)
- Rotate any credentials that were exposed during testing
