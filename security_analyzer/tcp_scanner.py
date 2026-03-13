"""TCP protocol attack surface scanner.

Probes open TCP ports for banner leakage, protocol-specific payload
analysis, dangerous default services, TCP configuration weaknesses,
and raw-socket-level attack vectors.
"""
import socket
import struct
import subprocess
import time
from typing import Optional
from .models import Finding, ScanResult, Severity, Category


class TCPScanner:
    """Scans for TCP-layer and transport-protocol attack surfaces."""

    def __init__(self, host: str, user: str = None,
                 key_path: Optional[str] = None, timeout: int = 5):
        self.host = host
        self.user = user
        self.key_path = key_path
        self.timeout = timeout

    # ── public entry point ──────────────────────────────────────────────────
    def scan(self, ports: list[int] = None) -> ScanResult:
        result = ScanResult(scanner_name="TCP Protocol Attack Scanner")

        if ports is None:
            ports = [
                21, 22, 23, 25, 80, 110, 143, 443, 445, 993, 995,
                2375, 2376, 3306, 3389, 4222, 5432, 5672, 5900,
                6379, 8080, 8443, 9090, 9200, 11211, 27017, 50000,
            ]

        open_ports = self._discover_open_ports(ports)
        result.raw_output += f"Open TCP ports: {open_ports}\n"

        # Per-port checks
        for port in open_ports:
            self._check_banner_leakage(port, result)
            self._check_protocol_payload(port, result)

        # Host-level TCP stack checks (via SSH if available)
        if self.user and self._can_connect():
            self._check_syn_cookies(result)
            self._check_tcp_timestamps(result)
            self._check_ip_forwarding(result)
            self._check_source_routing(result)
            self._check_icmp_redirect(result)
            self._check_tcp_keepalive(result)
            self._check_rp_filter(result)
            self._check_tcp_window_scaling(result)

        # Cleartext protocol checks
        self._check_cleartext_protocols(open_ports, result)

        return result

    # ── helpers ──────────────────────────────────────────────────────────────
    def _can_connect(self) -> bool:
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
               "-o", "ConnectTimeout=10", "-o", "BatchMode=yes"]
        if self.key_path:
            cmd.extend(["-i", self.key_path])
        cmd.extend([f"{self.user}@{self.host}", "echo ok"])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return proc.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def _run_remote(self, command: str, timeout: int = 20) -> Optional[str]:
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
               "-o", "ConnectTimeout=10", "-o", "BatchMode=yes"]
        if self.key_path:
            cmd.extend(["-i", self.key_path])
        cmd.extend([f"{self.user}@{self.host}", command])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return proc.stdout if proc.returncode == 0 else proc.stderr
        except subprocess.TimeoutExpired:
            return None

    def _discover_open_ports(self, ports: list[int]) -> list[int]:
        """TCP connect scan to discover open ports."""
        open_ports = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    if s.connect_ex((self.host, port)) == 0:
                        open_ports.append(port)
            except (socket.timeout, OSError):
                pass
        return open_ports

    def _grab_banner(self, port: int, probe: bytes = b"", timeout: int = 3) -> str:
        """Connect, optionally send a probe, and read the banner."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((self.host, port))
                if probe:
                    s.sendall(probe)
                return s.recv(1024).decode(errors="replace").strip()
        except Exception:
            return ""

    # ── per-port checks ──────────────────────────────────────────────────────
    def _check_banner_leakage(self, port: int, result: ScanResult):
        """Grab TCP banner and check for version / OS disclosure."""
        banner = self._grab_banner(port)
        if not banner:
            return

        result.raw_output += f"Port {port} banner: {banner[:200]}\n"

        # Detect version strings that reveal software & version
        version_keywords = [
            "openssh", "apache", "nginx", "microsoft", "iis",
            "postfix", "exim", "dovecot", "proftpd", "vsftpd",
            "mysql", "mariadb", "postgresql", "redis", "mongodb",
            "memcached", "rabbitmq", "ubuntu", "debian", "centos",
            "fedora", "docker", "elastic", "nats",
        ]
        banner_lower = banner.lower()
        disclosed = [kw for kw in version_keywords if kw in banner_lower]

        if disclosed:
            result.add_finding(Finding(
                title=f"TCP Banner Discloses Software Version (port {port})",
                severity=Severity.MEDIUM,
                category=Category.TCP_ATTACK,
                description=f"Service on port {port} reveals software identity in its TCP banner. "
                            "Attackers use this to target known CVEs.",
                evidence=f"Banner: {banner[:300]}",
                recommendation="Configure service to suppress or customize the banner. "
                               "For example: 'ServerTokens Prod' (Apache), "
                               "'server_tokens off' (Nginx).",
                cwe_id="CWE-200",
            ))

    def _check_protocol_payload(self, port: int, result: ScanResult):
        """Send protocol-specific probes and analyze responses for security issues."""

        # ── FTP (21) ────────────────────────────────────────────────────────
        if port == 21:
            banner = self._grab_banner(port)
            if banner:
                # Check anonymous login
                anon = self._try_ftp_anon(port)
                if anon:
                    result.add_finding(Finding(
                        title="FTP Anonymous Login Permitted",
                        severity=Severity.CRITICAL,
                        category=Category.TCP_ATTACK,
                        description="FTP server allows anonymous login. "
                                    "Attackers can read/upload files without credentials.",
                        evidence=f"Anonymous login succeeded on port {port}",
                        recommendation="Disable anonymous FTP access. Use SFTP instead.",
                        cwe_id="CWE-287",
                    ))

        # ── Telnet (23) ─────────────────────────────────────────────────────
        if port == 23:
            banner = self._grab_banner(port)
            if banner:
                result.add_finding(Finding(
                    title="Telnet Service Active (port 23)",
                    severity=Severity.HIGH,
                    category=Category.TCP_ATTACK,
                    description="Telnet transmits credentials and data in cleartext. "
                                "Attackers on the network can capture all traffic.",
                    evidence=f"Telnet banner: {banner[:200]}",
                    recommendation="Disable Telnet and use SSH instead.",
                    cwe_id="CWE-319",
                ))

        # ── SMTP (25) ───────────────────────────────────────────────────────
        if port == 25:
            self._check_smtp(port, result)

        # ── Redis (6379) ────────────────────────────────────────────────────
        if port == 6379:
            self._check_redis(port, result)

        # ── Memcached (11211) ───────────────────────────────────────────────
        if port == 11211:
            self._check_memcached(port, result)

        # ── MongoDB (27017) ─────────────────────────────────────────────────
        if port == 27017:
            self._check_mongodb(port, result)

        # ── MySQL (3306) ────────────────────────────────────────────────────
        if port == 3306:
            self._check_mysql_greeting(port, result)

        # ── Docker API (2375) ───────────────────────────────────────────────
        if port == 2375:
            self._check_docker_api(port, result)

        # ── RDP (3389) ──────────────────────────────────────────────────────
        if port == 3389:
            result.add_finding(Finding(
                title="RDP Service Exposed (port 3389)",
                severity=Severity.HIGH,
                category=Category.TCP_ATTACK,
                description="Remote Desktop Protocol is exposed to the network. "
                            "RDP is a frequent target for brute-force and BlueKeep-style exploits.",
                evidence=f"TCP port 3389 open on {self.host}",
                recommendation="Restrict RDP via firewall/VPN. Enable NLA. Disable if unused.",
                cwe_id="CWE-284",
            ))

        # ── VNC (5900) ──────────────────────────────────────────────────────
        if port == 5900:
            banner = self._grab_banner(port)
            result.add_finding(Finding(
                title="VNC Service Exposed (port 5900)",
                severity=Severity.HIGH,
                category=Category.TCP_ATTACK,
                description="VNC is exposed. Many VNC implementations have weak "
                            "authentication or no encryption.",
                evidence=f"TCP 5900 open, banner: {banner[:100]}",
                recommendation="Restrict VNC via firewall. Tunnel over SSH or use a VPN.",
                cwe_id="CWE-284",
            ))

        # ── SMB (445) ───────────────────────────────────────────────────────
        if port == 445:
            result.add_finding(Finding(
                title="SMB Service Exposed (port 445)",
                severity=Severity.HIGH,
                category=Category.TCP_ATTACK,
                description="SMB port 445 is exposed. SMB has a long history of critical "
                            "vulnerabilities (EternalBlue, SMBGhost).",
                evidence=f"TCP port 445 open on {self.host}",
                recommendation="Block SMB at the firewall. If needed internally, "
                               "restrict to LAN and disable SMBv1.",
                cwe_id="CWE-284",
            ))

    def _try_ftp_anon(self, port: int) -> bool:
        """Attempt anonymous FTP login."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((self.host, port))
                s.recv(1024)  # banner
                s.sendall(b"USER anonymous\r\n")
                resp = s.recv(1024).decode(errors="replace")
                if "331" in resp:
                    s.sendall(b"PASS anonymous@test.com\r\n")
                    resp = s.recv(1024).decode(errors="replace")
                    return "230" in resp
        except Exception:
            pass
        return False

    def _check_smtp(self, port: int, result: ScanResult):
        """Check SMTP for open relay and VRFY/EXPN commands."""
        banner = self._grab_banner(port)
        if not banner:
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((self.host, port))
                s.recv(1024)  # banner

                # VRFY check
                s.sendall(b"VRFY root\r\n")
                vrfy_resp = s.recv(1024).decode(errors="replace")
                if vrfy_resp.startswith("252") or vrfy_resp.startswith("250"):
                    result.add_finding(Finding(
                        title="SMTP VRFY Command Enabled (port 25)",
                        severity=Severity.MEDIUM,
                        category=Category.TCP_ATTACK,
                        description="SMTP VRFY command is enabled, allowing attackers "
                                    "to enumerate valid email addresses.",
                        evidence=f"VRFY root: {vrfy_resp.strip()[:100]}",
                        recommendation="Disable VRFY in SMTP configuration.",
                        cwe_id="CWE-200",
                    ))

                # EXPN check
                s.sendall(b"EXPN root\r\n")
                expn_resp = s.recv(1024).decode(errors="replace")
                if expn_resp.startswith("250"):
                    result.add_finding(Finding(
                        title="SMTP EXPN Command Enabled (port 25)",
                        severity=Severity.MEDIUM,
                        category=Category.TCP_ATTACK,
                        description="SMTP EXPN command reveals mailing list members.",
                        evidence=f"EXPN root: {expn_resp.strip()[:100]}",
                        recommendation="Disable EXPN in SMTP configuration.",
                        cwe_id="CWE-200",
                    ))
        except Exception:
            pass

    def _check_redis(self, port: int, result: ScanResult):
        """Check Redis for unauthenticated access."""
        resp = self._grab_banner(port, probe=b"PING\r\n")
        if "+PONG" in resp:
            result.add_finding(Finding(
                title=f"Redis Unauthenticated Access (port {port})",
                severity=Severity.CRITICAL,
                category=Category.TCP_ATTACK,
                description="Redis responds to PING without authentication. "
                            "Attackers can read/write all data and execute commands.",
                evidence=f"PING → {resp[:100]}",
                recommendation="Enable Redis AUTH, bind to 127.0.0.1, and use ACLs.",
                cwe_id="CWE-306",
            ))

        # Check if CONFIG command is available (code execution risk)
        config_resp = self._grab_banner(port, probe=b"CONFIG GET dir\r\n")
        if config_resp and "ERR" not in config_resp and len(config_resp) > 5:
            result.add_finding(Finding(
                title=f"Redis CONFIG Command Accessible (port {port})",
                severity=Severity.CRITICAL,
                category=Category.TCP_ATTACK,
                description="Redis CONFIG command is accessible. Attackers can use "
                            "CONFIG SET to write arbitrary files (e.g. SSH keys, crontabs).",
                evidence=f"CONFIG GET dir → {config_resp[:200]}",
                recommendation="Rename or disable dangerous commands: "
                               "'rename-command CONFIG \"\"' in redis.conf.",
                cwe_id="CWE-78",
            ))

    def _check_memcached(self, port: int, result: ScanResult):
        """Check Memcached for unauthenticated access (amplification risk)."""
        resp = self._grab_banner(port, probe=b"stats\r\n")
        if "STAT" in resp:
            result.add_finding(Finding(
                title=f"Memcached Unauthenticated (port {port})",
                severity=Severity.HIGH,
                category=Category.TCP_ATTACK,
                description="Memcached responds to 'stats' without authentication. "
                            "Can be abused for DDoS amplification and data exfiltration.",
                evidence=f"stats → {resp[:200]}",
                recommendation="Enable SASL authentication. Bind to localhost. "
                               "Firewall port 11211.",
                cwe_id="CWE-306",
            ))

    def _check_mongodb(self, port: int, result: ScanResult):
        """Check if MongoDB is accessible without authentication."""
        # MongoDB wire protocol: send an isMaster command
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((self.host, port))
                # Send a minimal OP_MSG for isMaster (MongoDB 3.6+)
                # If we get any response at all on the raw socket, it's accepting connections
                s.sendall(b"\x00")
                time.sleep(0.5)
                data = s.recv(256)
                if data:
                    result.add_finding(Finding(
                        title=f"MongoDB Accepts Raw TCP Connections (port {port})",
                        severity=Severity.HIGH,
                        category=Category.TCP_ATTACK,
                        description="MongoDB port is reachable and responds to raw TCP. "
                                    "If authentication is not enabled, full database access is possible.",
                        evidence=f"Received {len(data)} bytes on raw connect to port {port}",
                        recommendation="Enable MongoDB authentication (--auth). "
                                       "Bind to 127.0.0.1. Use firewall rules.",
                        cwe_id="CWE-306",
                    ))
        except Exception:
            pass

    def _check_mysql_greeting(self, port: int, result: ScanResult):
        """Check MySQL greeting packet for version disclosure."""
        banner = self._grab_banner(port)
        if banner:
            # MySQL greeting starts with protocol version + server version string
            version_keywords = ["mysql", "mariadb", "percona"]
            if any(kw in banner.lower() for kw in version_keywords):
                result.add_finding(Finding(
                    title=f"MySQL Version Exposed in Greeting (port {port})",
                    severity=Severity.MEDIUM,
                    category=Category.TCP_ATTACK,
                    description="MySQL greeting packet reveals exact server version.",
                    evidence=f"Greeting: {banner[:200]}",
                    recommendation="Configure mysql to suppress version: "
                                   "set 'skip-show-database' and review firewall rules.",
                    cwe_id="CWE-200",
                ))

    def _check_docker_api(self, port: int, result: ScanResult):
        """Check for unauthenticated Docker API."""
        try:
            import urllib.request
            url = f"http://{self.host}:{port}/version"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode(errors="replace")[:2000]
                if "ApiVersion" in body or "Version" in body:
                    result.add_finding(Finding(
                        title=f"Unauthenticated Docker API (port {port})",
                        severity=Severity.CRITICAL,
                        category=Category.TCP_ATTACK,
                        description="Docker daemon API is accessible without TLS or authentication. "
                                    "Full host compromise possible via container escape.",
                        evidence=f"GET /version → {body[:300]}",
                        recommendation="Enable TLS mutual auth on Docker daemon. "
                                       "Never expose port 2375 without protection.",
                        cwe_id="CWE-306",
                    ))
        except Exception:
            pass

    # ── host-level TCP stack checks (via SSH) ────────────────────────────────
    def _check_sysctl(self, key: str) -> Optional[str]:
        out = self._run_remote(f"sysctl -n {key} 2>/dev/null")
        return out.strip() if out else None

    def _check_syn_cookies(self, result: ScanResult):
        """Check if SYN cookies are enabled (SYN flood protection)."""
        val = self._check_sysctl("net.ipv4.tcp_syncookies")
        if val == "0":
            result.add_finding(Finding(
                title="TCP SYN Cookies Disabled",
                severity=Severity.HIGH,
                category=Category.TCP_ATTACK,
                description="SYN cookies are disabled. The server is vulnerable to "
                            "SYN flood denial-of-service attacks.",
                evidence="net.ipv4.tcp_syncookies = 0",
                recommendation="Enable SYN cookies: sysctl -w net.ipv4.tcp_syncookies=1",
                cwe_id="CWE-770",
            ))

    def _check_tcp_timestamps(self, result: ScanResult):
        """Check TCP timestamps (uptime & OS fingerprinting leak)."""
        val = self._check_sysctl("net.ipv4.tcp_timestamps")
        if val == "1":
            result.add_finding(Finding(
                title="TCP Timestamps Enabled",
                severity=Severity.LOW,
                category=Category.TCP_ATTACK,
                description="TCP timestamps reveal system uptime and aid OS fingerprinting. "
                            "Attackers can estimate patch level from uptime.",
                evidence="net.ipv4.tcp_timestamps = 1",
                recommendation="Consider disabling: sysctl -w net.ipv4.tcp_timestamps=0 "
                               "(may affect PAWS and RTT estimation).",
                cwe_id="CWE-200",
            ))

    def _check_ip_forwarding(self, result: ScanResult):
        """Check if IP forwarding is enabled (pivot risk)."""
        for key in ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"]:
            val = self._check_sysctl(key)
            if val == "1":
                result.add_finding(Finding(
                    title=f"IP Forwarding Enabled ({key})",
                    severity=Severity.MEDIUM,
                    category=Category.TCP_ATTACK,
                    description=f"{key} is enabled. Compromised host can be used as "
                                "a network pivot to reach internal systems.",
                    evidence=f"{key} = 1",
                    recommendation=f"Disable unless needed: sysctl -w {key}=0",
                    cwe_id="CWE-441",
                ))

    def _check_source_routing(self, result: ScanResult):
        """Check if source routing is accepted (routing attack vector)."""
        val = self._check_sysctl("net.ipv4.conf.all.accept_source_route")
        if val == "1":
            result.add_finding(Finding(
                title="IP Source Routing Accepted",
                severity=Severity.HIGH,
                category=Category.TCP_ATTACK,
                description="Source routing allows attackers to specify the route "
                            "packets take, bypassing firewalls and ACLs.",
                evidence="net.ipv4.conf.all.accept_source_route = 1",
                recommendation="Disable: sysctl -w net.ipv4.conf.all.accept_source_route=0",
                cwe_id="CWE-441",
            ))

    def _check_icmp_redirect(self, result: ScanResult):
        """Check if ICMP redirects are accepted."""
        val = self._check_sysctl("net.ipv4.conf.all.accept_redirects")
        if val == "1":
            result.add_finding(Finding(
                title="ICMP Redirects Accepted",
                severity=Severity.MEDIUM,
                category=Category.TCP_ATTACK,
                description="ICMP redirect acceptance allows attackers to alter the "
                            "host's routing table via spoofed ICMP messages.",
                evidence="net.ipv4.conf.all.accept_redirects = 1",
                recommendation="Disable: sysctl -w net.ipv4.conf.all.accept_redirects=0",
                cwe_id="CWE-441",
            ))

    def _check_tcp_keepalive(self, result: ScanResult):
        """Check TCP keepalive settings for resource exhaustion."""
        keepalive_time = self._check_sysctl("net.ipv4.tcp_keepalive_time")
        if keepalive_time:
            try:
                seconds = int(keepalive_time)
                if seconds > 7200:
                    result.add_finding(Finding(
                        title=f"TCP Keepalive Too Long ({seconds}s)",
                        severity=Severity.LOW,
                        category=Category.TCP_ATTACK,
                        description=f"tcp_keepalive_time is {seconds}s ({seconds//3600}h). "
                                    "Stale connections consume resources, enabling slowloris-style DoS.",
                        evidence=f"net.ipv4.tcp_keepalive_time = {seconds}",
                        recommendation="Reduce to 600-1800 seconds: "
                                       "sysctl -w net.ipv4.tcp_keepalive_time=600",
                        cwe_id="CWE-400",
                    ))
            except ValueError:
                pass

    def _check_rp_filter(self, result: ScanResult):
        """Check reverse path filtering (IP spoofing protection)."""
        val = self._check_sysctl("net.ipv4.conf.all.rp_filter")
        if val == "0":
            result.add_finding(Finding(
                title="Reverse Path Filtering Disabled",
                severity=Severity.MEDIUM,
                category=Category.TCP_ATTACK,
                description="rp_filter is disabled. The kernel will not validate that "
                            "incoming packets arrive on the expected interface, "
                            "making IP spoofing attacks easier.",
                evidence="net.ipv4.conf.all.rp_filter = 0",
                recommendation="Enable strict mode: sysctl -w net.ipv4.conf.all.rp_filter=1",
                cwe_id="CWE-290",
            ))

    def _check_tcp_window_scaling(self, result: ScanResult):
        """Informational — check TCP window scaling and buffer sizes."""
        wmem = self._check_sysctl("net.ipv4.tcp_wmem")
        rmem = self._check_sysctl("net.ipv4.tcp_rmem")
        if wmem:
            result.raw_output += f"tcp_wmem: {wmem}\n"
        if rmem:
            result.raw_output += f"tcp_rmem: {rmem}\n"

        somaxconn = self._check_sysctl("net.core.somaxconn")
        if somaxconn:
            try:
                val = int(somaxconn)
                if val < 128:
                    result.add_finding(Finding(
                        title=f"Low somaxconn ({val}) — DoS Risk",
                        severity=Severity.MEDIUM,
                        category=Category.TCP_ATTACK,
                        description=f"net.core.somaxconn is {val}. A low listen backlog "
                                    "makes it easy to exhaust with a small SYN flood.",
                        evidence=f"net.core.somaxconn = {val}",
                        recommendation="Increase to at least 1024: "
                                       "sysctl -w net.core.somaxconn=1024",
                        cwe_id="CWE-770",
                    ))
            except ValueError:
                pass

    def _check_cleartext_protocols(self, open_ports: list[int], result: ScanResult):
        """Flag cleartext protocols where encrypted alternatives exist."""
        cleartext_map = {
            21: ("FTP", "SFTP/SCP", "CWE-319"),
            23: ("Telnet", "SSH", "CWE-319"),
            25: ("SMTP", "SMTPS (port 465/587 with STARTTLS)", "CWE-319"),
            80: ("HTTP", "HTTPS (port 443)", "CWE-319"),
            110: ("POP3", "POP3S (port 995)", "CWE-319"),
            143: ("IMAP", "IMAPS (port 993)", "CWE-319"),
            389: ("LDAP", "LDAPS (port 636)", "CWE-319"),
            5900: ("VNC", "VNC over SSH tunnel", "CWE-319"),
        }

        # Don't double-report if encrypted counterpart is also open
        encrypted_counterparts = {21: 22, 23: 22, 80: 443, 110: 995, 143: 993}

        for port in open_ports:
            if port not in cleartext_map:
                continue
            proto, alternative, cwe = cleartext_map[port]
            # Skip if it was already covered in _check_protocol_payload for telnet
            if port == 23:
                continue
            enc_port = encrypted_counterparts.get(port)
            if enc_port and enc_port in open_ports:
                sev = Severity.MEDIUM  # Both open — downgrade severity
            else:
                sev = Severity.HIGH

            result.add_finding(Finding(
                title=f"Cleartext Protocol: {proto} (port {port})",
                severity=sev,
                category=Category.TCP_ATTACK,
                description=f"{proto} on port {port} transmits data in cleartext. "
                            f"Credentials and payloads are visible to network sniffers.",
                evidence=f"TCP port {port} ({proto}) is open",
                recommendation=f"Replace with {alternative}. Firewall port {port} if unused.",
                cwe_id=cwe,
            ))
