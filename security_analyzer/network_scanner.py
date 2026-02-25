"""Network security scanner - port scanning, service detection, exposure analysis."""
import socket
import ssl
import subprocess
import concurrent.futures
from typing import Optional
from .models import Finding, ScanResult, Severity, Category


class NetworkScanner:
    def __init__(self, host: str, timeout: int = 5):
        self.host = host
        self.timeout = timeout

    def scan(self, ports: list[int] = None) -> ScanResult:
        result = ScanResult(scanner_name="Network Scanner")

        if ports is None:
            ports = [
                22, 80, 443, 3000, 4000, 5000, 5100, 8080, 8081, 8090,
                8443, 9090, 8888, 27017, 6379, 4222, 5432, 3306,
            ]

        # 1. DNS & IP resolution
        self._check_dns(result)

        # 2. Port scan
        open_ports = self._scan_ports(ports, result)

        # 3. Check for exposed sensitive services
        self._check_exposed_services(open_ports, result)

        # 4. Check TLS on HTTPS ports
        for port in open_ports:
            if port in (443, 8443):
                self._check_tls(port, result)

        # 5. TLS cipher suite and certificate analysis
        for port in open_ports:
            if port in (443, 8443, 8080, 3000, 9090):
                self._check_tls_ciphers(port, result)
                self._check_certificate_expiry(port, result)

        # 6. HTTP to HTTPS redirect check
        for port in open_ports:
            if port in (80, 8080, 3000, 9090):
                self._check_http_to_https_redirect(port, result)

        # 7. Service banner grabbing
        self._grab_service_banners(open_ports, result)

        # 8. Check if publicly reachable (no VPN/IP whitelist)
        self._check_public_exposure(open_ports, result)

        # 9. DNS zone transfer check
        self._check_dns_zone_transfer(result)

        # 10. Try nmap if available
        self._nmap_scan(result)

        return result

    def _check_dns(self, result: ScanResult):
        try:
            ip = socket.gethostbyname(self.host)
            result.raw_output += f"DNS Resolution: {self.host} -> {ip}\n"

            # Check if it's a public IP
            octets = [int(o) for o in ip.split(".")]
            is_private = (
                octets[0] == 10
                or (octets[0] == 172 and 16 <= octets[1] <= 31)
                or (octets[0] == 192 and octets[1] == 168)
            )
            if not is_private:
                result.add_finding(Finding(
                    title="Public IP Address Detected",
                    severity=Severity.MEDIUM,
                    category=Category.NETWORK,
                    description=f"Host {self.host} resolves to public IP {ip}. "
                                "Public IPs are directly reachable from the internet.",
                    evidence=f"IP: {ip}",
                    recommendation="Use private IPs with VPN/bastion host for UAT environments.",
                    cwe_id="CWE-284",
                ))
        except socket.gaierror:
            result.raw_output += f"DNS Resolution failed for {self.host}\n"

    def _scan_ports(self, ports: list[int], result: ScanResult) -> list[int]:
        open_ports = []

        def check_port(port: int) -> Optional[int]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    if s.connect_ex((self.host, port)) == 0:
                        return port
            except (socket.timeout, OSError):
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_port, p): p for p in ports}
            for future in concurrent.futures.as_completed(futures):
                port = future.result()
                if port is not None:
                    open_ports.append(port)

        open_ports.sort()
        result.raw_output += f"Open ports: {open_ports}\n"

        if not open_ports:
            result.raw_output += "No open ports found (all filtered/closed)\n"
            result.add_finding(Finding(
                title="All Scanned Ports Filtered",
                severity=Severity.INFO,
                category=Category.NETWORK,
                description="No open ports detected from scan origin. "
                            "This could mean security groups are restricting access, "
                            "or the host is unreachable.",
                evidence=f"Scanned {len(ports)} ports, all filtered/closed",
                recommendation="Verify security group rules to confirm intentional filtering.",
            ))

        return open_ports

    def _check_exposed_services(self, open_ports: list[int], result: ScanResult):
        dangerous_ports = {
            27017: ("MongoDB", Severity.CRITICAL),
            6379: ("Redis", Severity.CRITICAL),
            5432: ("PostgreSQL", Severity.HIGH),
            3306: ("MySQL", Severity.HIGH),
            4222: ("NATS", Severity.HIGH),
            9200: ("Elasticsearch", Severity.HIGH),
            2379: ("etcd", Severity.CRITICAL),
            11211: ("Memcached", Severity.HIGH),
        }

        for port in open_ports:
            if port in dangerous_ports:
                svc_name, severity = dangerous_ports[port]
                result.add_finding(Finding(
                    title=f"Exposed {svc_name} Port ({port})",
                    severity=severity,
                    category=Category.NETWORK,
                    description=f"{svc_name} is accessible on port {port}. "
                                "Database and infrastructure services should never be "
                                "exposed to the internet.",
                    evidence=f"Port {port} ({svc_name}) is open",
                    recommendation=f"Block port {port} in security groups. "
                                   f"Use SSH tunneling or VPN for {svc_name} access.",
                    cwe_id="CWE-200",
                ))

    def _check_tls(self, port: int, result: ScanResult):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    result.raw_output += f"TLS on port {port}: {version}\n"

                    if version in ("TLSv1", "TLSv1.1"):
                        result.add_finding(Finding(
                            title=f"Deprecated TLS Version on Port {port}",
                            severity=Severity.HIGH,
                            category=Category.TLS,
                            description=f"Port {port} uses {version} which is deprecated.",
                            evidence=f"TLS version: {version}",
                            recommendation="Upgrade to TLS 1.2 or 1.3.",
                            cwe_id="CWE-326",
                        ))
        except ssl.SSLCertVerificationError as e:
            result.add_finding(Finding(
                title=f"Invalid TLS Certificate on Port {port}",
                severity=Severity.HIGH,
                category=Category.TLS,
                description=f"TLS certificate verification failed on port {port}.",
                evidence=str(e),
                recommendation="Install a valid TLS certificate (Let's Encrypt or CA-signed).",
                cwe_id="CWE-295",
            ))
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

    def _check_public_exposure(self, open_ports: list[int], result: ScanResult):
        if open_ports:
            result.add_finding(Finding(
                title="Services Accessible Without VPN",
                severity=Severity.HIGH,
                category=Category.ACCESS_CONTROL,
                description="Open ports are reachable from the internet without "
                            "requiring VPN connection. UAT environments should not "
                            "be publicly accessible.",
                evidence=f"Open ports from internet: {open_ports}",
                recommendation="Deploy a VPN (WireGuard/OpenVPN) or use AWS "
                               "PrivateLink/VPC peering. Restrict security groups "
                               "to VPN CIDR only.",
                cwe_id="CWE-284",
            ))

    def _check_tls_ciphers(self, port: int, result: ScanResult):
        """Check for weak TLS cipher suites."""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name, proto, bits = cipher
                        result.raw_output += f"TLS cipher on {port}: {cipher_name} ({proto}, {bits} bits)\n"
                        weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]
                        for weak in weak_ciphers:
                            if weak.lower() in cipher_name.lower():
                                result.add_finding(Finding(
                                    title=f"Weak TLS Cipher on Port {port}",
                                    severity=Severity.HIGH,
                                    category=Category.TLS,
                                    description=f"Port {port} uses weak cipher {cipher_name}.",
                                    evidence=f"Cipher: {cipher_name}, Protocol: {proto}, Bits: {bits}",
                                    recommendation="Disable weak ciphers. Use AES-GCM or ChaCha20-Poly1305.",
                                    cwe_id="CWE-327",
                                ))
                                break
                        if bits and bits < 128:
                            result.add_finding(Finding(
                                title=f"Low TLS Key Strength on Port {port} ({bits}-bit)",
                                severity=Severity.HIGH,
                                category=Category.TLS,
                                description=f"TLS cipher on port {port} uses only {bits}-bit key.",
                                evidence=f"Cipher: {cipher_name}, Bits: {bits}",
                                recommendation="Configure minimum 128-bit cipher suites (256-bit preferred).",
                                cwe_id="CWE-326",
                            ))
        except Exception:
            pass

    def _check_certificate_expiry(self, port: int, result: ScanResult):
        """Check TLS certificate expiration."""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                        # Try DER form
                        der_cert = ssock.getpeercert(binary_form=True)
                        if der_cert:
                            result.raw_output += f"Certificate on port {port}: binary form only (self-signed or untrusted)\n"
                        return
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        import datetime as _dt
                        expiry = _dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - _dt.datetime.utcnow()).days
                        result.raw_output += f"Certificate on port {port} expires: {not_after} ({days_left} days)\n"
                        if days_left < 0:
                            result.add_finding(Finding(
                                title=f"Expired TLS Certificate on Port {port}",
                                severity=Severity.CRITICAL,
                                category=Category.TLS,
                                description=f"TLS certificate on port {port} expired {abs(days_left)} days ago.",
                                evidence=f"Expiry: {not_after}",
                                recommendation="Renew the TLS certificate immediately.",
                                cwe_id="CWE-295",
                            ))
                        elif days_left < 30:
                            result.add_finding(Finding(
                                title=f"TLS Certificate Expiring Soon on Port {port} ({days_left} days)",
                                severity=Severity.HIGH,
                                category=Category.TLS,
                                description=f"TLS certificate on port {port} expires in {days_left} days.",
                                evidence=f"Expiry: {not_after}",
                                recommendation="Renew the TLS certificate. Consider automating renewal with certbot.",
                                cwe_id="CWE-295",
                            ))
                    # Check self-signed
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    if issuer == subject:
                        result.add_finding(Finding(
                            title=f"Self-Signed Certificate on Port {port}",
                            severity=Severity.MEDIUM,
                            category=Category.TLS,
                            description=f"Port {port} uses a self-signed certificate.",
                            evidence=f"Issuer == Subject: {issuer.get('commonName', 'unknown')}",
                            recommendation="Use a CA-signed certificate (Let's Encrypt is free).",
                            cwe_id="CWE-295",
                        ))
        except Exception:
            pass

    def _check_http_to_https_redirect(self, port: int, result: ScanResult):
        """Check if HTTP redirects to HTTPS."""
        try:
            import urllib.request
            import urllib.error
            url = f"http://{self.host}:{port}/"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "SecurityAnalyzer/2.0")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                final_url = resp.geturl()
                if not final_url.startswith("https://"):
                    result.add_finding(Finding(
                        title=f"No HTTP to HTTPS Redirect (port {port})",
                        severity=Severity.MEDIUM,
                        category=Category.TLS,
                        description=f"HTTP service on port {port} does not redirect to HTTPS.",
                        evidence=f"HTTP {port} serves content without redirect to HTTPS",
                        recommendation="Configure HTTP to redirect to HTTPS (301 redirect).",
                        cwe_id="CWE-319",
                    ))
        except Exception:
            pass

    def _grab_service_banners(self, open_ports: list[int], result: ScanResult):
        """Grab service banners to detect version information exposure."""
        for port in open_ports[:10]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    s.connect((self.host, port))
                    # Try HTTP probe
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n")
                    banner = s.recv(1024).decode(errors="replace")
                    if banner:
                        result.raw_output += f"Banner port {port}: {banner[:200]}\n"
                        # Check for version disclosure in Server header
                        for line in banner.split("\r\n"):
                            if line.lower().startswith("server:"):
                                server_val = line.split(":", 1)[1].strip()
                                # Check for detailed version info
                                import re
                                if re.search(r'\d+\.\d+', server_val):
                                    result.add_finding(Finding(
                                        title=f"Server Version Disclosed on Port {port}",
                                        severity=Severity.LOW,
                                        category=Category.NETWORK,
                                        description=f"Server header reveals version information on port {port}.",
                                        evidence=f"Server: {server_val}",
                                        recommendation="Remove version from Server header. "
                                                       "Use 'server_tokens off' (nginx) or "
                                                       "'ServerTokens Prod' (Apache).",
                                        cwe_id="CWE-200",
                                    ))
                            if line.lower().startswith("x-powered-by:"):
                                result.add_finding(Finding(
                                    title=f"X-Powered-By Header Exposed on Port {port}",
                                    severity=Severity.LOW,
                                    category=Category.NETWORK,
                                    description=f"X-Powered-By header reveals technology stack on port {port}.",
                                    evidence=line.strip(),
                                    recommendation="Remove X-Powered-By header from responses.",
                                    cwe_id="CWE-200",
                                ))
            except Exception:
                pass

    def _check_dns_zone_transfer(self, result: ScanResult):
        """Check if DNS zone transfer is possible."""
        try:
            proc = subprocess.run(
                ["host", "-t", "axfr", self.host, self.host],
                capture_output=True, text=True, timeout=10,
            )
            if proc.returncode == 0 and "Transfer" not in proc.stderr:
                if len(proc.stdout.strip().split("\n")) > 2:
                    result.add_finding(Finding(
                        title="DNS Zone Transfer Allowed",
                        severity=Severity.HIGH,
                        category=Category.NETWORK,
                        description="DNS zone transfer (AXFR) is allowed, exposing all DNS records.",
                        evidence=f"Zone transfer returned records",
                        recommendation="Disable zone transfers or restrict to authorized secondaries.",
                        cwe_id="CWE-200",
                    ))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    def _nmap_scan(self, result: ScanResult):
        try:
            proc = subprocess.run(
                ["nmap", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            if proc.returncode == 0:
                # nmap is available, do a service version scan on common ports
                proc = subprocess.run(
                    ["nmap", "-sV", "-T4", "--top-ports", "100",
                     "-oN", "-", self.host],
                    capture_output=True, text=True, timeout=120,
                )
                result.raw_output += f"\n--- nmap output ---\n{proc.stdout}\n"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            result.raw_output += "nmap not available, skipping advanced scan\n"
