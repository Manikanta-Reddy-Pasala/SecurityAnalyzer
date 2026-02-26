"""Network security scanner - port scanning, service detection, exposure analysis."""
import json
import socket
import ssl
import subprocess
import concurrent.futures
import urllib.request
import urllib.error
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
                # Infrastructure API ports
                2375, 2376, 2379, 2380, 6443, 8222, 8500, 9000, 9091,
                9200, 9300, 10250, 10255, 50000,
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

        # 11. Infrastructure API security checks
        for finding in self._check_infrastructure_apis():
            result.add_finding(finding)

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

    # ------------------------------------------------------------------
    # Infrastructure API security checks
    # ------------------------------------------------------------------

    def _port_open(self, port: int) -> bool:
        """Return True if the TCP port is open (3-second timeout)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                return s.connect_ex((self.host, port)) == 0
        except OSError:
            return False

    def _http_get(self, url: str, timeout: int = 3,
                  username: str = None, password: str = None,
                  method: str = "GET") -> tuple[Optional[int], Optional[str]]:
        """Perform an HTTP request and return (status_code, body).

        Returns (None, None) on any network / protocol error.
        """
        try:
            req = urllib.request.Request(url, method=method)
            req.add_header("User-Agent", "SecurityAnalyzer/2.0")
            if username is not None and password is not None:
                import base64
                creds = base64.b64encode(
                    f"{username}:{password}".encode()
                ).decode()
                req.add_header("Authorization", f"Basic {creds}")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.read(8192).decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, None
        except Exception:
            return None, None

    def _check_infrastructure_apis(self) -> list[Finding]:
        """Check for exposed infrastructure management APIs."""
        findings: list[Finding] = []

        # 1. Docker API on 2375 (unauthenticated plaintext)
        if self._port_open(2375):
            status, body = self._http_get(f"http://{self.host}:2375/version")
            if status == 200 and body:
                try:
                    data = json.loads(body)
                    version = data.get("Version", "unknown")
                    findings.append(Finding(
                        title="Unauthenticated Docker API Exposed (Port 2375)",
                        severity=Severity.CRITICAL,
                        category=Category.INFRASTRUCTURE,
                        description=(
                            "The Docker daemon is listening on TCP port 2375 without "
                            "any authentication or TLS. An attacker can execute arbitrary "
                            "containers, mount the host filesystem, and achieve full host "
                            "compromise."
                        ),
                        evidence=f"GET http://{self.host}:2375/version → 200 OK, Docker {version}",
                        recommendation=(
                            "Disable TCP socket or enable TLS mutual authentication "
                            "(--tlsverify). Never expose the Docker daemon on a TCP port "
                            "without client certificate authentication."
                        ),
                        cwe_id="CWE-306",
                        cvss_score=10.0,
                    ))
                except (json.JSONDecodeError, ValueError):
                    pass

        # 2. Docker TLS on 2376
        if self._port_open(2376):
            # Try plain HTTP (no TLS) — a 200/4xx response means TLS is NOT enforced
            status, body = self._http_get(f"http://{self.host}:2376/version")
            if status is not None:
                findings.append(Finding(
                    title="Docker API TLS Not Enforced (Port 2376)",
                    severity=Severity.HIGH,
                    category=Category.INFRASTRUCTURE,
                    description=(
                        "Docker is listening on port 2376 (the conventional TLS port) "
                        "but responded to a plain-text HTTP request, indicating TLS is "
                        "not enforced."
                    ),
                    evidence=f"Plain HTTP to {self.host}:2376 returned HTTP {status}",
                    recommendation=(
                        "Configure Docker to require TLS with --tlsverify and restrict "
                        "access using client certificates."
                    ),
                    cwe_id="CWE-319",
                ))
            else:
                # Port is open and rejected plain HTTP — assume TLS is working
                findings.append(Finding(
                    title="Docker TLS API on 2376 (verify auth)",
                    severity=Severity.INFO,
                    category=Category.INFRASTRUCTURE,
                    description=(
                        "Docker TLS API appears to be active on port 2376. "
                        "Verify that mutual TLS (client certificate) authentication is "
                        "required and that the CA is not publicly trusted."
                    ),
                    evidence=f"Port 2376 open; plain HTTP rejected (TLS likely enforced)",
                    recommendation=(
                        "Confirm --tlsverify is set and client certificates are required."
                    ),
                    cwe_id=None,
                ))

        # 3. Kubernetes API Server on 6443 and 8080
        if self._port_open(6443):
            status, body = self._http_get(f"https://{self.host}:6443/version")
            if status == 200 and body:
                try:
                    data = json.loads(body)
                    git_version = data.get("gitVersion", "unknown")
                    # Check anonymous access to namespace list
                    ns_status, _ = self._http_get(
                        f"https://{self.host}:6443/api/v1/namespaces"
                    )
                    if ns_status == 200:
                        findings.append(Finding(
                            title="Kubernetes API Anonymous Access Enabled",
                            severity=Severity.CRITICAL,
                            category=Category.INFRASTRUCTURE,
                            description=(
                                "The Kubernetes API server is publicly reachable and "
                                "allows unauthenticated (anonymous) access. An attacker "
                                "can enumerate all namespaces, pods, secrets, and "
                                "potentially escalate to cluster admin."
                            ),
                            evidence=(
                                f"GET https://{self.host}:6443/api/v1/namespaces → "
                                f"HTTP 200 (no credentials). Kubernetes {git_version}."
                            ),
                            recommendation=(
                                "Disable anonymous authentication: set "
                                "--anonymous-auth=false on the API server. Restrict "
                                "network access to the API server (port 6443) to "
                                "authorised management networks only."
                            ),
                            cwe_id="CWE-306",
                            cvss_score=9.8,
                        ))
                    elif ns_status in (401, 403):
                        findings.append(Finding(
                            title="Kubernetes API Server Exposed (auth required)",
                            severity=Severity.HIGH,
                            category=Category.INFRASTRUCTURE,
                            description=(
                                "The Kubernetes API server on port 6443 is publicly "
                                "reachable but requires authentication. While credentials "
                                "protect the API, its public exposure increases the "
                                "attack surface (brute-force, CVE exploitation)."
                            ),
                            evidence=(
                                f"GET https://{self.host}:6443/version → HTTP 200 "
                                f"({git_version}). /api/v1/namespaces → HTTP {ns_status}."
                            ),
                            recommendation=(
                                "Restrict port 6443 to authorised IP ranges via firewall "
                                "or security groups. Consider placing the API server "
                                "behind a VPN or bastion host."
                            ),
                            cwe_id="CWE-306",
                        ))
                    else:
                        findings.append(Finding(
                            title="Kubernetes API Server Accessible",
                            severity=Severity.CRITICAL,
                            category=Category.INFRASTRUCTURE,
                            description=(
                                "The Kubernetes API server on port 6443 is publicly "
                                "reachable and returned version information."
                            ),
                            evidence=(
                                f"GET https://{self.host}:6443/version → HTTP 200, "
                                f"{git_version}"
                            ),
                            recommendation=(
                                "Restrict network access to the Kubernetes API server."
                            ),
                            cwe_id="CWE-306",
                            cvss_score=9.8,
                        ))
                except (json.JSONDecodeError, ValueError):
                    pass

        if self._port_open(8080):
            # Distinguish Kubernetes insecure port from generic HTTP
            status, body = self._http_get(f"http://{self.host}:8080/version")
            if status == 200 and body and "gitVersion" in body:
                findings.append(Finding(
                    title="Kubernetes API Server Insecure Port (8080) Exposed",
                    severity=Severity.CRITICAL,
                    category=Category.INFRASTRUCTURE,
                    description=(
                        "The Kubernetes API server is listening on the insecure port "
                        "8080 which has no authentication or TLS. Any request is "
                        "accepted as cluster admin."
                    ),
                    evidence=(
                        f"GET http://{self.host}:8080/version → HTTP 200 with "
                        "Kubernetes version data"
                    ),
                    recommendation=(
                        "Disable the insecure port by setting --insecure-port=0 on the "
                        "API server."
                    ),
                    cwe_id="CWE-306",
                    cvss_score=10.0,
                ))

        # 4. Kubelet API on 10250 and 10255
        if self._port_open(10250):
            status, body = self._http_get(f"https://{self.host}:10250/pods")
            if status == 200 and body:
                findings.append(Finding(
                    title="Kubelet API Unauthenticated (Port 10250)",
                    severity=Severity.CRITICAL,
                    category=Category.INFRASTRUCTURE,
                    description=(
                        "The Kubelet API on port 10250 is accessible without "
                        "authentication. An attacker can list all pods on the node, "
                        "execute commands inside running containers, and read secrets "
                        "mounted in pods."
                    ),
                    evidence=(
                        f"GET https://{self.host}:10250/pods → HTTP 200 (no credentials)"
                    ),
                    recommendation=(
                        "Enable Kubelet authentication and authorisation: set "
                        "authentication.anonymous.enabled=false and "
                        "authorization.mode=Webhook in the Kubelet configuration."
                    ),
                    cwe_id="CWE-306",
                    cvss_score=9.8,
                ))

        if self._port_open(10255):
            findings.append(Finding(
                title="Kubelet Read-Only API Exposed (Port 10255)",
                severity=Severity.HIGH,
                category=Category.INFRASTRUCTURE,
                description=(
                    "The Kubelet read-only API on port 10255 is accessible. It exposes "
                    "pod and node metadata without requiring authentication and can be "
                    "used for reconnaissance."
                ),
                evidence=f"Port 10255 (Kubelet read-only) is open on {self.host}",
                recommendation=(
                    "Disable the read-only port by setting --read-only-port=0 in the "
                    "Kubelet configuration."
                ),
                cwe_id="CWE-284",
            ))

        # 5. etcd on 2379 / 2380
        if self._port_open(2379):
            status, body = self._http_get(f"http://{self.host}:2379/version")
            if status == 200 and body:
                findings.append(Finding(
                    title="etcd Cluster API Exposed Without Authentication",
                    severity=Severity.CRITICAL,
                    category=Category.INFRASTRUCTURE,
                    description=(
                        "The etcd key-value store API is publicly accessible on port "
                        "2379 without authentication. etcd stores all Kubernetes cluster "
                        "state including secrets, so unauthenticated access leads to "
                        "full cluster compromise."
                    ),
                    evidence=(
                        f"GET http://{self.host}:2379/version → HTTP 200: {body[:200]}"
                    ),
                    recommendation=(
                        "Enable etcd peer TLS and client certificate authentication. "
                        "Restrict port 2379 to the control-plane nodes only."
                    ),
                    cwe_id="CWE-306",
                    cvss_score=9.8,
                ))

        # 6. HashiCorp Consul on 8500
        if self._port_open(8500):
            status, body = self._http_get(f"http://{self.host}:8500/v1/agent/self")
            if status == 200 and body:
                findings.append(Finding(
                    title="HashiCorp Consul API Exposed",
                    severity=Severity.HIGH,
                    category=Category.INFRASTRUCTURE,
                    description=(
                        "The Consul HTTP API on port 8500 is publicly accessible. "
                        "Consul stores service registry data, health checks, and "
                        "potentially KV secrets."
                    ),
                    evidence=(
                        f"GET http://{self.host}:8500/v1/agent/self → HTTP 200"
                    ),
                    recommendation=(
                        "Enable Consul ACLs (acl.enabled = true) and restrict the "
                        "HTTP API to trusted networks."
                    ),
                    cwe_id="CWE-306",
                ))
                # Check whether ACLs are disabled
                acl_disabled = True
                try:
                    data = json.loads(body)
                    acl_section = data.get("acl") or data.get("DebugConfig", {}).get("ACLsEnabled")
                    if acl_section is True or (
                        isinstance(acl_section, dict) and acl_section.get("enabled") is True
                    ):
                        acl_disabled = False
                except (json.JSONDecodeError, ValueError):
                    pass
                if acl_disabled:
                    findings.append(Finding(
                        title="Consul API ACLs Disabled",
                        severity=Severity.CRITICAL,
                        category=Category.INFRASTRUCTURE,
                        description=(
                            "The Consul API is accessible and ACLs appear to be disabled "
                            "or absent. Any client can read/write service registrations, "
                            "KV entries, and intentions."
                        ),
                        evidence=(
                            f"GET http://{self.host}:8500/v1/agent/self → no ACL "
                            "enabled flag detected in response"
                        ),
                        recommendation=(
                            "Enable ACLs: set acl.enabled = true, acl.default_policy = "
                            "deny, and create bootstrap tokens."
                        ),
                        cwe_id="CWE-306",
                        cvss_score=9.1,
                    ))

        # 7. Prometheus on 9090 / 9091
        for prom_port in (9090, 9091):
            if self._port_open(prom_port):
                status, body = self._http_get(
                    f"http://{self.host}:{prom_port}/api/v1/targets"
                )
                if status == 200 and body:
                    findings.append(Finding(
                        title=f"Prometheus Metrics API Exposed (Port {prom_port})",
                        severity=Severity.MEDIUM,
                        category=Category.INFRASTRUCTURE,
                        description=(
                            f"The Prometheus HTTP API on port {prom_port} is publicly "
                            "accessible without authentication. It exposes internal "
                            "scrape targets, service topology, and metric data that "
                            "can aid attackers in reconnaissance."
                        ),
                        evidence=(
                            f"GET http://{self.host}:{prom_port}/api/v1/targets "
                            "→ HTTP 200"
                        ),
                        recommendation=(
                            "Enable Prometheus authentication (reverse proxy with "
                            "basic/mTLS auth) and restrict access to the metrics port."
                        ),
                        cwe_id="CWE-200",
                    ))
                # Check reload endpoint
                reload_status, _ = self._http_get(
                    f"http://{self.host}:{prom_port}/-/reload", method="POST"
                )
                if reload_status is not None and reload_status not in (404, 405):
                    findings.append(Finding(
                        title=f"Prometheus Config Reload Endpoint Exposed (Port {prom_port})",
                        severity=Severity.HIGH,
                        category=Category.INFRASTRUCTURE,
                        description=(
                            f"The Prometheus /-/reload endpoint on port {prom_port} "
                            "is accessible. An attacker can force a configuration reload "
                            "to redirect scraping, exfiltrate credentials from config "
                            "files, or cause a denial of service."
                        ),
                        evidence=(
                            f"POST http://{self.host}:{prom_port}/-/reload "
                            f"→ HTTP {reload_status}"
                        ),
                        recommendation=(
                            "Disable the lifecycle API (--web.enable-lifecycle=false) "
                            "or protect it behind an authenticated reverse proxy."
                        ),
                        cwe_id="CWE-284",
                    ))

        # 8. Grafana on 3000
        if self._port_open(3000):
            # Try default admin:admin credentials
            status, body = self._http_get(
                f"http://{self.host}:3000/api/org",
                username="admin", password="admin",
            )
            if status == 200:
                findings.append(Finding(
                    title="Grafana Default Credentials (admin/admin)",
                    severity=Severity.CRITICAL,
                    category=Category.INFRASTRUCTURE,
                    description=(
                        "Grafana is accessible with the default admin/admin credentials. "
                        "An attacker can view all dashboards (which may expose internal "
                        "metrics and infrastructure layout), modify alerting, and "
                        "potentially abuse data sources to pivot into internal systems."
                    ),
                    evidence=(
                        f"GET http://{self.host}:3000/api/org with Basic admin:admin "
                        "→ HTTP 200"
                    ),
                    recommendation=(
                        "Change the default admin password immediately. Enable "
                        "GF_AUTH_DISABLE_LOGIN_FORM or configure an SSO provider. "
                        "Restrict port 3000 to trusted networks."
                    ),
                    cwe_id="CWE-798",
                    cvss_score=9.8,
                ))
            else:
                findings.append(Finding(
                    title="Grafana on Port 3000 (verify auth)",
                    severity=Severity.INFO,
                    category=Category.INFRASTRUCTURE,
                    description=(
                        "Grafana appears to be running on port 3000. Default credentials "
                        "were not accepted. Verify that authentication is properly "
                        "configured and that the instance is not accessible from the "
                        "internet."
                    ),
                    evidence=f"Port 3000 open; admin:admin credentials rejected (HTTP {status})",
                    recommendation=(
                        "Ensure strong passwords are set and restrict network access "
                        "to port 3000."
                    ),
                    cwe_id=None,
                ))

        # 9. Jenkins on 8080 / 50000
        if self._port_open(8080):
            status, body = self._http_get(f"http://{self.host}:8080/api/json")
            if status == 200 and body:
                findings.append(Finding(
                    title="Jenkins Anonymous Read Access Enabled",
                    severity=Severity.HIGH,
                    category=Category.INFRASTRUCTURE,
                    description=(
                        "The Jenkins API is accessible without authentication. An "
                        "attacker can enumerate jobs, build history, environment "
                        "variables, and potentially trigger builds."
                    ),
                    evidence=(
                        f"GET http://{self.host}:8080/api/json → HTTP 200 (no credentials)"
                    ),
                    recommendation=(
                        "Disable anonymous access in Jenkins: Manage Jenkins → "
                        "Configure Global Security → enable authentication and set "
                        "anonymous read permission to none."
                    ),
                    cwe_id="CWE-306",
                    cvss_score=8.1,
                ))
            # Check Script Console
            script_status, script_body = self._http_get(
                f"http://{self.host}:8080/script"
            )
            if script_status == 200 and script_body and "Groovy" in script_body:
                findings.append(Finding(
                    title="Jenkins Script Console Exposed",
                    severity=Severity.CRITICAL,
                    category=Category.INFRASTRUCTURE,
                    description=(
                        "The Jenkins Groovy Script Console (/script) is accessible "
                        "without authentication. This allows arbitrary code execution "
                        "on the Jenkins controller with the OS privileges of the Jenkins "
                        "process."
                    ),
                    evidence=(
                        f"GET http://{self.host}:8080/script → HTTP 200 with Groovy "
                        "console content"
                    ),
                    recommendation=(
                        "Restrict the script console to administrators only and enable "
                        "Jenkins authentication. Consider disabling the script console "
                        "in production."
                    ),
                    cwe_id="CWE-306",
                    cvss_score=9.9,
                ))

        if self._port_open(50000):
            findings.append(Finding(
                title="Jenkins JNLP Agent Port Exposed (Port 50000)",
                severity=Severity.MEDIUM,
                category=Category.INFRASTRUCTURE,
                description=(
                    "The Jenkins JNLP agent port 50000 is publicly accessible. "
                    "If the agent secret is weak or was leaked, an attacker could "
                    "register a malicious agent and receive build jobs containing "
                    "secrets."
                ),
                evidence=f"Port 50000 (Jenkins JNLP) is open on {self.host}",
                recommendation=(
                    "Restrict port 50000 to build agent IP ranges only. Consider "
                    "switching to WebSocket-based agents (no port 50000 required)."
                ),
                cwe_id="CWE-284",
            ))

        # 10. SonarQube on 9000
        if self._port_open(9000):
            status, body = self._http_get(
                f"http://{self.host}:9000/api/system/status"
            )
            if status == 200 and body:
                findings.append(Finding(
                    title="SonarQube Detected",
                    severity=Severity.INFO,
                    category=Category.INFRASTRUCTURE,
                    description=(
                        "SonarQube is accessible on port 9000. Code quality and "
                        "security analysis results stored in SonarQube may contain "
                        "sensitive information about internal codebases and known "
                        "vulnerabilities."
                    ),
                    evidence=f"GET http://{self.host}:9000/api/system/status → HTTP 200",
                    recommendation=(
                        "Restrict SonarQube access to authorised users. Enable SSO "
                        "or strong password policies."
                    ),
                    cwe_id=None,
                ))
                # Test default admin:admin credentials via login API
                try:
                    import urllib.parse
                    login_data = urllib.parse.urlencode(
                        {"login": "admin", "password": "admin"}
                    ).encode()
                    req = urllib.request.Request(
                        f"http://{self.host}:9000/api/authentication/login",
                        data=login_data,
                        method="POST",
                    )
                    req.add_header("User-Agent", "SecurityAnalyzer/2.0")
                    req.add_header(
                        "Content-Type", "application/x-www-form-urlencoded"
                    )
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        if resp.status == 200:
                            findings.append(Finding(
                                title="SonarQube Default Credentials (admin/admin)",
                                severity=Severity.CRITICAL,
                                category=Category.INFRASTRUCTURE,
                                description=(
                                    "SonarQube accepted the default admin/admin "
                                    "credentials. An attacker gains full administrative "
                                    "access to all projects, scan results, and can "
                                    "configure webhooks to exfiltrate data."
                                ),
                                evidence=(
                                    f"POST http://{self.host}:9000/api/authentication"
                                    "/login with admin:admin → HTTP 200"
                                ),
                                recommendation=(
                                    "Change the admin password immediately. Enable "
                                    "force-auth mode to prevent anonymous access."
                                ),
                                cwe_id="CWE-798",
                                cvss_score=9.8,
                            ))
                except Exception:
                    pass

        # 11. NATS on 4222 — banner and monitoring port 8222
        if self._port_open(4222):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    s.connect((self.host, 4222))
                    banner = s.recv(2048).decode(errors="replace")
                    if banner and "version" in banner.lower():
                        findings.append(Finding(
                            title="NATS Server Version Disclosed",
                            severity=Severity.MEDIUM,
                            category=Category.NETWORK,
                            description=(
                                "The NATS server banner on port 4222 discloses its "
                                "version number. Version information assists attackers "
                                "in identifying known CVEs for that release."
                            ),
                            evidence=f"NATS banner: {banner[:300]}",
                            recommendation=(
                                "Configure NATS to suppress version information in the "
                                "server INFO message, or restrict port 4222 to "
                                "authorised clients only."
                            ),
                            cwe_id="CWE-200",
                        ))
            except Exception:
                pass

        if self._port_open(8222):
            status, body = self._http_get(f"http://{self.host}:8222/varz")
            if status == 200 and body:
                findings.append(Finding(
                    title="NATS Monitoring API Exposed (Port 8222)",
                    severity=Severity.MEDIUM,
                    category=Category.INFRASTRUCTURE,
                    description=(
                        "The NATS HTTP monitoring endpoint on port 8222 is publicly "
                        "accessible. It exposes server statistics, connected client "
                        "counts, subject subscriptions, and configuration details "
                        "useful for reconnaissance."
                    ),
                    evidence=(
                        f"GET http://{self.host}:8222/varz → HTTP 200"
                    ),
                    recommendation=(
                        "Disable the NATS monitoring port or restrict it to "
                        "internal monitoring systems only."
                    ),
                    cwe_id="CWE-200",
                ))

        # 12. Elasticsearch on 9200 / 9300
        if self._port_open(9200):
            status, body = self._http_get(
                f"http://{self.host}:9200/_cluster/health"
            )
            if status == 200 and body:
                findings.append(Finding(
                    title="Elasticsearch API Unauthenticated (Port 9200)",
                    severity=Severity.CRITICAL,
                    category=Category.INFRASTRUCTURE,
                    description=(
                        "Elasticsearch is accessible on port 9200 without "
                        "authentication. An attacker can read, modify, or delete all "
                        "indexed data and potentially execute arbitrary scripts via the "
                        "scripting API."
                    ),
                    evidence=(
                        f"GET http://{self.host}:9200/_cluster/health → HTTP 200"
                    ),
                    recommendation=(
                        "Enable Elasticsearch security features (xpack.security.enabled"
                        "=true). Require TLS and username/password authentication. "
                        "Restrict port 9200 to application servers only."
                    ),
                    cwe_id="CWE-306",
                    cvss_score=9.8,
                ))
            # Check index listing
            idx_status, idx_body = self._http_get(
                f"http://{self.host}:9200/_cat/indices"
            )
            if idx_status == 200 and idx_body:
                findings.append(Finding(
                    title="Elasticsearch Index List Exposed (/_cat/indices)",
                    severity=Severity.CRITICAL,
                    category=Category.INFRASTRUCTURE,
                    description=(
                        "The Elasticsearch /_cat/indices endpoint is accessible without "
                        "authentication, revealing all index names and document counts. "
                        "This enables targeted data exfiltration."
                    ),
                    evidence=(
                        f"GET http://{self.host}:9200/_cat/indices → HTTP 200, "
                        f"{len(idx_body.splitlines())} indices listed"
                    ),
                    recommendation=(
                        "Enable Elasticsearch authentication and authorisation. Apply "
                        "index-level security to restrict access per user/role."
                    ),
                    cwe_id="CWE-306",
                    cvss_score=9.8,
                ))

        return findings
