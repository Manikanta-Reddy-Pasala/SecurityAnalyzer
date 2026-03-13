"""HTTPS & Web Application attack surface scanner.

Checks HTTP security headers, HTTPS enforcement, cookie flags,
CORS misconfigurations, dangerous HTTP methods, and common web
attack vectors like open redirects and clickjacking.
"""
import socket
import ssl
import urllib.request
import urllib.error
from typing import Optional
from .models import Finding, ScanResult, Severity, Category


class HTTPSScanner:
    """Scans for HTTPS and web-application-layer security issues."""

    def __init__(self, host: str, timeout: int = 5):
        self.host = host
        self.timeout = timeout

    # ── public entry point ──────────────────────────────────────────────────
    def scan(self, ports: list[int] = None) -> ScanResult:
        result = ScanResult(scanner_name="HTTPS & Web Attack Scanner")

        if ports is None:
            ports = [80, 443, 3000, 4000, 5000, 8080, 8081, 8090, 8443, 9090]

        http_ports, https_ports = self._classify_ports(ports)
        result.raw_output += f"HTTP ports: {http_ports}, HTTPS ports: {https_ports}\n"

        # ── HTTPS-specific checks ───────────────────────────────────────────
        for port in https_ports:
            self._check_security_headers(port, result, tls=True)
            self._check_hsts(port, result)
            self._check_cookie_flags(port, result, tls=True)
            self._check_cors(port, result, tls=True)
            self._check_dangerous_methods(port, result, tls=True)
            self._check_open_redirect(port, result, tls=True)
            self._check_clickjacking(port, result, tls=True)
            self._check_content_type_sniffing(port, result, tls=True)
            self._check_csp(port, result, tls=True)
            self._check_referrer_policy(port, result, tls=True)
            self._check_permissions_policy(port, result, tls=True)
            self._check_http_version(port, result)

        # ── Plain-HTTP checks ───────────────────────────────────────────────
        for port in http_ports:
            self._check_security_headers(port, result, tls=False)
            self._check_cookie_flags(port, result, tls=False)
            self._check_cors(port, result, tls=False)
            self._check_dangerous_methods(port, result, tls=False)
            self._check_open_redirect(port, result, tls=False)
            self._check_clickjacking(port, result, tls=False)
            self._check_content_type_sniffing(port, result, tls=False)
            self._check_csp(port, result, tls=False)
            self._check_https_enforcement(port, result)

        return result

    # ── helpers ──────────────────────────────────────────────────────────────
    def _classify_ports(self, ports: list[int]) -> tuple[list[int], list[int]]:
        """Return (http_ports, https_ports) that are actually reachable."""
        http_ports, https_ports = [], []
        for port in ports:
            if not self._port_open(port):
                continue
            if self._speaks_tls(port):
                https_ports.append(port)
            else:
                # Check if it at least responds to HTTP
                status, _ = self._http_get(port, "/", tls=False)
                if status > 0:
                    http_ports.append(port)
        return http_ports, https_ports

    def _port_open(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                return s.connect_ex((self.host, port)) == 0
        except (socket.timeout, OSError):
            return False

    def _speaks_tls(self, port: int) -> bool:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((self.host, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.host) as _:
                    return True
        except Exception:
            return False

    def _http_get(self, port: int, path: str, tls: bool = False,
                  extra_headers: dict = None, timeout: int = 5) -> tuple[int, str, dict]:
        """Returns (status, body, headers_dict).  headers_dict keys are lowercased."""
        scheme = "https" if tls else "http"
        url = f"{scheme}://{self.host}:{port}{path}"
        try:
            req = urllib.request.Request(url)
            if extra_headers:
                for k, v in extra_headers.items():
                    req.add_header(k, v)
            ctx = None
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.read().decode(errors="replace")[:4000]
                return resp.status, body, hdrs
        except urllib.error.HTTPError as e:
            hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            body = ""
            try:
                body = e.read().decode(errors="replace")[:4000]
            except Exception:
                pass
            return e.code, body, hdrs
        except Exception:
            return 0, "", {}

    def _http_method(self, port: int, path: str, method: str, tls: bool) -> tuple[int, dict]:
        """Send an arbitrary HTTP method and return (status, headers)."""
        scheme = "https" if tls else "http"
        url = f"{scheme}://{self.host}:{port}{path}"
        try:
            req = urllib.request.Request(url, method=method)
            ctx = None
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                return resp.status, hdrs
        except urllib.error.HTTPError as e:
            hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            return e.code, hdrs
        except Exception:
            return 0, {}

    # ── individual checks ────────────────────────────────────────────────────
    def _check_security_headers(self, port: int, result: ScanResult, tls: bool):
        """Check for missing critical HTTP security headers."""
        status, body, hdrs = self._http_get(port, "/", tls=tls)
        if status == 0:
            return

        scheme = "HTTPS" if tls else "HTTP"
        required_headers = {
            "strict-transport-security": ("Strict-Transport-Security (HSTS)", Severity.HIGH,
                "CWE-319", "Add Strict-Transport-Security header with max-age >= 31536000."),
            "x-content-type-options": ("X-Content-Type-Options", Severity.MEDIUM,
                "CWE-16", "Add 'X-Content-Type-Options: nosniff' header."),
            "x-frame-options": ("X-Frame-Options", Severity.MEDIUM,
                "CWE-1021", "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header."),
            "content-security-policy": ("Content-Security-Policy", Severity.MEDIUM,
                "CWE-693", "Implement a Content-Security-Policy header."),
            "x-xss-protection": ("X-XSS-Protection", Severity.LOW,
                "CWE-79", "Add 'X-XSS-Protection: 1; mode=block' header."),
            "referrer-policy": ("Referrer-Policy", Severity.LOW,
                "CWE-200", "Add 'Referrer-Policy: strict-origin-when-cross-origin'."),
            "permissions-policy": ("Permissions-Policy", Severity.LOW,
                "CWE-16", "Add a Permissions-Policy header to restrict browser features."),
        }

        missing = []
        for hdr_key, (label, sev, cwe, rec) in required_headers.items():
            if hdr_key not in hdrs:
                missing.append(label)
                result.add_finding(Finding(
                    title=f"Missing {label} Header ({scheme} port {port})",
                    severity=sev,
                    category=Category.WEB_ATTACK,
                    description=f"The {label} header is missing on {scheme} port {port}. "
                                f"This weakens browser-side security controls.",
                    evidence=f"Header '{hdr_key}' absent in response from {scheme}://{self.host}:{port}/",
                    recommendation=rec,
                    cwe_id=cwe,
                ))

    def _check_hsts(self, port: int, result: ScanResult):
        """Deep HSTS validation — only on TLS ports."""
        status, body, hdrs = self._http_get(port, "/", tls=True)
        hsts = hdrs.get("strict-transport-security", "")
        if not hsts:
            return  # already reported by _check_security_headers

        # Check max-age is sufficiently long
        try:
            max_age = int([p.split("=")[1] for p in hsts.split(";")
                          if "max-age" in p.lower()][0])
            if max_age < 31536000:
                result.add_finding(Finding(
                    title=f"Weak HSTS max-age ({max_age}s) on port {port}",
                    severity=Severity.MEDIUM,
                    category=Category.WEB_ATTACK,
                    description=f"HSTS max-age is only {max_age}s ({max_age//86400} days). "
                                "Recommended minimum is 31536000 (1 year).",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    recommendation="Set max-age to at least 31536000 and consider adding "
                                   "includeSubDomains and preload directives.",
                    cwe_id="CWE-319",
                ))
        except (IndexError, ValueError):
            pass

        # Missing includeSubDomains
        if "includesubdomains" not in hsts.lower():
            result.add_finding(Finding(
                title=f"HSTS Missing includeSubDomains (port {port})",
                severity=Severity.LOW,
                category=Category.WEB_ATTACK,
                description="HSTS does not include the includeSubDomains directive.",
                evidence=f"Strict-Transport-Security: {hsts}",
                recommendation="Add includeSubDomains to protect all subdomains.",
                cwe_id="CWE-319",
            ))

    def _check_cookie_flags(self, port: int, result: ScanResult, tls: bool):
        """Check Set-Cookie headers for Secure, HttpOnly, SameSite."""
        status, body, hdrs = self._http_get(port, "/", tls=tls)
        if status == 0:
            return

        # urllib merges multiple Set-Cookie into one comma-separated value
        cookie_header = hdrs.get("set-cookie", "")
        if not cookie_header:
            return

        scheme = "HTTPS" if tls else "HTTP"
        cookies = [c.strip() for c in cookie_header.split(",") if "=" in c]

        for cookie in cookies[:5]:
            name = cookie.split("=")[0].strip()
            lower = cookie.lower()

            if tls and "secure" not in lower:
                result.add_finding(Finding(
                    title=f"Cookie '{name}' Missing Secure Flag ({scheme} port {port})",
                    severity=Severity.HIGH,
                    category=Category.WEB_ATTACK,
                    description=f"Cookie '{name}' on HTTPS port {port} does not have "
                                "the Secure flag, allowing transmission over plain HTTP.",
                    evidence=f"Set-Cookie: {cookie[:200]}",
                    recommendation="Add Secure flag to all cookies served over HTTPS.",
                    cwe_id="CWE-614",
                ))

            if "httponly" not in lower:
                result.add_finding(Finding(
                    title=f"Cookie '{name}' Missing HttpOnly Flag ({scheme} port {port})",
                    severity=Severity.MEDIUM,
                    category=Category.WEB_ATTACK,
                    description=f"Cookie '{name}' lacks HttpOnly, making it accessible to JavaScript (XSS risk).",
                    evidence=f"Set-Cookie: {cookie[:200]}",
                    recommendation="Add HttpOnly flag to prevent client-side script access.",
                    cwe_id="CWE-1004",
                ))

            if "samesite" not in lower:
                result.add_finding(Finding(
                    title=f"Cookie '{name}' Missing SameSite ({scheme} port {port})",
                    severity=Severity.MEDIUM,
                    category=Category.WEB_ATTACK,
                    description=f"Cookie '{name}' lacks SameSite attribute, vulnerable to CSRF.",
                    evidence=f"Set-Cookie: {cookie[:200]}",
                    recommendation="Add SameSite=Strict or SameSite=Lax attribute.",
                    cwe_id="CWE-352",
                ))

    def _check_cors(self, port: int, result: ScanResult, tls: bool):
        """Check for overly permissive CORS configuration."""
        scheme = "HTTPS" if tls else "HTTP"
        # Send a cross-origin preflight with a bogus Origin
        status, body, hdrs = self._http_get(
            port, "/", tls=tls,
            extra_headers={"Origin": "https://evil-attacker.com"}
        )
        if status == 0:
            return

        acao = hdrs.get("access-control-allow-origin", "")
        acac = hdrs.get("access-control-allow-credentials", "")

        if acao == "*":
            sev = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
            result.add_finding(Finding(
                title=f"Wildcard CORS Policy ({scheme} port {port})",
                severity=sev,
                category=Category.WEB_ATTACK,
                description=f"Server on {scheme} port {port} returns "
                            "Access-Control-Allow-Origin: * which allows any origin.",
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                recommendation="Restrict CORS to trusted origins. Never combine wildcard "
                               "with Allow-Credentials.",
                cwe_id="CWE-942",
            ))
        elif "evil-attacker.com" in acao:
            result.add_finding(Finding(
                title=f"CORS Reflects Arbitrary Origin ({scheme} port {port})",
                severity=Severity.CRITICAL,
                category=Category.WEB_ATTACK,
                description="Server reflects the attacker-controlled Origin header back in "
                            "Access-Control-Allow-Origin — full CORS bypass.",
                evidence=f"Sent Origin: https://evil-attacker.com, Got ACAO: {acao}",
                recommendation="Validate Origin against an allowlist. Never reflect "
                               "arbitrary origins.",
                cwe_id="CWE-942",
            ))

    def _check_dangerous_methods(self, port: int, result: ScanResult, tls: bool):
        """Check if dangerous HTTP methods are enabled (TRACE, PUT, DELETE)."""
        scheme = "HTTPS" if tls else "HTTP"
        dangerous = {
            "TRACE": (Severity.HIGH, "CWE-693",
                      "TRACE enables Cross-Site Tracing (XST) attacks, leaking cookies/auth headers."),
            "PUT": (Severity.MEDIUM, "CWE-749",
                    "PUT method may allow arbitrary file upload."),
            "DELETE": (Severity.MEDIUM, "CWE-749",
                       "DELETE method may allow resource deletion."),
        }

        # First try OPTIONS to discover allowed methods
        status, resp_hdrs = self._http_method(port, "/", "OPTIONS", tls)
        allowed = resp_hdrs.get("allow", "").upper()
        if allowed:
            for method, (sev, cwe, desc) in dangerous.items():
                if method in allowed:
                    result.add_finding(Finding(
                        title=f"Dangerous HTTP Method {method} Allowed ({scheme} port {port})",
                        severity=sev,
                        category=Category.WEB_ATTACK,
                        description=desc,
                        evidence=f"OPTIONS response Allow: {allowed}",
                        recommendation=f"Disable {method} method in web server configuration.",
                        cwe_id=cwe,
                    ))
            return

        # Fallback: probe TRACE directly
        status, resp_hdrs = self._http_method(port, "/", "TRACE", tls)
        if status in (200, 204):
            sev, cwe, desc = dangerous["TRACE"]
            result.add_finding(Finding(
                title=f"TRACE Method Enabled ({scheme} port {port})",
                severity=sev,
                category=Category.WEB_ATTACK,
                description=desc,
                evidence=f"TRACE / returned HTTP {status}",
                recommendation="Disable TRACE in web server configuration.",
                cwe_id=cwe,
            ))

    def _check_open_redirect(self, port: int, result: ScanResult, tls: bool):
        """Check for open redirect via common query parameter patterns."""
        scheme = "HTTPS" if tls else "HTTP"
        payloads = [
            "/login?next=https://evil.com",
            "/redirect?url=https://evil.com",
            "/?return_to=https://evil.com",
            "/?redirect_uri=https://evil.com",
        ]

        for path in payloads:
            status, body, hdrs = self._http_get(port, path, tls=tls)
            location = hdrs.get("location", "")
            if status in (301, 302, 303, 307, 308) and "evil.com" in location:
                result.add_finding(Finding(
                    title=f"Open Redirect Detected ({scheme} port {port})",
                    severity=Severity.HIGH,
                    category=Category.WEB_ATTACK,
                    description="Server redirects to an attacker-controlled URL via query parameter.",
                    evidence=f"Request: {path} → Location: {location}",
                    recommendation="Validate redirect targets against an allowlist. "
                                   "Never redirect to user-supplied URLs.",
                    cwe_id="CWE-601",
                ))
                break

    def _check_clickjacking(self, port: int, result: ScanResult, tls: bool):
        """Check X-Frame-Options and CSP frame-ancestors together."""
        status, body, hdrs = self._http_get(port, "/", tls=tls)
        if status == 0:
            return

        scheme = "HTTPS" if tls else "HTTP"
        xfo = hdrs.get("x-frame-options", "").upper()
        csp = hdrs.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower() if csp else False

        if not xfo and not has_frame_ancestors:
            result.add_finding(Finding(
                title=f"Clickjacking: No Frame Protection ({scheme} port {port})",
                severity=Severity.MEDIUM,
                category=Category.WEB_ATTACK,
                description="Neither X-Frame-Options nor CSP frame-ancestors is set. "
                            "Page can be embedded in attacker iframes (clickjacking).",
                evidence=f"X-Frame-Options absent, CSP frame-ancestors absent",
                recommendation="Set 'X-Frame-Options: DENY' and CSP 'frame-ancestors none'.",
                cwe_id="CWE-1021",
            ))

    def _check_content_type_sniffing(self, port: int, result: ScanResult, tls: bool):
        """Check for X-Content-Type-Options: nosniff."""
        status, body, hdrs = self._http_get(port, "/", tls=tls)
        if status == 0:
            return

        xcto = hdrs.get("x-content-type-options", "")
        if xcto.lower() != "nosniff":
            return  # already reported by _check_security_headers if missing

        # If present but wrong value
        if xcto and xcto.lower() != "nosniff":
            scheme = "HTTPS" if tls else "HTTP"
            result.add_finding(Finding(
                title=f"Invalid X-Content-Type-Options Value ({scheme} port {port})",
                severity=Severity.MEDIUM,
                category=Category.WEB_ATTACK,
                description=f"X-Content-Type-Options has unexpected value '{xcto}'. "
                            "Only 'nosniff' is valid.",
                evidence=f"X-Content-Type-Options: {xcto}",
                recommendation="Set 'X-Content-Type-Options: nosniff'.",
                cwe_id="CWE-16",
            ))

    def _check_csp(self, port: int, result: ScanResult, tls: bool):
        """Check Content-Security-Policy for dangerous directives."""
        status, body, hdrs = self._http_get(port, "/", tls=tls)
        if status == 0:
            return

        csp = hdrs.get("content-security-policy", "")
        if not csp:
            return  # missing header already reported

        scheme = "HTTPS" if tls else "HTTP"
        dangerous_values = [
            ("unsafe-inline", "Allows inline scripts/styles, defeating CSP purpose", Severity.MEDIUM),
            ("unsafe-eval", "Allows eval() and similar dynamic code execution", Severity.HIGH),
            ("data:", "Allows data: URIs which can be used for XSS", Severity.MEDIUM),
            ("*", "Wildcard source allows loading from any origin", Severity.HIGH),
        ]

        for val, desc, sev in dangerous_values:
            if val in csp:
                result.add_finding(Finding(
                    title=f"Weak CSP: '{val}' Directive ({scheme} port {port})",
                    severity=sev,
                    category=Category.WEB_ATTACK,
                    description=f"Content-Security-Policy contains '{val}'. {desc}.",
                    evidence=f"CSP: {csp[:300]}",
                    recommendation=f"Remove '{val}' from CSP. Use nonce-based or hash-based allowlists.",
                    cwe_id="CWE-693",
                ))

    def _check_referrer_policy(self, port: int, result: ScanResult, tls: bool):
        """Check for unsafe Referrer-Policy."""
        status, body, hdrs = self._http_get(port, "/", tls=tls)
        if status == 0:
            return

        rp = hdrs.get("referrer-policy", "")
        if not rp:
            return  # missing already reported

        scheme = "HTTPS" if tls else "HTTP"
        unsafe = ["unsafe-url", "no-referrer-when-downgrade"]
        if rp.lower().strip() in unsafe:
            result.add_finding(Finding(
                title=f"Unsafe Referrer-Policy '{rp}' ({scheme} port {port})",
                severity=Severity.MEDIUM,
                category=Category.WEB_ATTACK,
                description=f"Referrer-Policy '{rp}' leaks full URL to third parties.",
                evidence=f"Referrer-Policy: {rp}",
                recommendation="Use 'strict-origin-when-cross-origin' or 'no-referrer'.",
                cwe_id="CWE-200",
            ))

    def _check_permissions_policy(self, port: int, result: ScanResult, tls: bool):
        """Warn if Permissions-Policy is present but allows dangerous features."""
        status, body, hdrs = self._http_get(port, "/", tls=tls)
        if status == 0:
            return

        pp = hdrs.get("permissions-policy", "")
        if not pp:
            return  # missing already reported

        scheme = "HTTPS" if tls else "HTTP"
        sensitive_features = ["camera", "microphone", "geolocation", "payment"]
        allowed_all = [f for f in sensitive_features if f"{f}=*" in pp.replace(" ", "")]
        if allowed_all:
            result.add_finding(Finding(
                title=f"Permissions-Policy Allows Sensitive Features ({scheme} port {port})",
                severity=Severity.MEDIUM,
                category=Category.WEB_ATTACK,
                description=f"Permissions-Policy grants unrestricted access to: "
                            f"{', '.join(allowed_all)}.",
                evidence=f"Permissions-Policy: {pp[:300]}",
                recommendation="Restrict sensitive features: camera=(), microphone=(), etc.",
                cwe_id="CWE-16",
            ))

    def _check_https_enforcement(self, port: int, result: ScanResult):
        """Check if plain-HTTP port redirects to HTTPS."""
        status, body, hdrs = self._http_get(port, "/", tls=False)
        if status == 0:
            return

        location = hdrs.get("location", "")
        if status in (301, 302, 307, 308) and location.startswith("https://"):
            return  # good — redirects to HTTPS

        result.add_finding(Finding(
            title=f"No HTTPS Redirect on HTTP Port {port}",
            severity=Severity.HIGH,
            category=Category.WEB_ATTACK,
            description=f"HTTP port {port} serves content without redirecting to HTTPS. "
                        "Users connecting over plain HTTP are vulnerable to MITM attacks.",
            evidence=f"HTTP {status} on port {port}, Location: {location or '(none)'}",
            recommendation="Configure HTTP→HTTPS redirect (301) for all HTTP ports.",
            cwe_id="CWE-319",
        ))

    def _check_http_version(self, port: int, result: ScanResult):
        """Check if server supports HTTP/2 via ALPN (TLS ports only)."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        try:
            with socket.create_connection((self.host, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.host) as tls_sock:
                    proto = tls_sock.selected_alpn_protocol()
                    if proto == "http/1.1":
                        result.add_finding(Finding(
                            title=f"HTTP/2 Not Supported (port {port})",
                            severity=Severity.LOW,
                            category=Category.WEB_ATTACK,
                            description="Server only supports HTTP/1.1 over TLS. "
                                        "HTTP/2 provides better performance and security "
                                        "(header compression, multiplexing).",
                            evidence=f"ALPN negotiated: {proto}",
                            recommendation="Enable HTTP/2 (h2) in web server / load balancer.",
                            cwe_id="CWE-16",
                        ))
        except Exception:
            pass
