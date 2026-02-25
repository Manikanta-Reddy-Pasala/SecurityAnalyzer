"""Authentication analyzer - comprehensive auth testing for services."""
import subprocess
import socket
import json
import base64
import urllib.request
import urllib.error
from typing import Optional
from .models import Finding, ScanResult, Severity, Category


class AuthAnalyzer:
    """Analyzes authentication mechanisms, session management, and access controls."""

    def __init__(self, host: str, user: str = None, key_path: Optional[str] = None):
        self.host = host
        self.user = user
        self.key_path = key_path

    def scan(self) -> ScanResult:
        result = ScanResult(scanner_name="Auth Analyzer")

        # Discover HTTP services
        ports = self._discover_http_ports()
        result.raw_output += f"HTTP services found on ports: {ports}\n"

        for port in ports:
            self._test_default_credentials(port, result)
            self._test_jwt_vulnerabilities(port, result)
            self._test_session_management(port, result)
            self._test_cors_policy(port, result)
            self._test_api_key_exposure(port, result)
            self._test_auth_bypass_techniques(port, result)
            self._test_rate_limiting(port, result)
            self._test_security_headers(port, result)
            self._test_http_methods(port, result)
            self._test_token_in_url(port, result)
            self._test_cache_control(port, result)

        # SSH auth checks via remote
        if self.user and self._can_connect():
            self._check_pam_config(result)
            self._check_password_policy(result)
            self._check_mfa_setup(result)

        return result

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

    def _run_remote(self, command: str, timeout: int = 30) -> Optional[str]:
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

    def _http_get(self, port: int, path: str, headers: dict = None,
                  timeout: int = 5) -> tuple[int, str, dict]:
        url = f"http://{self.host}:{port}{path}"
        try:
            req = urllib.request.Request(url)
            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_headers = dict(resp.headers)
                return resp.status, resp.read().decode(errors="replace")[:2000], resp_headers
        except urllib.error.HTTPError as e:
            resp_headers = dict(e.headers) if e.headers else {}
            body = ""
            try:
                body = e.read().decode(errors="replace")[:2000]
            except Exception:
                pass
            return e.code, body, resp_headers
        except Exception:
            return 0, "", {}

    def _discover_http_ports(self) -> list[int]:
        ports = []
        for port in [80, 443, 3000, 4000, 5000, 8080, 8081, 8090, 8443, 9090]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    if s.connect_ex((self.host, port)) == 0:
                        ports.append(port)
            except (socket.timeout, OSError):
                pass
        return ports

    def _test_default_credentials(self, port: int, result: ScanResult):
        """Test for default/common credentials on login endpoints."""
        login_paths = ["/login", "/api/login", "/auth/login", "/api/auth/login",
                       "/admin/login", "/api/v1/auth/login"]
        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("test", "test"),
            ("user", "user"),
        ]

        for path in login_paths:
            status, body, _ = self._http_get(port, path)
            if status in (200, 401, 405):
                for username, password in default_creds:
                    try:
                        data = json.dumps({"username": username, "password": password}).encode()
                        url = f"http://{self.host}:{port}{path}"
                        req = urllib.request.Request(url, data=data, method="POST")
                        req.add_header("Content-Type", "application/json")
                        with urllib.request.urlopen(req, timeout=5) as resp:
                            if resp.status == 200:
                                resp_body = resp.read().decode(errors="replace")[:500]
                                if "token" in resp_body.lower() or "session" in resp_body.lower():
                                    result.add_finding(Finding(
                                        title=f"Default Credentials Accepted ({username}:{password})",
                                        severity=Severity.CRITICAL,
                                        category=Category.AUTH,
                                        description=f"Login endpoint {path} on port {port} "
                                                    f"accepts default credentials {username}:{password}.",
                                        evidence=f"HTTP 200 with token/session in response",
                                        recommendation="Change default credentials immediately. "
                                                       "Implement account lockout policy.",
                                        cwe_id="CWE-798",
                                        cvss_score=9.8,
                                    ))
                    except Exception:
                        pass

    def _test_jwt_vulnerabilities(self, port: int, result: ScanResult):
        """Test for JWT implementation weaknesses."""
        # JWT with 'none' algorithm
        none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwiYWRtaW4iOnRydWV9."
        status, body, _ = self._http_get(
            port, "/api/me",
            headers={"Authorization": f"Bearer {none_jwt}"}
        )
        if status == 200:
            result.add_finding(Finding(
                title=f"JWT 'none' Algorithm Accepted (port {port})",
                severity=Severity.CRITICAL,
                category=Category.AUTH,
                description="The service accepts JWT tokens with 'none' algorithm, "
                            "allowing authentication bypass.",
                evidence=f"HTTP 200 with Bearer token using alg:none on port {port}",
                recommendation="Validate JWT algorithm server-side. Reject 'none' algorithm.",
                cwe_id="CWE-345",
                cvss_score=9.1,
            ))

        # Empty JWT
        status, body, _ = self._http_get(
            port, "/api/me",
            headers={"Authorization": "Bearer "}
        )
        if status == 200:
            result.add_finding(Finding(
                title=f"Empty Bearer Token Accepted (port {port})",
                severity=Severity.CRITICAL,
                category=Category.AUTH,
                description="The service accepts empty Bearer tokens.",
                evidence=f"HTTP 200 with empty Bearer token on port {port}",
                recommendation="Validate that Bearer token is non-empty and properly signed.",
                cwe_id="CWE-306",
            ))

        # Expired JWT (exp: 2020-01-01)
        expired_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjoxNTc3ODM2ODAwfQ.invalid"
        status, body, _ = self._http_get(
            port, "/api/me",
            headers={"Authorization": f"Bearer {expired_jwt}"}
        )
        if status == 200:
            result.add_finding(Finding(
                title=f"Expired JWT Token Accepted (port {port})",
                severity=Severity.HIGH,
                category=Category.AUTH,
                description="The service accepts expired JWT tokens.",
                evidence=f"HTTP 200 with expired JWT on port {port}",
                recommendation="Implement and enforce JWT expiration validation.",
                cwe_id="CWE-613",
            ))

    def _test_session_management(self, port: int, result: ScanResult):
        """Test session management security."""
        status, body, headers = self._http_get(port, "/")
        if status == 0:
            return

        # Check Set-Cookie flags
        set_cookie = headers.get("Set-Cookie", "")
        if set_cookie:
            result.raw_output += f"Port {port} Set-Cookie: {set_cookie[:200]}\n"

            if "httponly" not in set_cookie.lower():
                result.add_finding(Finding(
                    title=f"Session Cookie Missing HttpOnly Flag (port {port})",
                    severity=Severity.HIGH,
                    category=Category.AUTH,
                    description="Session cookie does not have HttpOnly flag, "
                                "making it accessible to JavaScript (XSS risk).",
                    evidence=f"Set-Cookie: {set_cookie[:100]}",
                    recommendation="Add HttpOnly flag to session cookies.",
                    cwe_id="CWE-1004",
                ))

            if "secure" not in set_cookie.lower():
                result.add_finding(Finding(
                    title=f"Session Cookie Missing Secure Flag (port {port})",
                    severity=Severity.MEDIUM,
                    category=Category.AUTH,
                    description="Session cookie does not have Secure flag, "
                                "allowing transmission over unencrypted HTTP.",
                    evidence=f"Set-Cookie: {set_cookie[:100]}",
                    recommendation="Add Secure flag to session cookies.",
                    cwe_id="CWE-614",
                ))

            if "samesite" not in set_cookie.lower():
                result.add_finding(Finding(
                    title=f"Session Cookie Missing SameSite Attribute (port {port})",
                    severity=Severity.MEDIUM,
                    category=Category.AUTH,
                    description="Session cookie does not have SameSite attribute, "
                                "increasing CSRF vulnerability risk.",
                    evidence=f"Set-Cookie: {set_cookie[:100]}",
                    recommendation="Add SameSite=Strict or SameSite=Lax to cookies.",
                    cwe_id="CWE-352",
                ))

    def _test_cors_policy(self, port: int, result: ScanResult):
        """Test CORS configuration."""
        status, body, headers = self._http_get(
            port, "/",
            headers={"Origin": "https://evil.com"}
        )
        acao = headers.get("Access-Control-Allow-Origin", "")

        if acao == "*":
            result.add_finding(Finding(
                title=f"Wildcard CORS Policy (port {port})",
                severity=Severity.HIGH,
                category=Category.AUTH,
                description="CORS policy allows any origin (*). This permits "
                            "any website to make authenticated requests.",
                evidence=f"Access-Control-Allow-Origin: *",
                recommendation="Restrict CORS to specific trusted origins.",
                cwe_id="CWE-942",
            ))
        elif acao == "https://evil.com":
            result.add_finding(Finding(
                title=f"CORS Origin Reflection (port {port})",
                severity=Severity.CRITICAL,
                category=Category.AUTH,
                description="CORS policy reflects the Origin header, allowing "
                            "any origin to make authenticated requests.",
                evidence=f"Access-Control-Allow-Origin reflects: https://evil.com",
                recommendation="Implement a whitelist of allowed origins.",
                cwe_id="CWE-942",
                cvss_score=8.0,
            ))

        acac = headers.get("Access-Control-Allow-Credentials", "")
        if acac.lower() == "true" and acao in ("*", "https://evil.com"):
            result.add_finding(Finding(
                title=f"CORS Allows Credentials with Weak Origin (port {port})",
                severity=Severity.CRITICAL,
                category=Category.AUTH,
                description="CORS allows credentials with a permissive origin policy.",
                evidence=f"Allow-Credentials: true, Allow-Origin: {acao}",
                recommendation="Never combine Allow-Credentials with wildcard/reflected origins.",
                cwe_id="CWE-942",
            ))

    def _test_api_key_exposure(self, port: int, result: ScanResult):
        """Check if API keys are exposed in responses."""
        paths = ["/", "/api", "/config", "/env", "/debug", "/health",
                 "/api/config", "/settings", "/.env"]

        for path in paths:
            status, body, _ = self._http_get(port, path)
            if status in (200, 301, 302):
                keywords = ["api_key", "apikey", "api-key", "secret_key",
                            "access_token", "private_key", "aws_secret"]
                for kw in keywords:
                    if kw in body.lower():
                        result.add_finding(Finding(
                            title=f"API Key Exposed in Response ({path}, port {port})",
                            severity=Severity.CRITICAL,
                            category=Category.AUTH,
                            description=f"Response from {path} contains what appears to be "
                                        f"an API key or secret ({kw}).",
                            evidence=f"Keyword '{kw}' found in response from {path}",
                            recommendation="Remove sensitive data from API responses. "
                                           "Use server-side configuration.",
                            cwe_id="CWE-200",
                            cvss_score=8.5,
                        ))
                        break

    def _test_auth_bypass_techniques(self, port: int, result: ScanResult):
        """Test various authentication bypass techniques."""
        # HTTP method override
        for header_name in ["X-HTTP-Method-Override", "X-Method-Override",
                            "X-HTTP-Method"]:
            status, body, _ = self._http_get(
                port, "/admin",
                headers={header_name: "GET"}
            )
            if status == 200:
                result.add_finding(Finding(
                    title=f"Auth Bypass via {header_name} (port {port})",
                    severity=Severity.HIGH,
                    category=Category.AUTH,
                    description=f"Protected endpoint /admin is accessible using "
                                f"{header_name} header.",
                    evidence=f"HTTP 200 with {header_name}: GET",
                    recommendation="Validate HTTP method at the framework level, "
                                   "ignoring override headers.",
                    cwe_id="CWE-287",
                ))

        # Path traversal bypass
        bypass_paths = [
            "/admin/.", "/admin/./", "/./admin",
            "/admin%00", "/admin%20", "/ADMIN",
            "/Admin", "//admin", "/admin;",
        ]
        for path in bypass_paths:
            status, body, _ = self._http_get(port, path)
            if status == 200:
                result.add_finding(Finding(
                    title=f"Auth Bypass via Path Manipulation: {path} (port {port})",
                    severity=Severity.HIGH,
                    category=Category.AUTH,
                    description=f"Protected endpoint is accessible via path manipulation.",
                    evidence=f"HTTP 200 on {path}",
                    recommendation="Normalize URL paths before authorization checks.",
                    cwe_id="CWE-287",
                ))

    def _test_rate_limiting(self, port: int, result: ScanResult):
        """Test for rate limiting on authentication endpoints."""
        login_paths = ["/login", "/api/login", "/auth/login"]
        for path in login_paths:
            status, _, _ = self._http_get(port, path)
            if status == 0:
                continue

            blocked = False
            for i in range(20):
                try:
                    data = json.dumps({"username": "test", "password": f"wrong{i}"}).encode()
                    url = f"http://{self.host}:{port}{path}"
                    req = urllib.request.Request(url, data=data, method="POST")
                    req.add_header("Content-Type", "application/json")
                    urllib.request.urlopen(req, timeout=3)
                except urllib.error.HTTPError as e:
                    if e.code == 429:
                        blocked = True
                        break
                except Exception:
                    break

            if not blocked:
                result.add_finding(Finding(
                    title=f"No Rate Limiting on Login (port {port})",
                    severity=Severity.HIGH,
                    category=Category.AUTH,
                    description=f"Login endpoint {path} on port {port} does not "
                                "implement rate limiting after 20 failed attempts.",
                    evidence=f"20 failed logins to {path} without HTTP 429",
                    recommendation="Implement rate limiting (e.g., 5 attempts per minute). "
                                   "Add account lockout after repeated failures.",
                    cwe_id="CWE-307",
                ))
                break

    def _test_security_headers(self, port: int, result: ScanResult):
        """Check for security-related HTTP headers."""
        status, body, headers = self._http_get(port, "/")
        if status == 0:
            return

        required_headers = {
            "X-Content-Type-Options": ("nosniff", Severity.LOW),
            "X-Frame-Options": (None, Severity.MEDIUM),
            "Strict-Transport-Security": (None, Severity.HIGH),
            "Content-Security-Policy": (None, Severity.MEDIUM),
            "X-XSS-Protection": (None, Severity.LOW),
        }

        for header, (expected_val, severity) in required_headers.items():
            val = headers.get(header, "")
            if not val:
                result.add_finding(Finding(
                    title=f"Missing {header} Header (port {port})",
                    severity=severity,
                    category=Category.AUTH,
                    description=f"Response from port {port} is missing the {header} "
                                "security header.",
                    evidence=f"Header not present in response",
                    recommendation=f"Add {header} header to all responses.",
                    cwe_id="CWE-693",
                ))

    def _test_http_methods(self, port: int, result: ScanResult):
        """Test for dangerous HTTP methods."""
        try:
            url = f"http://{self.host}:{port}/"
            req = urllib.request.Request(url, method="OPTIONS")
            with urllib.request.urlopen(req, timeout=5) as resp:
                allow = resp.headers.get("Allow", "")
                if allow:
                    dangerous = {"PUT", "DELETE", "TRACE", "CONNECT"}
                    allowed_methods = {m.strip().upper() for m in allow.split(",")}
                    exposed = dangerous & allowed_methods
                    if exposed:
                        result.add_finding(Finding(
                            title=f"Dangerous HTTP Methods Allowed on Port {port}",
                            severity=Severity.MEDIUM,
                            category=Category.AUTH,
                            description=f"Server on port {port} allows dangerous HTTP methods: "
                                        f"{', '.join(exposed)}.",
                            evidence=f"Allow: {allow}",
                            recommendation="Disable unnecessary HTTP methods (PUT, DELETE, TRACE).",
                            cwe_id="CWE-749",
                        ))
                    if "TRACE" in allowed_methods:
                        result.add_finding(Finding(
                            title=f"HTTP TRACE Method Enabled on Port {port}",
                            severity=Severity.MEDIUM,
                            category=Category.AUTH,
                            description="TRACE method is enabled, which can be exploited "
                                        "for Cross-Site Tracing (XST) attacks.",
                            evidence=f"Allow header includes TRACE",
                            recommendation="Disable TRACE method in web server configuration.",
                            cwe_id="CWE-693",
                        ))
        except Exception:
            pass

    def _test_token_in_url(self, port: int, result: ScanResult):
        """Check if tokens/sessions are passed via URL parameters."""
        paths_to_check = ["/", "/login", "/api", "/dashboard"]
        for path in paths_to_check:
            status, body, headers = self._http_get(port, path)
            if status in (301, 302):
                location = headers.get("Location", "")
                if any(kw in location.lower() for kw in ["token=", "session=", "auth=", "key="]):
                    result.add_finding(Finding(
                        title=f"Token/Session in URL Redirect (port {port})",
                        severity=Severity.HIGH,
                        category=Category.AUTH,
                        description=f"Redirect from {path} on port {port} includes tokens "
                                    "in the URL, which are logged and visible in browser history.",
                        evidence=f"Location header contains token parameter",
                        recommendation="Pass tokens via headers or POST body, never in URLs.",
                        cwe_id="CWE-598",
                    ))
                    break

    def _test_cache_control(self, port: int, result: ScanResult):
        """Check if sensitive pages have proper cache control."""
        status, body, headers = self._http_get(port, "/")
        if status == 0:
            return

        cache_control = headers.get("Cache-Control", "")
        pragma = headers.get("Pragma", "")

        if not cache_control and not pragma:
            result.add_finding(Finding(
                title=f"No Cache-Control Headers (port {port})",
                severity=Severity.LOW,
                category=Category.AUTH,
                description=f"No Cache-Control or Pragma headers on port {port}. "
                            "Sensitive data may be cached by browsers and proxies.",
                evidence="Missing Cache-Control and Pragma headers",
                recommendation="Add 'Cache-Control: no-store, no-cache' for sensitive pages.",
                cwe_id="CWE-525",
            ))

    def _check_pam_config(self, result: ScanResult):
        """Check PAM authentication configuration."""
        pam_common = self._run_remote("cat /etc/pam.d/common-auth 2>/dev/null || cat /etc/pam.d/system-auth 2>/dev/null")
        if pam_common:
            result.raw_output += f"--- PAM Config ---\n{pam_common[:500]}\n"
            if "pam_faillock" not in pam_common and "pam_tally" not in pam_common:
                result.add_finding(Finding(
                    title="No Account Lockout in PAM",
                    severity=Severity.MEDIUM,
                    category=Category.AUTH,
                    description="PAM is not configured with pam_faillock or pam_tally "
                                "for account lockout after failed login attempts.",
                    evidence="No pam_faillock/pam_tally in PAM config",
                    recommendation="Add pam_faillock to PAM configuration.",
                    cwe_id="CWE-307",
                ))

    def _check_password_policy(self, result: ScanResult):
        """Check password complexity requirements."""
        pwquality = self._run_remote("cat /etc/security/pwquality.conf 2>/dev/null")
        if pwquality:
            result.raw_output += f"--- Password Policy ---\n{pwquality[:500]}\n"
            if "minlen" not in pwquality or "minlen = 0" in pwquality:
                result.add_finding(Finding(
                    title="Weak Password Length Policy",
                    severity=Severity.MEDIUM,
                    category=Category.AUTH,
                    description="No minimum password length configured.",
                    evidence="minlen not set in pwquality.conf",
                    recommendation="Set minlen = 12 in /etc/security/pwquality.conf",
                    cwe_id="CWE-521",
                ))
        else:
            result.add_finding(Finding(
                title="No Password Complexity Policy",
                severity=Severity.MEDIUM,
                category=Category.AUTH,
                description="No password quality configuration found.",
                evidence="pwquality.conf not found",
                recommendation="Install libpwquality and configure password policy.",
                cwe_id="CWE-521",
            ))

    def _check_mfa_setup(self, result: ScanResult):
        """Check for multi-factor authentication setup."""
        google_auth = self._run_remote(
            "rpm -q google-authenticator 2>/dev/null || dpkg -l libpam-google-authenticator 2>/dev/null"
        )
        pam_mfa = self._run_remote("grep -r 'pam_google_authenticator\\|pam_duo\\|pam_yubikey' /etc/pam.d/ 2>/dev/null")

        if not pam_mfa or not pam_mfa.strip():
            result.add_finding(Finding(
                title="No Multi-Factor Authentication (MFA) Configured",
                severity=Severity.HIGH,
                category=Category.AUTH,
                description="No MFA module (Google Authenticator, Duo, YubiKey) "
                            "is configured in PAM.",
                evidence="No MFA PAM modules found in /etc/pam.d/",
                recommendation="Enable MFA for SSH access. Install google-authenticator-libpam "
                               "or configure AWS SSM Session Manager.",
                cwe_id="CWE-308",
            ))
