"""System payload exposure scanner - detects exposed system data and debug info."""
import subprocess
import socket
import urllib.request
import urllib.error
from typing import Optional
from .models import Finding, ScanResult, Severity, Category


class PayloadScanner:
    """Scans for exposed system payloads, debug endpoints, and information leaks."""

    def __init__(self, host: str, user: str = None, key_path: Optional[str] = None):
        self.host = host
        self.user = user
        self.key_path = key_path

    def scan(self) -> ScanResult:
        result = ScanResult(scanner_name="Payload Exposure Scanner")

        # External checks (HTTP-based)
        ports = self._discover_http_ports()
        result.raw_output += f"Testing ports: {ports}\n"

        for port in ports:
            self._check_debug_endpoints(port, result)
            self._check_error_page_leaks(port, result)
            self._check_stack_trace_exposure(port, result)
            self._check_source_code_exposure(port, result)
            self._check_actuator_endpoints(port, result)
            self._check_graphql_introspection(port, result)
            self._check_api_docs_exposure(port, result)
            self._check_backup_files(port, result)
            self._check_server_info_headers(port, result)
            self._check_robots_sitemap(port, result)

        # Internal checks (SSH-based)
        if self.user and self._can_connect():
            self._check_proc_exposure(result)
            self._check_core_dumps(result)
            self._check_debug_symbols(result)
            self._check_tmp_sensitive_files(result)
            self._check_log_sensitive_data(result)
            self._check_memory_dumps(result)
            self._check_process_env_exposure(result)
            self._check_history_files(result)
            self._check_ssh_keys_exposure(result)

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

    def _http_get(self, port: int, path: str, timeout: int = 5) -> tuple[int, str]:
        url = f"http://{self.host}:{port}{path}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode(errors="replace")[:4000]
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode(errors="replace")[:4000]
            except Exception:
                pass
            return e.code, body
        except Exception:
            return 0, ""

    def _discover_http_ports(self) -> list[int]:
        ports = []
        for port in [80, 443, 3000, 5000, 8080, 8081, 8090, 9090]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    if s.connect_ex((self.host, port)) == 0:
                        ports.append(port)
            except (socket.timeout, OSError):
                pass
        return ports

    def _check_debug_endpoints(self, port: int, result: ScanResult):
        """Check for exposed debug and profiling endpoints."""
        debug_paths = [
            ("/debug", "Debug endpoint"),
            ("/debug/pprof", "Go pprof profiler"),
            ("/debug/pprof/goroutine", "Go goroutine dump"),
            ("/debug/pprof/heap", "Go heap profiler"),
            ("/debug/vars", "Go expvar"),
            ("/_debug", "Hidden debug"),
            ("/trace", "Distributed tracing"),
            ("/metrics", "Prometheus metrics"),
            ("/prometheus", "Prometheus metrics"),
            ("/dump", "Memory dump endpoint"),
            ("/heapdump", "Java heap dump"),
            ("/threaddump", "Java thread dump"),
            ("/jolokia", "JMX over HTTP"),
            ("/console", "Interactive console"),
            ("/shell", "Shell access endpoint"),
        ]

        for path, desc in debug_paths:
            status, body = self._http_get(port, path)
            if status == 200 and len(body) > 10:
                sev = Severity.CRITICAL if path in ("/console", "/shell", "/heapdump", "/jolokia") else Severity.HIGH
                result.add_finding(Finding(
                    title=f"Exposed {desc}: {path} (port {port})",
                    severity=sev,
                    category=Category.PAYLOAD_EXPOSURE,
                    description=f"{desc} is accessible on port {port}. "
                                "Debug endpoints can leak system internals.",
                    evidence=f"HTTP 200 on {path}, response length: {len(body)}",
                    recommendation=f"Disable or protect {path} in production. "
                                   "Use authentication middleware.",
                    cwe_id="CWE-215",
                ))

    def _check_error_page_leaks(self, port: int, result: ScanResult):
        """Check if error pages leak system information."""
        trigger_paths = [
            "/%00", "/nonexistent_path_12345", "/'", "/\"",
            "/;", "/<script>", "/..%00",
        ]

        leak_keywords = [
            "stack trace", "traceback", "exception", "at line",
            "syntax error", "fatal error", "internal server error",
            "django", "flask", "express", "spring", "laravel",
            "/home/", "/opt/", "/var/", "/usr/local/",
            "sqlstate", "mysql", "postgresql", "mongodb",
        ]

        for path in trigger_paths:
            status, body = self._http_get(port, path)
            if not body:
                continue

            body_lower = body.lower()
            leaked_info = [kw for kw in leak_keywords if kw in body_lower]

            if leaked_info and status in (400, 404, 500, 502, 503):
                result.add_finding(Finding(
                    title=f"Error Page Information Leak (port {port})",
                    severity=Severity.HIGH,
                    category=Category.PAYLOAD_EXPOSURE,
                    description=f"Error page on port {port} leaks system information.",
                    evidence=f"Path: {path}, Status: {status}, "
                             f"Leaked: {', '.join(leaked_info[:5])}",
                    recommendation="Configure custom error pages that hide internal details. "
                                   "Disable debug mode in production.",
                    cwe_id="CWE-209",
                ))
                break

    def _check_stack_trace_exposure(self, port: int, result: ScanResult):
        """Check if stack traces are exposed in responses."""
        # Send malformed data to trigger errors
        try:
            url = f"http://{self.host}:{port}/api"
            req = urllib.request.Request(url, data=b"{{invalid json", method="POST")
            req.add_header("Content-Type", "application/json")
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode(errors="replace")[:4000]
                stack_indicators = [
                    "at com.", "at org.", "at java.", "at sun.",  # Java
                    "File \"", "line ", "Traceback",  # Python
                    "at Object.", "at Module.", "at Function.",  # Node.js
                    "#0 ", "in /", "from /",  # C/C++
                ]
                found = [ind for ind in stack_indicators if ind in body]
                if found:
                    result.add_finding(Finding(
                        title=f"Stack Trace Exposed in Error Response (port {port})",
                        severity=Severity.HIGH,
                        category=Category.PAYLOAD_EXPOSURE,
                        description="API error responses contain stack traces, "
                                    "revealing internal code structure and file paths.",
                        evidence=f"Stack trace indicators: {', '.join(found[:3])}",
                        recommendation="Catch all exceptions and return generic error messages. "
                                       "Log stack traces server-side only.",
                        cwe_id="CWE-209",
                    ))
            except Exception:
                pass
        except Exception:
            pass

    def _check_source_code_exposure(self, port: int, result: ScanResult):
        """Check for exposed source code and version control."""
        code_paths = [
            ("/.git/config", "Git configuration"),
            ("/.git/HEAD", "Git HEAD reference"),
            ("/.gitignore", "Git ignore file"),
            ("/.svn/entries", "SVN metadata"),
            ("/.hg/store", "Mercurial metadata"),
            ("/package.json", "Node.js package manifest"),
            ("/composer.json", "PHP Composer manifest"),
            ("/Gemfile", "Ruby Gemfile"),
            ("/requirements.txt", "Python requirements"),
            ("/pom.xml", "Maven POM"),
            ("/web.config", "IIS configuration"),
            ("/.htaccess", "Apache configuration"),
            ("/Dockerfile", "Docker build file"),
            ("/docker-compose.yml", "Docker Compose config"),
            ("/.env.example", "Environment template"),
            ("/config.yml", "Application config"),
            ("/application.properties", "Spring properties"),
            ("/application.yml", "Spring YAML config"),
        ]

        for path, desc in code_paths:
            status, body = self._http_get(port, path)
            if status == 200 and len(body) > 5:
                sev = Severity.CRITICAL if ".git" in path or ".env" in path else Severity.HIGH
                result.add_finding(Finding(
                    title=f"Exposed {desc}: {path} (port {port})",
                    severity=sev,
                    category=Category.PAYLOAD_EXPOSURE,
                    description=f"{desc} is accessible via HTTP on port {port}. "
                                "This may expose source code, credentials, or "
                                "infrastructure details.",
                    evidence=f"HTTP 200 on {path}, size: {len(body)} bytes",
                    recommendation=f"Block access to {path} in web server config. "
                                   "Use .htaccess or nginx location blocks.",
                    cwe_id="CWE-538",
                ))

    def _check_actuator_endpoints(self, port: int, result: ScanResult):
        """Check for exposed Spring Boot Actuator or similar management endpoints."""
        actuator_paths = [
            ("/actuator", "Actuator root"),
            ("/actuator/env", "Environment variables"),
            ("/actuator/configprops", "Configuration properties"),
            ("/actuator/beans", "Spring beans"),
            ("/actuator/mappings", "URL mappings"),
            ("/actuator/httptrace", "HTTP trace"),
            ("/actuator/loggers", "Logger config"),
            ("/actuator/scheduledtasks", "Scheduled tasks"),
            ("/actuator/sessions", "Active sessions"),
            ("/actuator/shutdown", "Shutdown endpoint"),
        ]

        for path, desc in actuator_paths:
            status, body = self._http_get(port, path)
            if status == 200 and len(body) > 10:
                sev = Severity.CRITICAL if path in ("/actuator/env", "/actuator/shutdown", "/actuator/sessions") else Severity.HIGH
                result.add_finding(Finding(
                    title=f"Exposed Actuator: {desc} (port {port})",
                    severity=sev,
                    category=Category.PAYLOAD_EXPOSURE,
                    description=f"Spring Boot Actuator endpoint {path} is accessible "
                                f"without authentication on port {port}.",
                    evidence=f"HTTP 200 on {path}",
                    recommendation="Secure actuator endpoints with Spring Security. "
                                   "Only expose /health and /info publicly.",
                    cwe_id="CWE-200",
                ))

    def _check_graphql_introspection(self, port: int, result: ScanResult):
        """Check if GraphQL introspection is enabled."""
        introspection_query = '{"query":"{ __schema { types { name } } }"}'
        for path in ["/graphql", "/api/graphql", "/query"]:
            try:
                url = f"http://{self.host}:{port}{path}"
                req = urllib.request.Request(url, data=introspection_query.encode(), method="POST")
                req.add_header("Content-Type", "application/json")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = resp.read().decode(errors="replace")[:2000]
                    if "__schema" in body or "__type" in body:
                        result.add_finding(Finding(
                            title=f"GraphQL Introspection Enabled ({path}, port {port})",
                            severity=Severity.MEDIUM,
                            category=Category.PAYLOAD_EXPOSURE,
                            description="GraphQL introspection is enabled, exposing "
                                        "the entire API schema to attackers.",
                            evidence=f"Introspection query returned schema data on {path}",
                            recommendation="Disable GraphQL introspection in production.",
                            cwe_id="CWE-200",
                        ))
            except Exception:
                pass

    def _check_api_docs_exposure(self, port: int, result: ScanResult):
        """Check for exposed API documentation."""
        doc_paths = [
            ("/swagger", "Swagger UI"),
            ("/swagger-ui.html", "Swagger UI HTML"),
            ("/swagger-ui/", "Swagger UI directory"),
            ("/api-docs", "API documentation"),
            ("/v2/api-docs", "Swagger v2 spec"),
            ("/v3/api-docs", "OpenAPI v3 spec"),
            ("/openapi.json", "OpenAPI JSON spec"),
            ("/openapi.yaml", "OpenAPI YAML spec"),
            ("/redoc", "ReDoc UI"),
            ("/graphiql", "GraphiQL IDE"),
        ]

        for path, desc in doc_paths:
            status, body = self._http_get(port, path)
            if status in (200, 301, 302) and len(body) > 10:
                result.add_finding(Finding(
                    title=f"Exposed {desc}: {path} (port {port})",
                    severity=Severity.MEDIUM,
                    category=Category.PAYLOAD_EXPOSURE,
                    description=f"{desc} is publicly accessible on port {port}. "
                                "API documentation reveals endpoint structure and parameters.",
                    evidence=f"HTTP {status} on {path}",
                    recommendation=f"Protect {path} with authentication or disable in production.",
                    cwe_id="CWE-200",
                ))

    def _check_proc_exposure(self, result: ScanResult):
        """/proc filesystem exposure checks."""
        # Check if /proc is world-readable
        proc_check = self._run_remote("cat /proc/1/cmdline 2>/dev/null | tr '\\0' ' '")
        if proc_check and proc_check.strip():
            result.raw_output += f"PID 1 cmdline: {proc_check.strip()[:200]}\n"

        # Check hidepid mount option
        proc_mount = self._run_remote("mount | grep '/proc'")
        if proc_mount and "hidepid" not in proc_mount:
            result.add_finding(Finding(
                title="Process Information Visible to All Users",
                severity=Severity.MEDIUM,
                category=Category.PAYLOAD_EXPOSURE,
                description="/proc is mounted without hidepid. All users can see "
                            "other users' processes, command lines, and environment.",
                evidence="No hidepid in /proc mount options",
                recommendation="Remount /proc with hidepid=2: "
                               "mount -o remount,hidepid=2 /proc",
                cwe_id="CWE-200",
            ))

        # Check for sensitive data in /proc/*/environ
        env_leak = self._run_remote(
            "cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n' | "
            "grep -icE '(PASSWORD|SECRET|TOKEN|API_KEY)' 2>/dev/null"
        )
        if env_leak and int(env_leak.strip()) > 0:
            result.add_finding(Finding(
                title=f"Secrets Exposed in /proc/*/environ ({env_leak.strip()} found)",
                severity=Severity.HIGH,
                category=Category.PAYLOAD_EXPOSURE,
                description=f"Found {env_leak.strip()} secret-like values in process "
                            "environment variables visible via /proc.",
                evidence=f"{env_leak.strip()} sensitive env vars in /proc",
                recommendation="Use a secrets manager instead of environment variables. "
                               "Mount /proc with hidepid=2.",
                cwe_id="CWE-200",
            ))

    def _check_core_dumps(self, result: ScanResult):
        """Check for core dump files that may contain sensitive data."""
        # Check core dump settings
        core_pattern = self._run_remote("cat /proc/sys/kernel/core_pattern 2>/dev/null")
        if core_pattern:
            result.raw_output += f"Core pattern: {core_pattern.strip()}\n"

        ulimit_core = self._run_remote("ulimit -c 2>/dev/null")
        if ulimit_core and ulimit_core.strip() != "0":
            result.add_finding(Finding(
                title="Core Dumps Enabled",
                severity=Severity.HIGH,
                category=Category.PAYLOAD_EXPOSURE,
                description=f"Core dumps are enabled (ulimit -c = {ulimit_core.strip()}). "
                            "Core dumps may contain sensitive data like passwords, "
                            "encryption keys, and tokens from process memory.",
                evidence=f"ulimit -c = {ulimit_core.strip()}",
                recommendation="Disable core dumps: ulimit -c 0 "
                               "or add '* hard core 0' to /etc/security/limits.conf",
                cwe_id="CWE-528",
            ))

        # Find existing core dumps
        core_files = self._run_remote(
            "find / -name 'core' -o -name 'core.*' -o -name '*.core' 2>/dev/null | head -10"
        )
        if core_files and core_files.strip():
            result.add_finding(Finding(
                title="Core Dump Files Found on Disk",
                severity=Severity.CRITICAL,
                category=Category.PAYLOAD_EXPOSURE,
                description="Core dump files found on the filesystem. These contain "
                            "full process memory snapshots including secrets.",
                evidence=core_files.strip()[:300],
                recommendation="Delete core dump files and disable core dumps.",
                cwe_id="CWE-528",
            ))

    def _check_debug_symbols(self, result: ScanResult):
        """Check if binaries have debug symbols (information leak risk)."""
        binaries = self._run_remote(
            "find /opt /srv /app /usr/local/bin -type f -executable 2>/dev/null | head -20"
        )
        if binaries:
            for binary in binaries.strip().split("\n")[:5]:
                binary = binary.strip()
                if not binary:
                    continue
                file_info = self._run_remote(f"file {binary} 2>/dev/null")
                if file_info and "not stripped" in file_info:
                    result.add_finding(Finding(
                        title=f"Binary Not Stripped: {binary}",
                        severity=Severity.MEDIUM,
                        category=Category.PAYLOAD_EXPOSURE,
                        description=f"Binary {binary} contains debug symbols. "
                                    "This aids reverse engineering and exploit development.",
                        evidence=file_info.strip()[:200],
                        recommendation=f"Strip the binary: strip {binary}",
                        cwe_id="CWE-215",
                    ))

    def _check_tmp_sensitive_files(self, result: ScanResult):
        """Check for sensitive files in temp directories."""
        sensitive = self._run_remote(
            "find /tmp /var/tmp -name '*.key' -o -name '*.pem' -o -name '*.p12' "
            "-o -name '*.jks' -o -name '*.env' -o -name '*password*' "
            "-o -name '*secret*' -o -name '*.sql' 2>/dev/null | head -10"
        )
        if sensitive and sensitive.strip():
            result.add_finding(Finding(
                title="Sensitive Files in Temp Directories",
                severity=Severity.HIGH,
                category=Category.PAYLOAD_EXPOSURE,
                description="Found sensitive files (keys, passwords, SQL dumps) "
                            "in world-readable temp directories.",
                evidence=sensitive.strip()[:300],
                recommendation="Remove sensitive files from /tmp. Use secure temp dirs "
                               "with proper permissions.",
                cwe_id="CWE-538",
            ))

    def _check_log_sensitive_data(self, result: ScanResult):
        """Check if logs contain sensitive data."""
        log_check = self._run_remote(
            "grep -rilE '(password|secret|token|api_key|bearer)' "
            "/var/log/ --include='*.log' 2>/dev/null | head -10"
        )
        if log_check and log_check.strip():
            result.add_finding(Finding(
                title="Sensitive Data in Log Files",
                severity=Severity.HIGH,
                category=Category.PAYLOAD_EXPOSURE,
                description="Log files contain potential secrets (password, token, "
                            "api_key patterns detected).",
                evidence=f"Files: {log_check.strip()[:300]}",
                recommendation="Implement log sanitization. Mask sensitive fields "
                               "before logging.",
                cwe_id="CWE-532",
            ))

    def _check_memory_dumps(self, result: ScanResult):
        """Check for memory dump files."""
        dumps = self._run_remote(
            "find / -name '*.hprof' -o -name '*.dmp' -o -name 'heapdump*' "
            "-o -name 'hs_err_*' 2>/dev/null | head -10"
        )
        if dumps and dumps.strip():
            result.add_finding(Finding(
                title="Memory Dump Files Found",
                severity=Severity.CRITICAL,
                category=Category.PAYLOAD_EXPOSURE,
                description="Heap dumps or error files found. These contain full "
                            "process memory including credentials and sensitive data.",
                evidence=dumps.strip()[:300],
                recommendation="Delete memory dump files. Disable automatic heap dumps "
                               "in production.",
                cwe_id="CWE-528",
            ))

    def _check_process_env_exposure(self, result: ScanResult):
        """Check if process environments are broadly accessible."""
        world_readable = self._run_remote(
            "ls -la /proc/*/environ 2>/dev/null | grep -v 'root.*root' | head -5"
        )
        if world_readable and world_readable.strip():
            result.raw_output += f"--- Non-root environ access ---\n{world_readable}\n"

    def _check_backup_files(self, port: int, result: ScanResult):
        """Check for exposed backup files via HTTP."""
        backup_paths = [
            ("/backup.sql", "SQL backup"),
            ("/backup.tar.gz", "Tar backup"),
            ("/backup.zip", "Zip backup"),
            ("/db.sql", "Database dump"),
            ("/database.sql", "Database dump"),
            ("/dump.sql", "Database dump"),
            ("/.backup", "Backup directory"),
            ("/backup/", "Backup directory"),
            ("/data.json", "Data export"),
            ("/export.csv", "Data export"),
            ("/site.tar.gz", "Site archive"),
            ("/wp-config.php.bak", "WordPress config backup"),
            ("/config.php.bak", "Config backup"),
            ("/web.config.bak", "IIS config backup"),
        ]

        for path, desc in backup_paths:
            status, body = self._http_get(port, path)
            if status == 200 and len(body) > 10:
                result.add_finding(Finding(
                    title=f"Exposed Backup File: {path} (port {port})",
                    severity=Severity.CRITICAL,
                    category=Category.PAYLOAD_EXPOSURE,
                    description=f"{desc} is accessible at {path} on port {port}. "
                                "Backup files often contain credentials and full database contents.",
                    evidence=f"HTTP 200 on {path}, size: {len(body)} bytes",
                    recommendation=f"Remove {path} from web root. Block access to backup files.",
                    cwe_id="CWE-530",
                ))

    def _check_server_info_headers(self, port: int, result: ScanResult):
        """Check for information disclosure in response headers."""
        status, body = self._http_get(port, "/")
        if status == 0:
            return

        try:
            import urllib.request
            url = f"http://{self.host}:{port}/"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as resp:
                headers = dict(resp.headers)
                # Check for technology disclosure headers
                disclosure_headers = [
                    "X-AspNet-Version", "X-AspNetMvc-Version",
                    "X-Drupal-Cache", "X-Generator", "X-Runtime",
                    "X-Version", "X-OWA-Version",
                ]
                for hdr in disclosure_headers:
                    if hdr in headers:
                        result.add_finding(Finding(
                            title=f"Technology Disclosure Header: {hdr} (port {port})",
                            severity=Severity.LOW,
                            category=Category.PAYLOAD_EXPOSURE,
                            description=f"Response header {hdr} reveals technology details.",
                            evidence=f"{hdr}: {headers[hdr]}",
                            recommendation=f"Remove {hdr} header from responses.",
                            cwe_id="CWE-200",
                        ))
        except Exception:
            pass

    def _check_robots_sitemap(self, port: int, result: ScanResult):
        """Check robots.txt and sitemap for sensitive path disclosure."""
        status, body = self._http_get(port, "/robots.txt")
        if status == 200 and body:
            result.raw_output += f"robots.txt on port {port}: {body[:300]}\n"
            sensitive_keywords = [
                "admin", "backup", "config", "database", "debug",
                "internal", "private", "secret", "staging", "test",
            ]
            disclosed = []
            for line in body.split("\n"):
                line_lower = line.lower()
                if line_lower.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    for kw in sensitive_keywords:
                        if kw in path.lower():
                            disclosed.append(path)
                            break

            if disclosed:
                result.add_finding(Finding(
                    title=f"Sensitive Paths in robots.txt (port {port})",
                    severity=Severity.MEDIUM,
                    category=Category.PAYLOAD_EXPOSURE,
                    description="robots.txt discloses potentially sensitive paths. "
                                "Attackers use robots.txt to find hidden endpoints.",
                    evidence=f"Sensitive paths: {', '.join(disclosed[:5])}",
                    recommendation="Protect sensitive paths with authentication rather than "
                                   "relying on robots.txt for obscurity.",
                    cwe_id="CWE-200",
                ))

    def _check_history_files(self, result: ScanResult):
        """Check for shell history files with sensitive data."""
        history_files = self._run_remote(
            "find /home /root -name '.*_history' -o -name '.bash_history' "
            "-o -name '.zsh_history' -o -name '.python_history' 2>/dev/null | head -10"
        )
        if history_files and history_files.strip():
            # Check if any contain sensitive commands
            sensitive = self._run_remote(
                "grep -ilE '(password|secret|token|curl.*-u|mysql.*-p|psql.*password)' "
                "/home/*/.bash_history /root/.bash_history 2>/dev/null | head -5"
            )
            if sensitive and sensitive.strip():
                result.add_finding(Finding(
                    title="Sensitive Commands in Shell History",
                    severity=Severity.HIGH,
                    category=Category.PAYLOAD_EXPOSURE,
                    description="Shell history files contain commands with potential "
                                "passwords, tokens, or credentials.",
                    evidence=f"Files: {sensitive.strip()[:200]}",
                    recommendation="Clear history: history -c && rm ~/.bash_history. "
                                   "Set HISTCONTROL=ignorespace to exclude sensitive commands.",
                    cwe_id="CWE-538",
                ))

    def _check_ssh_keys_exposure(self, result: ScanResult):
        """Check for exposed SSH private keys."""
        exposed_keys = self._run_remote(
            "find /home /opt /srv /tmp /var -name 'id_rsa' -o -name 'id_ecdsa' "
            "-o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null | "
            "xargs -I{} sh -c 'test -r {} && echo {}' 2>/dev/null | head -10"
        )
        if exposed_keys and exposed_keys.strip():
            result.add_finding(Finding(
                title="SSH Private Keys Found in Accessible Locations",
                severity=Severity.CRITICAL,
                category=Category.PAYLOAD_EXPOSURE,
                description="SSH private keys found in accessible directories.",
                evidence=exposed_keys.strip()[:300],
                recommendation="Move keys to secure locations with 600 permissions. "
                               "Consider using SSH agent or secrets manager.",
                cwe_id="CWE-538",
            ))
