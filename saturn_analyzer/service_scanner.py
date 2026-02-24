"""Service security scanner - discovers and tests Saturn and related services."""
import subprocess
import json
from typing import Optional
from .models import Finding, ScanResult, Severity, Category


class ServiceScanner:
    def __init__(self, host: str, user: str, key_path: Optional[str] = None):
        self.host = host
        self.user = user
        self.key_path = key_path

    def scan(self) -> ScanResult:
        result = ScanResult(scanner_name="Service Scanner")

        if not self._can_connect():
            result.success = False
            result.error = "Cannot connect to host via SSH"
            return result

        # 1. Discover running processes
        self._discover_processes(result)

        # 2. Check Saturn specifically
        self._check_saturn(result)

        # 3. Check listening ports from inside
        self._check_listening_ports(result)

        # 4. Check for exposed APIs without auth
        self._check_unauthenticated_apis(result)

        # 5. Check Docker containers
        self._check_docker(result)

        # 6. Check systemd services
        self._check_systemd_services(result)

        # 7. Check for secrets in environment/config
        self._check_secrets_exposure(result)

        # 8. Check OS security
        self._check_os_security(result)

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

    def _discover_processes(self, result: ScanResult):
        output = self._run_remote("ps aux --sort=-%mem | head -30")
        if output:
            result.raw_output += f"--- Running Processes ---\n{output}\n"

    def _check_saturn(self, result: ScanResult):
        # Find Saturn process
        saturn_ps = self._run_remote("ps -ef | grep -i saturn | grep -v grep")
        if not saturn_ps or not saturn_ps.strip():
            result.add_finding(Finding(
                title="Saturn Process Not Found",
                severity=Severity.INFO,
                category=Category.SERVICE,
                description="No Saturn process detected. It may not be running.",
                evidence="ps -ef | grep saturn returned empty",
                recommendation="Verify Saturn is supposed to be running on this host.",
            ))
            return

        result.raw_output += f"--- Saturn Process ---\n{saturn_ps}\n"

        # Check if Saturn is running as root
        if saturn_ps.strip().startswith("root"):
            result.add_finding(Finding(
                title="Saturn Running as Root",
                severity=Severity.CRITICAL,
                category=Category.SERVICE,
                description="Saturn is running as root user. If compromised, "
                            "attacker has full system access.",
                evidence=saturn_ps.strip()[:200],
                recommendation="Create a dedicated service account: "
                               "useradd -r -s /sbin/nologin saturn",
                cwe_id="CWE-250",
            ))

        # Check Saturn port/binding
        saturn_port = self._run_remote(
            "ss -tlnp 2>/dev/null | grep -i saturn || netstat -tlnp 2>/dev/null | grep -i saturn"
        )
        if saturn_port:
            result.raw_output += f"Saturn listening: {saturn_port}\n"
            if "0.0.0.0" in saturn_port or ":::" in saturn_port:
                result.add_finding(Finding(
                    title="Saturn Bound to All Interfaces",
                    severity=Severity.HIGH,
                    category=Category.SERVICE,
                    description="Saturn is listening on all interfaces (0.0.0.0). "
                                "Should bind to localhost or private IP only.",
                    evidence=saturn_port.strip(),
                    recommendation="Configure Saturn to bind to 127.0.0.1 or "
                                   "use a reverse proxy (nginx) with TLS.",
                    cwe_id="CWE-284",
                ))

        # Check if Saturn has auth
        self._probe_saturn_auth(result)

    def _probe_saturn_auth(self, result: ScanResult):
        # Try to access Saturn endpoints without auth from inside the server
        saturn_ports = self._run_remote(
            "ss -tlnp 2>/dev/null | grep -i saturn | awk '{print $4}' | grep -oE '[0-9]+$'"
        )
        if not saturn_ports:
            # Try common ports
            saturn_ports = "8080\n3000\n9090\n4000"

        for port in saturn_ports.strip().split("\n"):
            port = port.strip()
            if not port:
                continue

            # Try unauthenticated access
            response = self._run_remote(
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"http://localhost:{port}/ 2>/dev/null"
            )
            if response and response.strip() in ("200", "301", "302"):
                result.add_finding(Finding(
                    title=f"Saturn Accessible Without Authentication (port {port})",
                    severity=Severity.CRITICAL,
                    category=Category.AUTH,
                    description=f"Saturn on port {port} responds to unauthenticated "
                                "requests. Any user with network access can interact "
                                "with the service.",
                    evidence=f"HTTP {response.strip()} on localhost:{port} without auth",
                    recommendation="Implement authentication (JWT/API key/OAuth2). "
                                   "Add auth middleware before any route handler.",
                    cwe_id="CWE-306",
                ))

            # Try common API paths
            for path in ["/api", "/health", "/metrics", "/debug", "/admin",
                         "/swagger", "/api-docs", "/graphql", "/status"]:
                resp = self._run_remote(
                    f"curl -s -o /dev/null -w '%{{http_code}}' "
                    f"http://localhost:{port}{path} 2>/dev/null"
                )
                if resp and resp.strip() in ("200", "301", "302"):
                    result.add_finding(Finding(
                        title=f"Exposed Endpoint: {path} (port {port})",
                        severity=Severity.HIGH if path in ("/admin", "/debug", "/metrics") else Severity.MEDIUM,
                        category=Category.AUTH,
                        description=f"Endpoint {path} on port {port} is accessible "
                                    "without authentication.",
                        evidence=f"HTTP {resp.strip()} on localhost:{port}{path}",
                        recommendation=f"Protect {path} with authentication or remove "
                                       "if not needed in production.",
                        cwe_id="CWE-306",
                    ))

    def _check_listening_ports(self, result: ScanResult):
        output = self._run_remote("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        if output:
            result.raw_output += f"--- Listening Ports ---\n{output}\n"

            # Check for services on 0.0.0.0
            for line in output.split("\n"):
                if "0.0.0.0" in line and ("mongo" in line.lower() or
                                           "redis" in line.lower() or
                                           "postgres" in line.lower()):
                    result.add_finding(Finding(
                        title="Database Service Bound to All Interfaces",
                        severity=Severity.CRITICAL,
                        category=Category.NETWORK,
                        description="A database service is listening on all interfaces.",
                        evidence=line.strip(),
                        recommendation="Bind database to 127.0.0.1 only.",
                        cwe_id="CWE-200",
                    ))

    def _check_unauthenticated_apis(self, result: ScanResult):
        # Check common ports for HTTP services without auth
        for port in [8080, 3000, 5000, 9090, 4000, 8081, 8090]:
            resp = self._run_remote(
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"http://localhost:{port}/ 2>/dev/null",
                timeout=10,
            )
            if resp and resp.strip() in ("200", "301", "302"):
                result.raw_output += f"Service on port {port}: HTTP {resp.strip()}\n"

    def _check_docker(self, result: ScanResult):
        containers = self._run_remote("docker ps --format '{{.Names}}\\t{{.Image}}\\t{{.Ports}}' 2>/dev/null")
        if containers and containers.strip():
            result.raw_output += f"--- Docker Containers ---\n{containers}\n"

            for line in containers.strip().split("\n"):
                if "0.0.0.0" in line:
                    result.add_finding(Finding(
                        title=f"Docker Container Exposed on All Interfaces",
                        severity=Severity.HIGH,
                        category=Category.NETWORK,
                        description=f"Container is publishing ports on 0.0.0.0.",
                        evidence=line.strip(),
                        recommendation="Use 127.0.0.1:port:port mapping instead of 0.0.0.0.",
                        cwe_id="CWE-284",
                    ))

        # Check if Docker socket is exposed
        docker_sock = self._run_remote("ls -la /var/run/docker.sock 2>/dev/null")
        if docker_sock and "srw" in docker_sock:
            result.raw_output += f"Docker socket: {docker_sock}\n"

    def _check_systemd_services(self, result: ScanResult):
        services = self._run_remote(
            "systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -30"
        )
        if services:
            result.raw_output += f"--- Running Services ---\n{services}\n"

    def _check_secrets_exposure(self, result: ScanResult):
        # Check environment variables for secrets
        env_check = self._run_remote(
            "env 2>/dev/null | grep -iE '(password|secret|key|token|api_key|db_pass)' | wc -l"
        )
        if env_check and int(env_check.strip()) > 0:
            result.add_finding(Finding(
                title="Secrets in Environment Variables",
                severity=Severity.HIGH,
                category=Category.SECRETS,
                description=f"Found {env_check.strip()} environment variables containing "
                            "potential secrets (password, key, token patterns).",
                evidence=f"{env_check.strip()} env vars with secret-like names",
                recommendation="Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) "
                               "instead of environment variables.",
                cwe_id="CWE-798",
            ))

        # Check for .env files
        env_files = self._run_remote(
            "find /home /opt /srv /app -name '.env' -o -name '*.env' 2>/dev/null | head -10"
        )
        if env_files and env_files.strip():
            result.add_finding(Finding(
                title=".env Files Found on Server",
                severity=Severity.MEDIUM,
                category=Category.SECRETS,
                description="Found .env files that may contain secrets.",
                evidence=env_files.strip()[:200],
                recommendation="Move secrets to a secrets manager. "
                               "Ensure .env files are not readable by other users.",
                cwe_id="CWE-538",
            ))

        # Check for hardcoded credentials in config files
        hardcoded = self._run_remote(
            "grep -rlE '(password|passwd|secret)\\s*[:=]\\s*[\"\\x27].{3,}' "
            "/opt /srv /home --include='*.yml' --include='*.yaml' "
            "--include='*.properties' --include='*.conf' 2>/dev/null | head -10"
        )
        if hardcoded and hardcoded.strip():
            result.add_finding(Finding(
                title="Hardcoded Credentials in Configuration Files",
                severity=Severity.CRITICAL,
                category=Category.SECRETS,
                description="Configuration files contain hardcoded passwords/secrets.",
                evidence=f"Files: {hardcoded.strip()[:300]}",
                recommendation="Replace hardcoded credentials with environment variables "
                               "or secrets manager references.",
                cwe_id="CWE-798",
            ))

    def _check_os_security(self, result: ScanResult):
        # Check for unattended upgrades / auto-updates
        updates = self._run_remote(
            "yum check-update 2>/dev/null | grep -c '^[a-zA-Z]' || "
            "apt list --upgradable 2>/dev/null | grep -c upgradable"
        )
        if updates and int(updates.strip()) > 10:
            result.add_finding(Finding(
                title="Pending Security Updates",
                severity=Severity.HIGH,
                category=Category.INFRASTRUCTURE,
                description=f"Found {updates.strip()} pending package updates.",
                evidence=f"{updates.strip()} packages need updating",
                recommendation="Apply security updates: sudo yum update -y",
                cwe_id="CWE-1104",
            ))

        # Check SELinux/AppArmor
        selinux = self._run_remote("getenforce 2>/dev/null || echo disabled")
        if selinux and "disabled" in selinux.lower():
            result.add_finding(Finding(
                title="SELinux Disabled",
                severity=Severity.MEDIUM,
                category=Category.INFRASTRUCTURE,
                description="SELinux is disabled. No mandatory access control.",
                evidence=f"SELinux status: {selinux.strip()}",
                recommendation="Enable SELinux in enforcing mode.",
            ))

        # Check firewall
        firewall = self._run_remote(
            "systemctl is-active firewalld 2>/dev/null || "
            "systemctl is-active ufw 2>/dev/null || "
            "iptables -L -n 2>/dev/null | head -5"
        )
        if firewall and "inactive" in firewall.lower():
            result.add_finding(Finding(
                title="Host Firewall Not Active",
                severity=Severity.HIGH,
                category=Category.INFRASTRUCTURE,
                description="No host-level firewall detected (firewalld/ufw inactive).",
                evidence=f"Firewall status: {firewall.strip()}",
                recommendation="Enable firewalld: sudo systemctl enable --now firewalld",
            ))
