"""Service security scanner - discovers and tests running services."""
import subprocess
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

        self._discover_processes(result)
        self._check_root_services(result)
        self._check_listening_ports(result)
        self._check_unauthenticated_apis(result)
        self._check_docker(result)
        self._check_container_security(result)
        self._check_systemd_services(result)
        self._check_secrets_exposure(result)
        self._check_os_security(result)
        self._check_file_permissions(result)
        self._check_user_accounts(result)
        self._check_cron_jobs(result)
        self._check_open_file_descriptors(result)
        self._check_world_writable_files(result)

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

    def _check_root_services(self, result: ScanResult):
        root_procs = self._run_remote(
            "ps -eo user,pid,comm --sort=-%mem | awk '$1==\"root\"' | head -20"
        )
        if root_procs:
            result.raw_output += f"--- Root Processes ---\n{root_procs}\n"
            app_keywords = ["node", "python", "java", "ruby", "go", "nginx", "apache", "httpd"]
            for line in root_procs.strip().split("\n"):
                for kw in app_keywords:
                    if kw in line.lower():
                        result.add_finding(Finding(
                            title=f"Application Service Running as Root ({kw})",
                            severity=Severity.CRITICAL,
                            category=Category.SERVICE,
                            description=f"A {kw} process is running as root. If compromised, "
                                        "attacker has full system access.",
                            evidence=line.strip()[:200],
                            recommendation=f"Create a dedicated service account: "
                                           f"useradd -r -s /sbin/nologin {kw}-svc",
                            cwe_id="CWE-250",
                        ))
                        break

        bound_all = self._run_remote("ss -tlnp 2>/dev/null | grep '0.0.0.0' | head -20")
        if bound_all:
            for line in bound_all.strip().split("\n"):
                if line.strip():
                    result.add_finding(Finding(
                        title="Service Bound to All Interfaces",
                        severity=Severity.HIGH,
                        category=Category.SERVICE,
                        description="A service is listening on all interfaces (0.0.0.0). "
                                    "Should bind to localhost or private IP only.",
                        evidence=line.strip(),
                        recommendation="Configure the service to bind to 127.0.0.1 or "
                                       "use a reverse proxy (nginx) with TLS.",
                        cwe_id="CWE-284",
                    ))

        self._probe_service_auth(result)

    def _probe_service_auth(self, result: ScanResult):
        listening = self._run_remote(
            "ss -tlnp 2>/dev/null | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un"
        )
        if not listening:
            listening = "8080\n3000\n9090\n4000"

        for port in listening.strip().split("\n")[:10]:
            port = port.strip()
            if not port:
                continue

            response = self._run_remote(
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"http://localhost:{port}/ 2>/dev/null"
            )
            if response and response.strip() in ("200", "301", "302"):
                result.add_finding(Finding(
                    title=f"Service Accessible Without Authentication (port {port})",
                    severity=Severity.CRITICAL,
                    category=Category.AUTH,
                    description=f"Service on port {port} responds to unauthenticated "
                                "requests. Any user with network access can interact "
                                "with the service.",
                    evidence=f"HTTP {response.strip()} on localhost:{port} without auth",
                    recommendation="Implement authentication (JWT/API key/OAuth2). "
                                   "Add auth middleware before any route handler.",
                    cwe_id="CWE-306",
                ))

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
                        title="Docker Container Exposed on All Interfaces",
                        severity=Severity.HIGH,
                        category=Category.NETWORK,
                        description="Container is publishing ports on 0.0.0.0.",
                        evidence=line.strip(),
                        recommendation="Use 127.0.0.1:port:port mapping instead of 0.0.0.0.",
                        cwe_id="CWE-284",
                    ))

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

    def _check_container_security(self, result: ScanResult):
        """Check Docker/container security configuration."""
        # Docker daemon configuration
        docker_config = self._run_remote("cat /etc/docker/daemon.json 2>/dev/null")
        if docker_config and docker_config.strip():
            result.raw_output += f"--- Docker Config ---\n{docker_config[:500]}\n"
            if '"userns-remap"' not in docker_config:
                result.add_finding(Finding(
                    title="Docker User Namespace Remapping Disabled",
                    severity=Severity.MEDIUM,
                    category=Category.SERVICE,
                    description="Docker is not configured with user namespace remapping. "
                                "Container root maps to host root.",
                    evidence="userns-remap not in daemon.json",
                    recommendation="Enable user namespace remapping in /etc/docker/daemon.json.",
                    cwe_id="CWE-250",
                ))
            if '"no-new-privileges"' not in docker_config:
                result.add_finding(Finding(
                    title="Docker no-new-privileges Not Set",
                    severity=Severity.MEDIUM,
                    category=Category.SERVICE,
                    description="Docker default security option no-new-privileges is not set.",
                    evidence="no-new-privileges not in daemon.json",
                    recommendation='Add "no-new-privileges": true to daemon.json default security opts.',
                ))

        # Privileged containers
        priv_containers = self._run_remote(
            "docker inspect $(docker ps -q) 2>/dev/null | "
            "python3 -c \"import sys,json;[print(c['Name']) for c in json.load(sys.stdin) "
            "if c.get('HostConfig',{}).get('Privileged')]\" 2>/dev/null"
        )
        if priv_containers and priv_containers.strip():
            result.add_finding(Finding(
                title="Privileged Docker Containers Running",
                severity=Severity.CRITICAL,
                category=Category.SERVICE,
                description="Containers running in privileged mode have full host access.",
                evidence=f"Privileged containers: {priv_containers.strip()[:200]}",
                recommendation="Remove --privileged flag. Use specific capabilities instead.",
                cwe_id="CWE-250",
            ))

        # Docker socket exposure
        docker_sock_mount = self._run_remote(
            "docker inspect $(docker ps -q) 2>/dev/null | "
            "grep -l 'docker.sock' 2>/dev/null | head -5"
        )
        if docker_sock_mount and "docker.sock" in docker_sock_mount:
            result.add_finding(Finding(
                title="Docker Socket Mounted in Container",
                severity=Severity.CRITICAL,
                category=Category.SERVICE,
                description="Docker socket is mounted inside a container, "
                            "allowing container escape and full host control.",
                evidence="docker.sock found in container mounts",
                recommendation="Remove docker.sock mount. Use Docker API proxy with restricted access.",
                cwe_id="CWE-269",
            ))

    def _check_file_permissions(self, result: ScanResult):
        """Check critical file and directory permissions."""
        perm_checks = [
            ("/etc/shadow", "640", "Shadow password file"),
            ("/etc/passwd", "644", "Password file"),
            ("/etc/sudoers", "440", "Sudoers file"),
            ("/etc/crontab", "644", "System crontab"),
            ("/etc/ssh/sshd_config", "600", "SSH daemon config"),
        ]

        for filepath, expected, desc in perm_checks:
            perms = self._run_remote(f"stat -c '%a' {filepath} 2>/dev/null")
            if perms:
                actual = perms.strip()
                if int(actual) > int(expected):
                    result.add_finding(Finding(
                        title=f"Overly Permissive: {filepath}",
                        severity=Severity.HIGH,
                        category=Category.ACCESS_CONTROL,
                        description=f"{desc} ({filepath}) has permissions {actual}, "
                                    f"should be {expected} or stricter.",
                        evidence=f"Permissions: {actual} (expected: {expected})",
                        recommendation=f"chmod {expected} {filepath}",
                        cwe_id="CWE-732",
                    ))

        # Check /home directory permissions
        home_perms = self._run_remote(
            "ls -ld /home/*/ 2>/dev/null | awk '{print $1, $3, $9}'"
        )
        if home_perms:
            for line in home_perms.strip().split("\n"):
                if line.strip() and ("rwxrwxrwx" in line or "rwxrwxr-x" in line):
                    result.add_finding(Finding(
                        title=f"Home Directory Too Permissive: {line.split()[-1] if line.split() else 'unknown'}",
                        severity=Severity.MEDIUM,
                        category=Category.ACCESS_CONTROL,
                        description="Home directory is world-readable or world-writable.",
                        evidence=line.strip(),
                        recommendation="Set home directories to 700: chmod 700 /home/<user>",
                        cwe_id="CWE-732",
                    ))

    def _check_user_accounts(self, result: ScanResult):
        """Audit user accounts for security issues."""
        # Users with UID 0 (root equivalents)
        uid0 = self._run_remote("awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null")
        if uid0:
            users = [u.strip() for u in uid0.strip().split("\n") if u.strip()]
            if len(users) > 1:
                result.add_finding(Finding(
                    title=f"Multiple UID 0 Accounts ({len(users)})",
                    severity=Severity.CRITICAL,
                    category=Category.ACCESS_CONTROL,
                    description="Multiple accounts have UID 0 (root privileges).",
                    evidence=f"UID 0 accounts: {', '.join(users)}",
                    recommendation="Remove or change UID for non-root accounts with UID 0.",
                    cwe_id="CWE-250",
                ))

        # Users with empty passwords
        empty_pw = self._run_remote(
            "sudo awk -F: '($2 == \"\" || $2 == \"!\") {print $1}' /etc/shadow 2>/dev/null"
        )
        if empty_pw and empty_pw.strip():
            accounts = empty_pw.strip().split("\n")
            real_accounts = [a.strip() for a in accounts if a.strip() and a.strip() not in ("*", "!")]
            if real_accounts:
                result.add_finding(Finding(
                    title=f"Accounts with Empty/No Password ({len(real_accounts)})",
                    severity=Severity.CRITICAL,
                    category=Category.ACCESS_CONTROL,
                    description="Accounts found with empty or no password set.",
                    evidence=f"Accounts: {', '.join(real_accounts[:5])}",
                    recommendation="Set passwords or lock unused accounts: passwd -l <user>",
                    cwe_id="CWE-521",
                ))

        # Users with login shell that shouldn't have one
        shell_users = self._run_remote(
            "awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)/ {print $1\":\"$7}' /etc/passwd 2>/dev/null"
        )
        if shell_users:
            login_users = [u.strip() for u in shell_users.strip().split("\n") if u.strip()]
            if len(login_users) > 5:
                result.add_finding(Finding(
                    title=f"Excessive Login-Capable Accounts ({len(login_users)})",
                    severity=Severity.MEDIUM,
                    category=Category.ACCESS_CONTROL,
                    description=f"Found {len(login_users)} accounts with login shells. "
                                "Service accounts should use /sbin/nologin.",
                    evidence=f"Login accounts: {', '.join(login_users[:5])}...",
                    recommendation="Set shell to /sbin/nologin for service accounts.",
                    cwe_id="CWE-284",
                ))

    def _check_cron_jobs(self, result: ScanResult):
        """Audit cron jobs for security issues."""
        # Check for world-writable cron scripts
        cron_writable = self._run_remote(
            "find /etc/cron* /var/spool/cron -writable 2>/dev/null | head -10"
        )
        if cron_writable and cron_writable.strip():
            result.add_finding(Finding(
                title="Writable Cron Files/Directories",
                severity=Severity.HIGH,
                category=Category.ACCESS_CONTROL,
                description="Cron files or directories are writable by current user. "
                            "Attacker could modify scheduled tasks for privilege escalation.",
                evidence=cron_writable.strip()[:300],
                recommendation="Fix permissions on cron files: chmod 600 for crontabs.",
                cwe_id="CWE-732",
            ))

        # Check cron jobs running as root with writable scripts
        root_cron = self._run_remote(
            "sudo cat /etc/crontab /var/spool/cron/root 2>/dev/null | "
            "grep -vE '^#|^$' | head -20"
        )
        if root_cron:
            result.raw_output += f"--- Root Cron Jobs ---\n{root_cron[:500]}\n"

    def _check_open_file_descriptors(self, result: ScanResult):
        """Check for excessive open file descriptors (resource exhaustion)."""
        fd_count = self._run_remote(
            "cat /proc/sys/fs/file-nr 2>/dev/null"
        )
        if fd_count:
            parts = fd_count.strip().split()
            if len(parts) >= 3:
                used = int(parts[0])
                maximum = int(parts[2])
                pct = (used / maximum * 100) if maximum > 0 else 0
                result.raw_output += f"File descriptors: {used}/{maximum} ({pct:.1f}%)\n"
                if pct > 80:
                    result.add_finding(Finding(
                        title=f"High File Descriptor Usage ({pct:.0f}%)",
                        severity=Severity.HIGH,
                        category=Category.SERVICE,
                        description=f"System is using {pct:.0f}% of available file descriptors "
                                    f"({used}/{maximum}). May cause service failures.",
                        evidence=f"file-nr: {fd_count.strip()}",
                        recommendation="Increase fs.file-max or investigate file descriptor leaks.",
                    ))

    def _check_world_writable_files(self, result: ScanResult):
        """Check for world-writable files in critical directories."""
        ww_files = self._run_remote(
            "find /etc /opt /srv /usr/local -xdev -perm -0002 -type f 2>/dev/null | head -15"
        )
        if ww_files and ww_files.strip():
            count = len(ww_files.strip().split("\n"))
            result.add_finding(Finding(
                title=f"World-Writable Files in System Directories ({count})",
                severity=Severity.HIGH,
                category=Category.ACCESS_CONTROL,
                description="World-writable files found in system directories. "
                            "Any user can modify these files.",
                evidence=ww_files.strip()[:300],
                recommendation="Remove world-writable permission: chmod o-w <file>",
                cwe_id="CWE-732",
            ))
