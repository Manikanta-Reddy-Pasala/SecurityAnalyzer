"""Deep secrets scanner - 50+ regex patterns for credentials, tokens, keys across the system."""
import re
import subprocess
from typing import Optional
from .models import Finding, ScanResult, Severity, Category

# ---------------------------------------------------------------------------
# 50+ secret detection patterns  (pattern, severity, description)
# ---------------------------------------------------------------------------
SECRET_PATTERNS: dict[str, tuple[str, Severity]] = {
    # Cloud provider keys
    "AWS Access Key ID":
        (r'\bAKIA[0-9A-Z]{16}\b', Severity.CRITICAL),
    "AWS Secret Access Key":
        (r'(?i)aws[_\-\s]{0,10}secret[_\-\s]{0,10}(access[_\-\s]{0,5})?key[\s:="\'"]{1,5}([A-Za-z0-9/+]{40})\b', Severity.CRITICAL),
    "AWS Session Token":
        (r'\bAsia[0-9A-Z]{16}\b', Severity.CRITICAL),
    "GCP Service Account Key":
        (r'"type"\s*:\s*"service_account"', Severity.CRITICAL),
    "GCP API Key":
        (r'\bAIza[0-9A-Za-z\-_]{35}\b', Severity.HIGH),
    "Azure Client Secret":
        (r'(?i)azure[_\-\s]{0,10}(client[_\-\s]{0,5})?secret[\s:="\'"]{1,5}([A-Za-z0-9\-_~]{34,40})', Severity.CRITICAL),

    # Source control tokens
    "GitHub Personal Access Token":
        (r'\bghp_[0-9a-zA-Z]{36}\b', Severity.CRITICAL),
    "GitHub OAuth Token":
        (r'\bgho_[0-9a-zA-Z]{36}\b', Severity.CRITICAL),
    "GitHub App Token":
        (r'\bghu_[0-9a-zA-Z]{36}\b', Severity.CRITICAL),
    "GitHub Fine-grained PAT":
        (r'\bgithub_pat_[0-9a-zA-Z_]{82}\b', Severity.CRITICAL),
    "GitLab Personal Access Token":
        (r'\bglpat-[0-9a-zA-Z\-]{20}\b', Severity.CRITICAL),
    "GitLab CI Job Token":
        (r'\bglcbt-[0-9a-zA-Z\-]{20}\b', Severity.HIGH),
    "Bitbucket App Password":
        (r'\bATBB[0-9a-zA-Z]{24}\b', Severity.HIGH),

    # Payment & commerce
    "Stripe Live Secret Key":
        (r'\bsk_live_[0-9a-zA-Z]{24,}\b', Severity.CRITICAL),
    "Stripe Test Secret Key":
        (r'\bsk_test_[0-9a-zA-Z]{24,}\b', Severity.MEDIUM),
    "Stripe Webhook Secret":
        (r'\bwhsec_[0-9a-zA-Z]{32,}\b', Severity.HIGH),
    "PayPal Client Secret":
        (r'(?i)paypal[_\-\s]{0,10}(client[_\-\s]{0,5})?secret[\s:="\'"]{1,5}([A-Za-z0-9\-_]{32,64})', Severity.HIGH),

    # Messaging & communication
    "Slack Bot Token":
        (r'\bxoxb-[0-9A-Z]{10,13}-[0-9A-Z]{10,13}-[0-9a-zA-Z]{24}\b', Severity.HIGH),
    "Slack User Token":
        (r'\bxoxp-[0-9A-Z]{10,13}-[0-9A-Z]{10,13}-[0-9A-Z]{10,13}-[0-9a-fA-F]{32}\b', Severity.HIGH),
    "Slack Webhook URL":
        (r'https://hooks\.slack\.com/services/T[0-9A-Z]{8,10}/B[0-9A-Z]{8,10}/[0-9a-zA-Z]{24}', Severity.HIGH),
    "Twilio Account SID":
        (r'\bAC[0-9a-f]{32}\b', Severity.HIGH),
    "Twilio Auth Token":
        (r'(?i)twilio[_\-\s]{0,10}(auth[_\-\s]{0,5})?token[\s:="\'"]{1,5}([0-9a-f]{32})', Severity.HIGH),
    "SendGrid API Key":
        (r'\bSG\.[0-9a-zA-Z\-_]{22,}\.[0-9a-zA-Z\-_]{43,}\b', Severity.HIGH),
    "Mailgun API Key":
        (r'\bkey-[0-9a-z]{32}\b', Severity.HIGH),

    # Authentication & sessions
    "JWT Token (live)":
        (r'\beyJ[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=+/]{10,}', Severity.MEDIUM),
    "HTTP Basic Auth in URL":
        (r'https?://[^:/@\s"\']{3,}:[^@/\s"\']{3,}@[^\s"\']+', Severity.HIGH),
    "OAuth Client Secret":
        (r'(?i)client[_\-\s]{0,5}secret[\s:="\'"]{1,5}([a-zA-Z0-9\-_]{16,64})', Severity.HIGH),

    # Cryptographic material
    "RSA Private Key":
        (r'-----BEGIN RSA PRIVATE KEY-----', Severity.CRITICAL),
    "EC Private Key":
        (r'-----BEGIN EC PRIVATE KEY-----', Severity.CRITICAL),
    "OpenSSH Private Key":
        (r'-----BEGIN OPENSSH PRIVATE KEY-----', Severity.CRITICAL),
    "Generic Private Key":
        (r'-----BEGIN (DSA |ENCRYPTED )?PRIVATE KEY-----', Severity.CRITICAL),
    "PGP Private Key":
        (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', Severity.CRITICAL),
    "Certificate With Key":
        (r'-----BEGIN CERTIFICATE-----[\s\S]{100,}-----BEGIN.*PRIVATE KEY-----', Severity.CRITICAL),

    # Database connection strings
    "PostgreSQL DSN with password":
        (r'postgresql?://[^:/@\s"\']+:[^@\s"\'/<>{}\[\]]{3,}@[^\s"\']+', Severity.CRITICAL),
    "MySQL DSN with password":
        (r'mysql://[^:/@\s"\']+:[^@\s"\'/<>{}\[\]]{3,}@[^\s"\']+', Severity.CRITICAL),
    "MongoDB DSN with password":
        (r'mongodb(\+srv)?://[^:/@\s"\']+:[^@\s"\'/<>{}\[\]]{3,}@[^\s"\']+', Severity.CRITICAL),
    "Redis DSN with password":
        (r'redis://:[^@\s"\'/<>{}\[\]]{3,}@[^\s"\']+', Severity.HIGH),
    "JDBC connection string with password":
        (r'jdbc:[a-z]+://[^\s"\']+password=[^\s"\'&;]+', Severity.CRITICAL),

    # Infrastructure & DevOps
    "HashiCorp Vault Token":
        (r'\bhvs\.[A-Za-z0-9_\-]{90,}\b', Severity.CRITICAL),
    "Kubernetes Service Account Token":
        (r'eyJhbGciOiJSUzI1NiIsImtpZCI[A-Za-z0-9\-_=.]+', Severity.HIGH),
    "NPM Auth Token":
        (r'//[a-z0-9\-]+\.npmjs\.(?:com|org)/:_authToken=[A-Za-z0-9\-_]{36,}', Severity.HIGH),
    "PyPI Token":
        (r'\bpypi-[A-Za-z0-9_\-]{50,}\b', Severity.HIGH),
    "Docker Registry Password in config.json":
        (r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"', Severity.HIGH),
    "Terraform Cloud Token":
        (r'\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{64,}\b', Severity.CRITICAL),

    # Generic high-confidence patterns
    "High-entropy secret in variable":
        (r'(?i)(?:password|passwd|secret|token|api[_\-]?key|auth[_\-]?key|access[_\-]?key)'
         r'[\s]*[=:]\s*["\']?[A-Za-z0-9+/\-_!@#$%^&*]{20,}["\']?', Severity.HIGH),
    "Private key passphrase in config":
        (r'(?i)(?:key[_\-]?pass|passphrase|pkcs12[_\-]?pass)[\s]*[=:]\s*["\']?[^\s"\'<>]{8,}',
         Severity.HIGH),
}

# File extensions to scan (source code + config)
SCAN_EXTENSIONS = (
    "*.py", "*.js", "*.ts", "*.java", "*.go", "*.rb", "*.php", "*.cs",
    "*.yml", "*.yaml", "*.json", "*.xml", "*.toml", "*.ini", "*.conf",
    "*.cfg", "*.properties", "*.env", "*.env.*", ".env",
    "*.tf", "*.tfvars", "*.sh", "*.bash",
)

# Directories to exclude from filesystem scan
EXCLUDE_DIRS = (
    "/proc", "/sys", "/dev", "/run", "/snap",
    "node_modules", ".git", "__pycache__", "vendor", ".tox",
)


class SecretsScanner:
    """Hunts for secrets, credentials, and private keys across the system."""

    def __init__(self, host: str, user: str, key_path: Optional[str] = None):
        self.host = host
        self.user = user
        self.key_path = key_path

    def scan(self) -> ScanResult:
        result = ScanResult(scanner_name="Secrets Scanner")
        can_ssh = self._can_connect()
        result.raw_output += f"SSH access: {'yes' if can_ssh else 'no'}\n\n"

        if can_ssh:
            self._check_filesystem_secrets(result)
            self._check_git_history_secrets(result)
            self._check_process_env_secrets(result)
            self._check_credential_files(result)
            self._check_private_key_files(result)
            self._check_docker_secrets(result)
            self._check_kubernetes_secrets(result)
            self._check_terraform_state(result)

        return result

    # ---------------------------------------------------------------- helpers

    def _can_connect(self) -> bool:
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
               "-o", "ConnectTimeout=10", "-o", "BatchMode=yes"]
        if self.key_path:
            cmd.extend(["-i", self.key_path])
        cmd.extend([f"{self.user}@{self.host}", "echo ok"])
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=15).returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def _run_remote(self, command: str, timeout: int = 60) -> Optional[str]:
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

    def _mask(self, value: str) -> str:
        """Show first 6 + last 4 chars, mask the middle."""
        v = value.strip()
        if len(v) <= 12:
            return v[:3] + "***"
        return v[:6] + "***" + v[-4:]

    # ------------------------------------------------- Filesystem secret scan

    def _check_filesystem_secrets(self, result: ScanResult):
        result.raw_output += "--- Filesystem Secrets Scan ---\n"

        # Build exclude args for grep
        exclude_dirs = " ".join(f"--exclude-dir='{d}'" for d in EXCLUDE_DIRS)
        ext_includes  = " ".join(f"--include='{e}'" for e in SCAN_EXTENSIONS)

        # Search dirs: discovered app dirs + common locations
        search_dirs = "/opt /srv /app /home /var/www /etc /root /data /apps 2>/dev/null"

        found_types: set[str] = set()

        for label, (pattern, severity) in SECRET_PATTERNS.items():
            # Use grep -Prl to find matching files (don't output content, just paths)
            files_out = self._run_remote(
                f"grep -Prl {exclude_dirs} {ext_includes} "
                f"'{pattern}' {search_dirs} 2>/dev/null | head -8",
                timeout=45,
            )
            if not files_out or not files_out.strip():
                continue

            files = [f.strip() for f in files_out.strip().splitlines() if f.strip()]
            if not files:
                continue

            # Get one matching line per file (masked) for evidence
            evidence_lines = []
            for f in files[:3]:
                match_line = self._run_remote(
                    f"grep -Pm1 '{pattern}' '{f}' 2>/dev/null | head -c 200"
                )
                if match_line and match_line.strip():
                    # Mask the actual secret value — show just enough to confirm
                    masked = re.sub(pattern, lambda m: self._mask(m.group(0)), match_line.strip())
                    evidence_lines.append(f"{f}: {masked[:120]}")

            result.raw_output += f"  [{label}] in: {', '.join(files[:3])}\n"
            found_types.add(label)

            result.add_finding(Finding(
                title=f"Secret Exposed in Source/Config: {label}",
                severity=severity,
                category=Category.SECRETS,
                description=(
                    f"Pattern matching '{label}' found in {len(files)} file(s). "
                    "Hardcoded secrets in source code or config files can be "
                    "extracted by anyone with read access to those files."
                ),
                evidence="\n".join(evidence_lines)[:400] or f"Files: {', '.join(files[:3])}",
                recommendation=(
                    "Remove the secret from the file immediately. Rotate the credential. "
                    "Use environment variables, a secrets manager (Vault, AWS Secrets Manager), "
                    "or sealed secrets. Add the pattern to .gitignore and pre-commit hooks."
                ),
                cwe_id="CWE-798",
            ))

        if not found_types:
            result.raw_output += "  No hardcoded secrets detected in source/config files\n"

    # ------------------------------------------------- Git history scan

    def _check_git_history_secrets(self, result: ScanResult):
        result.raw_output += "\n--- Git History Secrets Scan ---\n"

        # Find all git repos on the system
        repos = self._run_remote(
            "find /opt /srv /app /home /var/www /root /data "
            "-name '.git' -type d -maxdepth 8 2>/dev/null | head -15"
        )
        if not repos or not repos.strip():
            result.raw_output += "  No git repositories found\n"
            return

        repo_dirs = [r.strip().rstrip("/.git").rstrip("/.git/") + "/.git"
                     for r in repos.strip().splitlines() if r.strip()]

        for git_dir in repo_dirs[:5]:
            work_dir = git_dir.rstrip("/.git")
            result.raw_output += f"  Scanning git history: {work_dir}\n"

            # Build combined pattern for git log search
            combined_pattern = "|".join(
                p for p, _ in list(SECRET_PATTERNS.values())[:20]  # limit for speed
            )

            # git log --all -p scans ALL commits across ALL branches
            git_scan = self._run_remote(
                f"cd '{work_dir}' && git log --all -p --follow "
                f"--diff-filter=A -- . 2>/dev/null | "
                f"grep -Pm5 -E '({combined_pattern})' | head -20",
                timeout=60,
            )
            if git_scan and git_scan.strip() and "fatal:" not in git_scan:
                # Count unique commit matches
                commit_count = self._run_remote(
                    f"cd '{work_dir}' && git log --all --oneline 2>/dev/null | wc -l"
                )
                result.add_finding(Finding(
                    title=f"Secrets Found in Git History: {work_dir}",
                    severity=Severity.CRITICAL,
                    category=Category.SECRETS,
                    description=(
                        f"Secret patterns were found in the git commit history of {work_dir}. "
                        "Even if the secret was later deleted from the codebase, it remains "
                        "permanently accessible in git history to anyone who can clone the repo."
                    ),
                    evidence=git_scan.strip()[:400],
                    recommendation=(
                        "Use 'git filter-repo' or BFG Repo Cleaner to purge secrets from history. "
                        "Rotate ALL credentials found — treat them as compromised. "
                        "Force-push cleaned history and invalidate all existing clones."
                    ),
                    cwe_id="CWE-540",
                    cvss_score=9.1,
                ))
            else:
                result.raw_output += f"    No secrets in history (scanned {commit_count.strip() if 'commit_count' in dir() else '?'} commits)\n"

    # --------------------------------------- Running process environment scan

    def _check_process_env_secrets(self, result: ScanResult):
        result.raw_output += "\n--- Process Environment Secrets ---\n"

        # Scan /proc/*/environ for all processes
        pattern_str = "|".join([
            r'(?i)(AWS_SECRET|AWS_ACCESS_KEY)',
            r'(?i)(GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN)',
            r'(?i)(DATABASE_URL|DB_PASSWORD|DB_PASS)',
            r'(?i)(STRIPE_|SENDGRID_|TWILIO_AUTH)',
            r'(?i)(API_KEY|API_SECRET|AUTH_TOKEN|ACCESS_TOKEN)',
            r'(?i)(PRIVATE_KEY|SECRET_KEY|JWT_SECRET)',
            r'(?i)(REDIS_PASSWORD|MONGO_PASSWORD|POSTGRES_PASSWORD)',
            r'(?i)(VAULT_TOKEN|K8S_TOKEN|KUBECONFIG)',
        ])

        env_hits = self._run_remote(
            f"cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n' | "
            f"grep -iE '({pattern_str})' | head -20"
        )
        if env_hits and env_hits.strip():
            # Count unique secret types
            hit_lines = env_hits.strip().splitlines()
            # Mask values
            masked_lines = []
            for line in hit_lines[:8]:
                if "=" in line:
                    k, v = line.split("=", 1)
                    masked_lines.append(f"{k}={self._mask(v)}")
                else:
                    masked_lines.append(line)

            result.add_finding(Finding(
                title=f"Secrets in Running Process Environment Variables ({len(hit_lines)} found)",
                severity=Severity.HIGH,
                category=Category.SECRETS,
                description=(
                    f"Found {len(hit_lines)} secret-like environment variables across running "
                    "processes in /proc/*/environ. These are visible to any user who can read "
                    "process environment files."
                ),
                evidence="\n".join(masked_lines[:8]),
                recommendation=(
                    "Use a secrets manager to inject credentials at runtime rather than "
                    "environment variables. Mount /proc with hidepid=2 to restrict "
                    "/proc/<pid>/environ access: mount -o remount,hidepid=2 /proc"
                ),
                cwe_id="CWE-214",
            ))
        else:
            result.raw_output += "  No secrets found in process environment\n"

    # -------------------------------------------------- Credential files scan

    def _check_credential_files(self, result: ScanResult):
        result.raw_output += "\n--- Credential Files ---\n"

        cred_file_checks = [
            ("~/.aws/credentials",
             "AWS credentials file", Severity.CRITICAL,
             r'\[|\baws_access_key_id\b|\baws_secret_access_key\b'),
            ("~/.aws/config",
             "AWS config with credentials", Severity.HIGH,
             r'role_arn|credential_source'),
            ("~/.docker/config.json",
             "Docker registry credentials", Severity.HIGH,
             r'"auth"\s*:\s*"[A-Za-z0-9+/=]{10,}"'),
            ("~/.netrc",
             "netrc credentials file", Severity.HIGH,
             r'password\s+\S+'),
            ("~/.npmrc",
             "NPM auth token", Severity.HIGH,
             r'_authToken='),
            ("~/.pypirc",
             "PyPI credentials", Severity.MEDIUM,
             r'password\s*='),
            ("/root/.aws/credentials",
             "Root AWS credentials", Severity.CRITICAL,
             r'\baws_access_key_id\b'),
            ("/etc/passwd.bak",
             "Password file backup", Severity.CRITICAL,
             r'root:'),
        ]

        for filepath, desc, severity, pattern in cred_file_checks:
            # Expand ~ for all users
            expanded_paths = self._run_remote(
                f"ls {filepath} /home/*/{filepath.lstrip('~/')} /root/{filepath.lstrip('~/')} "
                "2>/dev/null | head -5"
            ) if filepath.startswith("~") else self._run_remote(
                f"test -f {filepath} && echo {filepath}"
            )

            if not expanded_paths or not expanded_paths.strip():
                continue

            for path in expanded_paths.strip().splitlines():
                path = path.strip()
                if not path:
                    continue

                content_match = self._run_remote(
                    f"grep -Pm2 '{pattern}' '{path}' 2>/dev/null | head -c 200"
                )
                if content_match and content_match.strip():
                    result.raw_output += f"  Found credential file: {path}\n"
                    result.add_finding(Finding(
                        title=f"Credential File Found: {path}",
                        severity=severity,
                        category=Category.SECRETS,
                        description=(
                            f"{desc} found at {path}. "
                            "This file contains authentication credentials that provide "
                            "direct access to external services."
                        ),
                        evidence=f"File: {path}",
                        recommendation=(
                            f"Ensure {path} has permissions 600 and is owned by the user. "
                            "Consider using a secrets manager instead of credential files. "
                            "Rotate any credentials stored in this file."
                        ),
                        cwe_id="CWE-522",
                    ))

    # -------------------------------------------------- Private key files scan

    def _check_private_key_files(self, result: ScanResult):
        result.raw_output += "\n--- Private Key Files ---\n"

        key_files = self._run_remote(
            "find /home /root /opt /srv /app /var/www /etc /tmp "
            r"\( -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' "
            r"-o -name '*.pem' -o -name '*.key' -o -name '*.p12' "
            r"-o -name '*.pfx' -o -name '*.jks' -o -name '*.keystore' \) "
            "-type f 2>/dev/null | head -20"
        )
        if not key_files or not key_files.strip():
            result.raw_output += "  No private key files found in scanned paths\n"
            return

        result.raw_output += f"Private key files found:\n{key_files.strip()}\n"

        for kf in key_files.strip().splitlines():
            kf = kf.strip()
            if not kf:
                continue

            # Check permissions
            perms = self._run_remote(f"stat -c '%a %U %G' '{kf}' 2>/dev/null")
            # Check if it's actually a private key (has header)
            is_private = self._run_remote(
                f"head -1 '{kf}' 2>/dev/null | grep -c 'PRIVATE\\|CERTIFICATE'"
            )

            perm_val = perms.strip().split()[0] if perms and perms.strip() else "???"
            owner = perms.strip().split()[1] if perms and len(perms.strip().split()) > 1 else "?"

            # Flag if world-readable (last digit > 0) or group-readable (middle digit > 4)
            try:
                perm_int = int(perm_val, 8)
                world_read = perm_int & 0o004
                group_read = perm_int & 0o040
            except ValueError:
                world_read, group_read = 0, 0

            if world_read or group_read or (is_private and is_private.strip() != "0"):
                severity = Severity.CRITICAL if world_read else Severity.HIGH
                result.add_finding(Finding(
                    title=f"Private Key File Accessible: {kf}",
                    severity=severity,
                    category=Category.SECRETS,
                    description=(
                        f"Private key file '{kf}' has permissions {perm_val} (owner: {owner}). "
                        + ("World-readable — any user can read this key. " if world_read else "")
                        + ("Group-readable — users in the group can read this key. " if group_read else "")
                    ),
                    evidence=f"{kf}: mode={perm_val}, owner={owner}",
                    recommendation=(
                        f"Fix permissions: chmod 600 {kf} && chown <owner>:<owner> {kf}. "
                        "Encrypt private keys with a passphrase. "
                        "Store keys in a secrets manager or hardware HSM."
                    ),
                    cwe_id="CWE-732",
                    cvss_score=8.0,
                ))

    # --------------------------------------------------- Docker secrets scan

    def _check_docker_secrets(self, result: ScanResult):
        result.raw_output += "\n--- Docker Secrets ---\n"

        # Check running containers for secrets in env vars
        containers = self._run_remote("docker ps -q 2>/dev/null")
        if not containers or not containers.strip():
            result.raw_output += "  No running Docker containers\n"
            return

        env_pattern = r'(?i)(PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|AUTH_TOKEN|ACCESS_KEY|PRIVATE_KEY|PASSWD)'

        for cid in containers.strip().splitlines()[:10]:
            cid = cid.strip()
            if not cid:
                continue

            env_out = self._run_remote(
                f"docker inspect {cid} 2>/dev/null | "
                "python3 -c \""
                "import sys,json; "
                "c=json.load(sys.stdin)[0]; "
                "name=c.get('Name','?'); "
                "envs=c.get('Config',{}).get('Env',[]); "
                "[print(name, '|', e) for e in envs "
                f" if __import__('re').search(r'{env_pattern}', e)]"
                "\" 2>/dev/null | head -10"
            )
            if env_out and env_out.strip():
                container_name = env_out.strip().splitlines()[0].split("|")[0].strip()
                # Mask values
                masked = []
                for line in env_out.strip().splitlines():
                    if "|" in line and "=" in line:
                        _, env = line.split("|", 1)
                        if "=" in env:
                            k, v = env.strip().split("=", 1)
                            masked.append(f"{k}={self._mask(v)}")
                result.add_finding(Finding(
                    title=f"Secrets in Docker Container Environment: {container_name}",
                    severity=Severity.HIGH,
                    category=Category.SECRETS,
                    description=(
                        f"Container {container_name} has secret-like environment variables. "
                        "These are stored in plaintext in the Docker daemon state and "
                        "visible via 'docker inspect' to anyone with Docker socket access."
                    ),
                    evidence="\n".join(masked[:5]),
                    recommendation=(
                        "Replace container environment variable secrets with Docker secrets "
                        "or a secrets manager. Use --secret flag in Docker Compose v3. "
                        "Restrict Docker socket access (never mount docker.sock in containers)."
                    ),
                    cwe_id="CWE-312",
                ))

        # Check Docker config.json for registry auth
        docker_configs = self._run_remote(
            "find /home /root /var/lib/docker -name 'config.json' 2>/dev/null | "
            "xargs -I{} grep -l '\"auths\"' {} 2>/dev/null | head -5"
        )
        if docker_configs and docker_configs.strip():
            result.add_finding(Finding(
                title="Docker Registry Credentials in config.json",
                severity=Severity.HIGH,
                category=Category.SECRETS,
                description=(
                    "Docker config.json files with registry authentication tokens found. "
                    "These base64-encoded credentials grant access to Docker registries."
                ),
                evidence=docker_configs.strip()[:300],
                recommendation=(
                    "Use 'docker-credential-helpers' to store registry credentials in the "
                    "OS keychain instead of config.json. Rotate all registry tokens."
                ),
                cwe_id="CWE-522",
            ))

    # ------------------------------------------------- Kubernetes secrets

    def _check_kubernetes_secrets(self, result: ScanResult):
        result.raw_output += "\n--- Kubernetes Secrets ---\n"

        kubectl = self._run_remote("which kubectl 2>/dev/null || which k3s 2>/dev/null")
        if not kubectl or not kubectl.strip():
            result.raw_output += "  kubectl not found, skipping K8s secrets check\n"
            return

        # List all secrets across all namespaces
        k8s_secrets = self._run_remote(
            "kubectl get secrets --all-namespaces "
            "-o=jsonpath='{range .items[*]}{.metadata.namespace}|{.metadata.name}|{.type}\\n{end}' "
            "2>/dev/null | head -20"
        )
        if not k8s_secrets or "Error" in (k8s_secrets or ""):
            result.raw_output += "  Cannot list K8s secrets (no cluster access?)\n"
            return

        result.raw_output += f"K8s secrets:\n{k8s_secrets[:400]}\n"

        # Check for secrets with Opaque type that may be plaintext
        opaque_count = k8s_secrets.count("Opaque")
        if opaque_count > 0:
            result.add_finding(Finding(
                title=f"Kubernetes: {opaque_count} Opaque Secrets Found",
                severity=Severity.MEDIUM,
                category=Category.SECRETS,
                description=(
                    f"Found {opaque_count} Opaque-type Kubernetes secrets. K8s secrets are "
                    "only base64-encoded (not encrypted) at rest by default. Anyone with "
                    "etcd access or RBAC permissions can decode them."
                ),
                evidence=k8s_secrets[:300],
                recommendation=(
                    "Enable encryption at rest for etcd: configure EncryptionConfiguration. "
                    "Use an external secrets manager (Vault, AWS Secrets Manager) with "
                    "External Secrets Operator instead of native K8s secrets."
                ),
                cwe_id="CWE-311",
            ))

        # Check if default service account has broad permissions
        default_sa = self._run_remote(
            "kubectl auth can-i --list --as=system:serviceaccount:default:default "
            "2>/dev/null | grep -v 'no' | head -10"
        )
        if default_sa and "get" in default_sa.lower():
            result.add_finding(Finding(
                title="Kubernetes Default Service Account Has Broad Permissions",
                severity=Severity.HIGH,
                category=Category.SECRETS,
                description=(
                    "The default service account in the default namespace has broad "
                    "API permissions. Containers without an explicit service account "
                    "use this token, potentially allowing cluster-level access."
                ),
                evidence=default_sa.strip()[:300],
                recommendation=(
                    "Create dedicated service accounts with minimal permissions. "
                    "Disable automounting of service account tokens for pods that don't need them: "
                    "automountServiceAccountToken: false"
                ),
                cwe_id="CWE-250",
                cvss_score=8.8,
            ))

    # -------------------------------------------- Terraform state files

    def _check_terraform_state(self, result: ScanResult):
        result.raw_output += "\n--- Terraform State Files ---\n"

        tf_states = self._run_remote(
            "find /home /root /opt /srv /app /var/www "
            r"-name 'terraform.tfstate' -o -name 'terraform.tfstate.backup' "
            "2>/dev/null | head -10"
        )
        if not tf_states or not tf_states.strip():
            result.raw_output += "  No Terraform state files found\n"
            return

        result.raw_output += f"Terraform state files:\n{tf_states.strip()}\n"

        for tf_file in tf_states.strip().splitlines()[:3]:
            tf_file = tf_file.strip()
            # Check for secrets inside state
            secret_hit = self._run_remote(
                f"cat '{tf_file}' 2>/dev/null | "
                "python3 -c \""
                "import sys,json,re; "
                "data=sys.stdin.read(); "
                "patterns=['password','secret','token','key','access_key']; "
                "lines=[l for l in data.split('\\\\n') "
                "  if any(p in l.lower() for p in patterns) "
                "  and len(l.strip())>10]; "
                "print('\\\\n'.join(lines[:5]))"
                "\" 2>/dev/null | head -10"
            )
            has_secret = secret_hit and secret_hit.strip() and len(secret_hit.strip()) > 10

            result.add_finding(Finding(
                title=f"Terraform State File Found: {tf_file}",
                severity=Severity.CRITICAL if has_secret else Severity.HIGH,
                category=Category.SECRETS,
                description=(
                    f"Terraform state file found at {tf_file}. "
                    "Terraform state files store all resource attributes in plaintext, "
                    "including passwords, connection strings, and API keys."
                    + (" Secret patterns detected in state file content." if has_secret else "")
                ),
                evidence=tf_file + (f"\nContains: {secret_hit.strip()[:200]}" if has_secret else ""),
                recommendation=(
                    "Store Terraform state in a remote backend with encryption "
                    "(S3 with SSE, Terraform Cloud). Never commit state files to git. "
                    "Add *.tfstate to .gitignore."
                ),
                cwe_id="CWE-312",
                cvss_score=9.0 if has_secret else 7.5,
            ))
