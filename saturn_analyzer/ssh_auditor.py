"""SSH configuration auditor - checks SSH security best practices."""
import subprocess
import os
from typing import Optional
from .models import Finding, ScanResult, Severity, Category


class SSHAuditor:
    def __init__(self, host: str, user: str, key_path: Optional[str] = None):
        self.host = host
        self.user = user
        self.key_path = key_path

    def audit(self) -> ScanResult:
        result = ScanResult(scanner_name="SSH Auditor")

        # 1. Check SSH key file permissions
        if self.key_path:
            self._check_key_permissions(result)
            self._check_key_strength(result)

        # 2. Try SSH connection and audit remote config
        if self._can_connect():
            self._audit_sshd_config(result)
            self._check_authorized_keys(result)
            self._check_ssh_banner(result)
            self._check_sudo_config(result)
            self._check_fail2ban(result)
        else:
            result.raw_output += "Cannot establish SSH connection\n"
            result.add_finding(Finding(
                title="SSH Connection Failed",
                severity=Severity.INFO,
                category=Category.SSH,
                description="Could not connect via SSH. Port may be filtered or "
                            "credentials are invalid.",
                evidence=f"Host: {self.host}, User: {self.user}",
                recommendation="Verify SSH access and retry from an authorized network.",
            ))

        # 3. Check for password auth from banner grab
        self._check_ssh_auth_methods(result)

        return result

    def _check_key_permissions(self, result: ScanResult):
        if not self.key_path or not os.path.exists(self.key_path):
            return

        mode = oct(os.stat(self.key_path).st_mode)[-3:]
        result.raw_output += f"SSH key permissions: {mode}\n"

        if mode != "600" and mode != "400":
            result.add_finding(Finding(
                title="SSH Key File Permissions Too Open",
                severity=Severity.HIGH,
                category=Category.SSH,
                description=f"SSH private key has permissions {mode}. "
                            "Should be 600 or 400.",
                evidence=f"File: {os.path.basename(self.key_path)}, Permissions: {mode}",
                recommendation="Run: chmod 600 <key_file>",
                cwe_id="CWE-732",
            ))

    def _check_key_strength(self, result: ScanResult):
        if not self.key_path or not os.path.exists(self.key_path):
            return

        try:
            proc = subprocess.run(
                ["ssh-keygen", "-l", "-f", self.key_path],
                capture_output=True, text=True, timeout=5,
            )
            if proc.returncode == 0:
                output = proc.stdout.strip()
                result.raw_output += f"Key info: {output}\n"

                # Parse key type and bits
                parts = output.split()
                bits = int(parts[0]) if parts else 0
                key_type = parts[-1].strip("()") if parts else "unknown"

                if "RSA" in key_type and bits < 4096:
                    result.add_finding(Finding(
                        title="Weak RSA Key Size",
                        severity=Severity.MEDIUM,
                        category=Category.SSH,
                        description=f"RSA key is {bits} bits. Minimum 4096 recommended.",
                        evidence=output,
                        recommendation="Generate a new key: ssh-keygen -t ed25519",
                        cwe_id="CWE-326",
                    ))
                elif "ED25519" in key_type.upper():
                    result.raw_output += "Key type ED25519 - good\n"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    def _can_connect(self) -> bool:
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
               "-o", "ConnectTimeout=10", "-o", "BatchMode=yes"]
        if self.key_path:
            cmd.extend(["-i", self.key_path])
        cmd.extend([f"{self.user}@{self.host}", "echo connected"])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return proc.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def _run_remote(self, command: str, timeout: int = 15) -> Optional[str]:
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
               "-o", "ConnectTimeout=10", "-o", "BatchMode=yes"]
        if self.key_path:
            cmd.extend(["-i", self.key_path])
        cmd.extend([f"{self.user}@{self.host}", command])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return proc.stdout if proc.returncode == 0 else None
        except subprocess.TimeoutExpired:
            return None

    def _audit_sshd_config(self, result: ScanResult):
        config = self._run_remote("sudo cat /etc/ssh/sshd_config 2>/dev/null || cat /etc/ssh/sshd_config 2>/dev/null")
        if not config:
            return

        result.raw_output += f"--- sshd_config ---\n{config[:2000]}\n"

        checks = {
            "PasswordAuthentication yes": Finding(
                title="SSH Password Authentication Enabled",
                severity=Severity.HIGH,
                category=Category.SSH,
                description="Password authentication is enabled. This allows brute-force attacks.",
                evidence="PasswordAuthentication yes in sshd_config",
                recommendation="Set 'PasswordAuthentication no' in /etc/ssh/sshd_config",
                cwe_id="CWE-307",
            ),
            "PermitRootLogin yes": Finding(
                title="SSH Root Login Permitted",
                severity=Severity.CRITICAL,
                category=Category.SSH,
                description="Root login via SSH is allowed. This is a critical security risk.",
                evidence="PermitRootLogin yes in sshd_config",
                recommendation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
                cwe_id="CWE-250",
            ),
            "X11Forwarding yes": Finding(
                title="X11 Forwarding Enabled",
                severity=Severity.LOW,
                category=Category.SSH,
                description="X11 forwarding is enabled, which increases attack surface.",
                evidence="X11Forwarding yes in sshd_config",
                recommendation="Set 'X11Forwarding no' unless required.",
            ),
        }

        for pattern, finding in checks.items():
            if pattern.lower() in config.lower().replace("  ", " "):
                result.add_finding(finding)

        # Check for AllowUsers/AllowGroups
        if "allowusers" not in config.lower() and "allowgroups" not in config.lower():
            result.add_finding(Finding(
                title="No SSH User Restrictions",
                severity=Severity.MEDIUM,
                category=Category.SSH,
                description="No AllowUsers or AllowGroups directive found. "
                            "Any valid user can SSH in.",
                evidence="Missing AllowUsers/AllowGroups in sshd_config",
                recommendation="Add 'AllowUsers ec2-user' to restrict SSH access.",
                cwe_id="CWE-284",
            ))

    def _check_authorized_keys(self, result: ScanResult):
        keys = self._run_remote("cat ~/.ssh/authorized_keys 2>/dev/null | wc -l")
        if keys:
            count = int(keys.strip())
            if count > 5:
                result.add_finding(Finding(
                    title="Excessive Authorized SSH Keys",
                    severity=Severity.MEDIUM,
                    category=Category.SSH,
                    description=f"Found {count} authorized SSH keys. Each key is an "
                                "access vector that needs management.",
                    evidence=f"{count} keys in authorized_keys",
                    recommendation="Audit and remove unused SSH keys regularly.",
                    cwe_id="CWE-284",
                ))

    def _check_ssh_banner(self, result: ScanResult):
        banner = self._run_remote("cat /etc/ssh/sshd_config 2>/dev/null | grep -i banner")
        if banner and "none" in banner.lower():
            result.add_finding(Finding(
                title="No SSH Warning Banner",
                severity=Severity.LOW,
                category=Category.SSH,
                description="No SSH login banner configured. A warning banner "
                            "provides legal notice to unauthorized users.",
                evidence="Banner none or not set",
                recommendation="Configure a warning banner in sshd_config.",
            ))

    def _check_sudo_config(self, result: ScanResult):
        sudo_check = self._run_remote("sudo -l 2>/dev/null | head -20")
        if sudo_check and "NOPASSWD" in sudo_check:
            result.add_finding(Finding(
                title="Passwordless Sudo Configured",
                severity=Severity.HIGH,
                category=Category.ACCESS_CONTROL,
                description="User has NOPASSWD sudo access. If SSH key is compromised, "
                            "attacker gets full root access.",
                evidence=f"sudo -l output contains NOPASSWD",
                recommendation="Remove NOPASSWD and require password for sudo, "
                               "or use AWS SSM Session Manager instead of SSH.",
                cwe_id="CWE-250",
            ))

    def _check_fail2ban(self, result: ScanResult):
        f2b = self._run_remote("systemctl is-active fail2ban 2>/dev/null || echo inactive")
        if f2b and "inactive" in f2b:
            result.add_finding(Finding(
                title="fail2ban Not Running",
                severity=Severity.MEDIUM,
                category=Category.SSH,
                description="fail2ban is not active. No brute-force protection for SSH.",
                evidence="fail2ban service inactive",
                recommendation="Install and enable fail2ban: "
                               "sudo yum install fail2ban && sudo systemctl enable --now fail2ban",
            ))

    def _check_ssh_auth_methods(self, result: ScanResult):
        try:
            proc = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no",
                 "-o", "ConnectTimeout=10",
                 "-o", "PreferredAuthentications=none",
                 f"{self.user}@{self.host}"],
                capture_output=True, text=True, timeout=15,
            )
            stderr = proc.stderr
            if "publickey,password" in stderr or "password" in stderr:
                result.add_finding(Finding(
                    title="SSH Password Authentication Available",
                    severity=Severity.HIGH,
                    category=Category.SSH,
                    description="SSH server advertises password authentication method.",
                    evidence=f"Auth methods from banner: {stderr.strip()[:200]}",
                    recommendation="Disable password authentication in sshd_config.",
                    cwe_id="CWE-307",
                ))
        except subprocess.TimeoutExpired:
            pass
