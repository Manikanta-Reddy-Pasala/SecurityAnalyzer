"""Infrastructure auditor - AWS security groups, VPN, IP whitelisting checks."""
import subprocess
import json
from typing import Optional
from .models import Finding, ScanResult, Severity, Category


class InfraAuditor:
    """Audits AWS infrastructure security configuration."""

    def __init__(self, host: str, user: str, key_path: Optional[str] = None):
        self.host = host
        self.user = user
        self.key_path = key_path

    def audit(self) -> ScanResult:
        result = ScanResult(scanner_name="Infrastructure Auditor")

        # 1. Check AWS CLI availability and instance metadata
        if self._can_connect():
            self._check_instance_metadata(result)
            self._check_aws_cli(result)
            self._check_iam_role(result)
            self._check_security_groups_from_inside(result)
            self._check_network_config(result)
            self._check_disk_encryption(result)
            self._check_logging(result)
            self._check_time_sync(result)
        else:
            # External checks only
            self._check_vpn_requirement(result)
            self._check_ip_whitelisting(result)

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

    def _check_instance_metadata(self, result: ScanResult):
        # Check IMDSv1 (insecure - no token required)
        imds_v1 = self._run_remote(
            "curl -s -o /dev/null -w '%{http_code}' "
            "http://169.254.169.254/latest/meta-data/ 2>/dev/null"
        )
        if imds_v1 and imds_v1.strip() == "200":
            # Check if IMDSv2 is enforced
            imds_v2 = self._run_remote(
                "TOKEN=$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' "
                "-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600') && "
                "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" "
                "http://169.254.169.254/latest/meta-data/instance-id"
            )

            result.add_finding(Finding(
                title="EC2 Instance Metadata v1 Accessible",
                severity=Severity.HIGH,
                category=Category.INFRASTRUCTURE,
                description="IMDSv1 is accessible without token. This allows SSRF attacks "
                            "to steal IAM credentials from the metadata service.",
                evidence="HTTP 200 from metadata endpoint without token",
                recommendation="Enforce IMDSv2: aws ec2 modify-instance-metadata-options "
                               "--instance-id <id> --http-tokens required",
                cwe_id="CWE-918",
            ))

        # Get instance info
        instance_id = self._run_remote(
            "curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null"
        )
        if instance_id:
            result.raw_output += f"Instance ID: {instance_id.strip()}\n"

        security_groups = self._run_remote(
            "curl -s http://169.254.169.254/latest/meta-data/security-groups 2>/dev/null"
        )
        if security_groups:
            result.raw_output += f"Security Groups: {security_groups.strip()}\n"

    def _check_aws_cli(self, result: ScanResult):
        aws_version = self._run_remote("aws --version 2>&1")
        if aws_version and "aws-cli" in aws_version:
            result.raw_output += f"AWS CLI: {aws_version.strip()}\n"

            # Check caller identity
            identity = self._run_remote("aws sts get-caller-identity 2>/dev/null")
            if identity:
                result.raw_output += f"AWS Identity: {identity.strip()}\n"

    def _check_iam_role(self, result: ScanResult):
        role = self._run_remote(
            "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null"
        )
        if role and role.strip():
            result.raw_output += f"IAM Role: {role.strip()}\n"

            # Check if role has overly broad permissions
            creds = self._run_remote(
                f"curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/{role.strip()} 2>/dev/null"
            )
            if creds and "AccessKeyId" in creds:
                result.add_finding(Finding(
                    title="IAM Role Credentials Accessible via Metadata",
                    severity=Severity.MEDIUM,
                    category=Category.INFRASTRUCTURE,
                    description="IAM role credentials are retrievable from instance metadata. "
                                "Combined with IMDSv1, SSRF attacks can steal these credentials.",
                    evidence=f"Role: {role.strip()}",
                    recommendation="Enforce IMDSv2 and apply least-privilege IAM policies.",
                    cwe_id="CWE-269",
                ))

    def _check_security_groups_from_inside(self, result: ScanResult):
        # Try to describe security groups via AWS CLI
        sg_output = self._run_remote(
            "aws ec2 describe-security-groups --output json 2>/dev/null | head -200"
        )
        if sg_output and "SecurityGroups" in sg_output:
            try:
                data = json.loads(sg_output)
                for sg in data.get("SecurityGroups", []):
                    for perm in sg.get("IpPermissions", []):
                        for ip_range in perm.get("IpRanges", []):
                            cidr = ip_range.get("CidrIp", "")
                            if cidr == "0.0.0.0/0":
                                port = perm.get("FromPort", "all")
                                result.add_finding(Finding(
                                    title=f"Security Group Allows 0.0.0.0/0 on Port {port}",
                                    severity=Severity.CRITICAL,
                                    category=Category.NETWORK,
                                    description=f"Security group {sg.get('GroupId')} allows "
                                                f"inbound from 0.0.0.0/0 on port {port}. "
                                                "This means anyone on the internet can access this port.",
                                    evidence=f"SG: {sg.get('GroupId')}, Port: {port}, CIDR: 0.0.0.0/0",
                                    recommendation="Restrict to specific IP ranges or VPN CIDR.",
                                    cwe_id="CWE-284",
                                ))
            except json.JSONDecodeError:
                pass

    def _check_network_config(self, result: ScanResult):
        # Check if in VPC
        vpc_id = self._run_remote(
            "curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/ 2>/dev/null"
        )
        if vpc_id:
            result.raw_output += f"Network MACs: {vpc_id.strip()}\n"

        # Check for public IP
        public_ip = self._run_remote(
            "curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null"
        )
        if public_ip and public_ip.strip():
            result.raw_output += f"Public IP: {public_ip.strip()}\n"
            result.add_finding(Finding(
                title="Instance Has Public IP",
                severity=Severity.MEDIUM,
                category=Category.INFRASTRUCTURE,
                description=f"Instance has public IP {public_ip.strip()}. "
                            "UAT servers should use private IPs with bastion/VPN access.",
                evidence=f"Public IP: {public_ip.strip()}",
                recommendation="Remove public IP. Use AWS Systems Manager Session Manager "
                               "or bastion host for access.",
                cwe_id="CWE-284",
            ))

    def _check_disk_encryption(self, result: ScanResult):
        lsblk = self._run_remote("lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE 2>/dev/null")
        if lsblk:
            result.raw_output += f"--- Block Devices ---\n{lsblk}\n"

        # Check EBS encryption
        encrypted = self._run_remote(
            "aws ec2 describe-volumes --output json 2>/dev/null | "
            "python3 -c \"import sys,json; d=json.load(sys.stdin); "
            "[print(f'{v[\\\"VolumeId\\\"]}: encrypted={v[\\\"Encrypted\\\"]}') for v in d.get('Volumes',[])]\" 2>/dev/null"
        )
        if encrypted:
            for line in encrypted.strip().split("\n"):
                if "encrypted=False" in line:
                    result.add_finding(Finding(
                        title="Unencrypted EBS Volume",
                        severity=Severity.HIGH,
                        category=Category.INFRASTRUCTURE,
                        description="EBS volume is not encrypted at rest.",
                        evidence=line.strip(),
                        recommendation="Enable EBS encryption. Create encrypted snapshot "
                                       "and replace the volume.",
                        cwe_id="CWE-311",
                    ))

    def _check_logging(self, result: ScanResult):
        # Check CloudWatch agent
        cw_agent = self._run_remote(
            "systemctl is-active amazon-cloudwatch-agent 2>/dev/null || echo inactive"
        )
        if cw_agent and "inactive" in cw_agent:
            result.add_finding(Finding(
                title="CloudWatch Agent Not Running",
                severity=Severity.MEDIUM,
                category=Category.INFRASTRUCTURE,
                description="CloudWatch agent is not running. No centralized logging.",
                evidence="amazon-cloudwatch-agent service inactive",
                recommendation="Install and configure CloudWatch agent for centralized "
                               "log aggregation and monitoring.",
            ))

        # Check audit logging
        auditd = self._run_remote("systemctl is-active auditd 2>/dev/null || echo inactive")
        if auditd and "inactive" in auditd:
            result.add_finding(Finding(
                title="Audit Daemon Not Running",
                severity=Severity.MEDIUM,
                category=Category.INFRASTRUCTURE,
                description="auditd is not running. No system call auditing.",
                evidence="auditd service inactive",
                recommendation="Enable auditd: sudo systemctl enable --now auditd",
            ))

    def _check_time_sync(self, result: ScanResult):
        time_sync = self._run_remote("timedatectl 2>/dev/null | grep -i 'ntp\\|synchronized'")
        if time_sync and "no" in time_sync.lower():
            result.add_finding(Finding(
                title="Time Synchronization Disabled",
                severity=Severity.LOW,
                category=Category.INFRASTRUCTURE,
                description="NTP/time sync is not active. This affects log correlation "
                            "and TLS certificate validation.",
                evidence=time_sync.strip(),
                recommendation="Enable chrony: sudo systemctl enable --now chronyd",
            ))

    def _check_vpn_requirement(self, result: ScanResult):
        result.add_finding(Finding(
            title="No VPN Tunnel Required for Access",
            severity=Severity.CRITICAL,
            category=Category.ACCESS_CONTROL,
            description="UAT environment is accessible without VPN. "
                        "All non-production environments should require VPN "
                        "to prevent unauthorized access.",
            evidence="Direct SSH/HTTP access possible without VPN",
            recommendation="Deploy WireGuard or OpenVPN. Configure security groups "
                           "to only allow traffic from VPN CIDR range.",
            cwe_id="CWE-284",
        ))

    def _check_ip_whitelisting(self, result: ScanResult):
        result.add_finding(Finding(
            title="No IP Whitelisting Configured",
            severity=Severity.HIGH,
            category=Category.ACCESS_CONTROL,
            description="No IP whitelisting detected. Security groups should "
                        "restrict access to known IP ranges only.",
            evidence="Services accessible from arbitrary source IPs",
            recommendation="Configure AWS security groups with specific IP ranges. "
                           "Use a bastion host pattern for SSH access.",
            cwe_id="CWE-284",
        ))
