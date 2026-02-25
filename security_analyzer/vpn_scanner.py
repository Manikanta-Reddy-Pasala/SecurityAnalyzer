"""VPN security scanner - checks VPN presence, configuration, and network isolation."""
import subprocess
import socket
from typing import Optional
from .models import Finding, ScanResult, Severity, Category


class VPNScanner:
    """Audits VPN configuration and network isolation."""

    def __init__(self, host: str, user: str = None, key_path: Optional[str] = None):
        self.host = host
        self.user = user
        self.key_path = key_path

    def scan(self) -> ScanResult:
        result = ScanResult(scanner_name="VPN Scanner")

        # External checks (no SSH needed)
        self._check_direct_access(result)
        self._check_vpn_ports(result)

        # Internal checks (SSH required)
        if self.user and self._can_connect():
            self._check_vpn_software(result)
            self._check_vpn_interfaces(result)
            self._check_vpn_config(result)
            self._check_split_tunneling(result)
            self._check_dns_leak(result)
            self._check_vpn_auth(result)
            self._check_ip_forwarding(result)
            self._check_vpn_logging(result)
            self._check_vpn_kill_switch(result)
            self._check_vpn_cert_expiry(result)
        else:
            result.raw_output += "SSH not available, running external-only VPN checks\n"
            self._check_vpn_requirement_external(result)

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

    def _check_direct_access(self, result: ScanResult):
        """Check if services are directly accessible without VPN."""
        test_ports = [22, 80, 443, 8080, 3000, 9090]
        open_ports = []

        for port in test_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5)
                    if s.connect_ex((self.host, port)) == 0:
                        open_ports.append(port)
            except (socket.timeout, OSError):
                pass

        if open_ports:
            result.raw_output += f"Directly accessible ports (no VPN): {open_ports}\n"
            result.add_finding(Finding(
                title="Services Accessible Without VPN",
                severity=Severity.CRITICAL,
                category=Category.VPN,
                description=f"Ports {open_ports} are directly accessible from the internet "
                            "without requiring a VPN connection. Non-production environments "
                            "should require VPN for all access.",
                evidence=f"Open ports from internet: {open_ports}",
                recommendation="Deploy WireGuard or OpenVPN. Restrict security groups "
                               "to only allow traffic from VPN CIDR range.",
                cwe_id="CWE-284",
                cvss_score=8.5,
            ))

    def _check_vpn_ports(self, result: ScanResult):
        """Check if VPN service ports are available."""
        vpn_ports = {
            1194: "OpenVPN",
            51820: "WireGuard",
            500: "IPSec IKE",
            4500: "IPSec NAT-T",
            1701: "L2TP",
            1723: "PPTP (insecure)",
        }
        found_vpn = False
        for port, name in vpn_ports.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    if s.connect_ex((self.host, port)) == 0:
                        found_vpn = True
                        result.raw_output += f"VPN port open: {port} ({name})\n"
                        if name == "PPTP (insecure)":
                            result.add_finding(Finding(
                                title="Insecure PPTP VPN Detected",
                                severity=Severity.HIGH,
                                category=Category.VPN,
                                description="PPTP VPN is running. PPTP has known cryptographic "
                                            "weaknesses and should not be used.",
                                evidence=f"Port {port} ({name}) is open",
                                recommendation="Migrate to WireGuard or OpenVPN with strong ciphers.",
                                cwe_id="CWE-327",
                            ))
            except (socket.timeout, OSError):
                pass

        # Also check UDP for WireGuard/IPSec
        for port in [51820, 500, 4500]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(3)
                    s.sendto(b"\x00", (self.host, port))
                    try:
                        s.recvfrom(1024)
                        found_vpn = True
                        result.raw_output += f"VPN UDP port responsive: {port}\n"
                    except socket.timeout:
                        pass
            except OSError:
                pass

        if not found_vpn:
            result.add_finding(Finding(
                title="No VPN Service Detected",
                severity=Severity.HIGH,
                category=Category.VPN,
                description="No VPN service ports (WireGuard, OpenVPN, IPSec) were "
                            "detected on the target host.",
                evidence="Checked ports: 1194, 51820, 500, 4500, 1701, 1723",
                recommendation="Deploy a VPN solution (WireGuard recommended) and restrict "
                               "all service access to VPN clients only.",
                cwe_id="CWE-284",
            ))

    def _check_vpn_software(self, result: ScanResult):
        """Check installed VPN software and its status."""
        vpn_checks = [
            ("WireGuard", "wg show 2>/dev/null", "wg-quick@"),
            ("OpenVPN", "openvpn --version 2>/dev/null | head -1", "openvpn"),
            ("StrongSwan (IPSec)", "ipsec version 2>/dev/null", "strongswan"),
            ("Libreswan (IPSec)", "ipsec --version 2>/dev/null", "pluto"),
        ]

        vpn_found = False
        for name, version_cmd, service_name in vpn_checks:
            version = self._run_remote(version_cmd)
            if version and version.strip():
                vpn_found = True
                result.raw_output += f"{name} installed: {version.strip()[:100]}\n"

                # Check if running
                status = self._run_remote(
                    f"systemctl is-active {service_name}* 2>/dev/null || "
                    f"pgrep -x {service_name} 2>/dev/null"
                )
                if status and ("active" in status or status.strip().isdigit()):
                    result.raw_output += f"{name} is running\n"
                else:
                    result.add_finding(Finding(
                        title=f"{name} Installed but Not Running",
                        severity=Severity.HIGH,
                        category=Category.VPN,
                        description=f"{name} is installed but not actively running.",
                        evidence=f"Version: {version.strip()[:80]}, Status: not active",
                        recommendation=f"Start {name} service and ensure it runs on boot.",
                    ))

        if not vpn_found:
            result.add_finding(Finding(
                title="No VPN Software Installed",
                severity=Severity.CRITICAL,
                category=Category.VPN,
                description="No VPN software (WireGuard, OpenVPN, StrongSwan) "
                            "is installed on the server.",
                evidence="Checked: WireGuard, OpenVPN, StrongSwan, Libreswan",
                recommendation="Install WireGuard: sudo yum install wireguard-tools "
                               "or sudo apt install wireguard",
                cwe_id="CWE-284",
                cvss_score=8.0,
            ))

    def _check_vpn_interfaces(self, result: ScanResult):
        """Check for VPN tunnel interfaces."""
        interfaces = self._run_remote("ip link show 2>/dev/null | grep -E 'wg|tun|tap|ipsec'")
        if interfaces:
            result.raw_output += f"VPN interfaces: {interfaces}\n"
        else:
            result.raw_output += "No VPN tunnel interfaces found\n"

    def _check_vpn_config(self, result: ScanResult):
        """Check VPN configuration security."""
        # WireGuard config
        wg_conf = self._run_remote("ls /etc/wireguard/*.conf 2>/dev/null")
        if wg_conf:
            # Check permissions
            perms = self._run_remote("stat -c '%a %n' /etc/wireguard/*.conf 2>/dev/null")
            if perms:
                for line in perms.strip().split("\n"):
                    if line and not line.startswith("600") and not line.startswith("400"):
                        result.add_finding(Finding(
                            title="WireGuard Config Permissions Too Open",
                            severity=Severity.HIGH,
                            category=Category.VPN,
                            description="WireGuard configuration contains private keys "
                                        "and should have restrictive permissions.",
                            evidence=line.strip(),
                            recommendation="chmod 600 /etc/wireguard/*.conf",
                            cwe_id="CWE-732",
                        ))

        # OpenVPN config
        ovpn_conf = self._run_remote("ls /etc/openvpn/*.conf /etc/openvpn/server/*.conf 2>/dev/null")
        if ovpn_conf:
            config_content = self._run_remote("cat /etc/openvpn/*.conf /etc/openvpn/server/*.conf 2>/dev/null")
            if config_content:
                # Check for weak ciphers
                if "cipher BF-CBC" in config_content or "cipher DES" in config_content:
                    result.add_finding(Finding(
                        title="OpenVPN Using Weak Cipher",
                        severity=Severity.HIGH,
                        category=Category.VPN,
                        description="OpenVPN is configured with a weak cipher.",
                        evidence="Weak cipher detected in OpenVPN config",
                        recommendation="Use 'cipher AES-256-GCM' in OpenVPN config.",
                        cwe_id="CWE-327",
                    ))

                # Check for TLS auth
                if "tls-auth" not in config_content and "tls-crypt" not in config_content:
                    result.add_finding(Finding(
                        title="OpenVPN Missing TLS Authentication",
                        severity=Severity.MEDIUM,
                        category=Category.VPN,
                        description="OpenVPN is not using tls-auth or tls-crypt for "
                                    "HMAC authentication of control channel.",
                        evidence="No tls-auth or tls-crypt directive found",
                        recommendation="Add 'tls-crypt' directive to OpenVPN config.",
                        cwe_id="CWE-306",
                    ))

    def _check_split_tunneling(self, result: ScanResult):
        """Check if VPN enforces full tunnel (no split tunneling)."""
        routes = self._run_remote("ip route show 2>/dev/null")
        if routes:
            result.raw_output += f"--- Routes ---\n{routes[:500]}\n"
            # Check if default route goes through VPN
            if "tun" not in routes and "wg" not in routes:
                result.add_finding(Finding(
                    title="No VPN Default Route (Possible Split Tunnel)",
                    severity=Severity.MEDIUM,
                    category=Category.VPN,
                    description="Default route does not go through a VPN interface. "
                                "Traffic may bypass VPN (split tunneling).",
                    evidence="No tun/wg interface in default route",
                    recommendation="Configure full tunnel VPN to route all traffic "
                                   "through the VPN interface.",
                    cwe_id="CWE-319",
                ))

    def _check_dns_leak(self, result: ScanResult):
        """Check for DNS leak potential."""
        resolv = self._run_remote("cat /etc/resolv.conf 2>/dev/null")
        if resolv:
            result.raw_output += f"--- DNS Config ---\n{resolv}\n"
            # Check if DNS is going to public resolvers
            public_dns = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "208.67.222.222"]
            for dns in public_dns:
                if dns in resolv:
                    result.add_finding(Finding(
                        title=f"Public DNS Resolver Configured ({dns})",
                        severity=Severity.MEDIUM,
                        category=Category.VPN,
                        description=f"Public DNS resolver {dns} is configured. DNS queries "
                                    "may leak outside the VPN tunnel.",
                        evidence=f"Found {dns} in /etc/resolv.conf",
                        recommendation="Use VPN-provided DNS or private DNS resolver "
                                       "within the VPN tunnel.",
                        cwe_id="CWE-200",
                    ))

    def _check_vpn_auth(self, result: ScanResult):
        """Check VPN authentication methods."""
        # WireGuard key check
        wg_output = self._run_remote("wg show 2>/dev/null")
        if wg_output:
            peers = wg_output.count("peer:")
            if peers > 20:
                result.add_finding(Finding(
                    title=f"Excessive WireGuard Peers ({peers})",
                    severity=Severity.MEDIUM,
                    category=Category.VPN,
                    description=f"WireGuard has {peers} configured peers. "
                                "Each peer is an access vector.",
                    evidence=f"{peers} peers configured",
                    recommendation="Audit and remove unused WireGuard peers regularly.",
                ))

        # Check for certificate-based auth
        certs = self._run_remote(
            "ls /etc/openvpn/easy-rsa/pki/issued/*.crt 2>/dev/null | wc -l"
        )
        if certs and int(certs.strip()) > 20:
            result.add_finding(Finding(
                title=f"Excessive VPN Certificates ({certs.strip()})",
                severity=Severity.MEDIUM,
                category=Category.VPN,
                description=f"Found {certs.strip()} VPN client certificates. "
                            "Unused certificates should be revoked.",
                evidence=f"{certs.strip()} certificates in PKI",
                recommendation="Audit certificates and revoke unused ones.",
                cwe_id="CWE-284",
            ))

    def _check_ip_forwarding(self, result: ScanResult):
        """Check IP forwarding settings for VPN server."""
        ipv4_fwd = self._run_remote("sysctl net.ipv4.ip_forward 2>/dev/null")
        if ipv4_fwd and "= 1" in ipv4_fwd:
            result.raw_output += "IPv4 forwarding enabled (required for VPN server)\n"
        elif ipv4_fwd and "= 0" in ipv4_fwd:
            result.add_finding(Finding(
                title="IPv4 Forwarding Disabled",
                severity=Severity.INFO,
                category=Category.VPN,
                description="IPv4 forwarding is disabled. This is required for VPN server operation.",
                evidence=ipv4_fwd.strip(),
                recommendation="Enable if this is a VPN server: sysctl -w net.ipv4.ip_forward=1",
            ))

    def _check_vpn_logging(self, result: ScanResult):
        """Check if VPN connection logging is enabled."""
        # WireGuard logging
        wg_log = self._run_remote("journalctl -u wg-quick@* --no-pager -n 1 2>/dev/null")
        ovpn_log = self._run_remote("ls /var/log/openvpn* 2>/dev/null")

        if not wg_log and not ovpn_log:
            result.add_finding(Finding(
                title="No VPN Connection Logging Detected",
                severity=Severity.MEDIUM,
                category=Category.VPN,
                description="No VPN connection logs found. VPN access should be logged "
                            "for audit and incident response.",
                evidence="No WireGuard journal or OpenVPN log files found",
                recommendation="Enable VPN logging. For OpenVPN add 'log /var/log/openvpn.log'. "
                               "For WireGuard use systemd journal.",
                cwe_id="CWE-778",
            ))

    def _check_vpn_kill_switch(self, result: ScanResult):
        """Check if a VPN kill switch (firewall rules) is configured."""
        iptables = self._run_remote("iptables -L OUTPUT -n 2>/dev/null | head -20")
        if iptables:
            # Check if there are rules that block traffic when VPN is down
            has_vpn_rules = any(
                iface in iptables for iface in ["wg0", "tun0", "tun1"]
            )
            if not has_vpn_rules:
                result.add_finding(Finding(
                    title="No VPN Kill Switch Detected",
                    severity=Severity.MEDIUM,
                    category=Category.VPN,
                    description="No firewall rules found to block traffic when VPN is down. "
                                "Traffic may leak outside VPN if the tunnel drops.",
                    evidence="No VPN interface rules in iptables OUTPUT chain",
                    recommendation="Configure iptables to only allow traffic through VPN interface.",
                    cwe_id="CWE-319",
                ))

    def _check_vpn_cert_expiry(self, result: ScanResult):
        """Check VPN certificate expiration dates."""
        # OpenVPN server cert
        cert_paths = [
            "/etc/openvpn/server.crt",
            "/etc/openvpn/server/server.crt",
            "/etc/openvpn/easy-rsa/pki/issued/server.crt",
        ]
        for cert_path in cert_paths:
            expiry = self._run_remote(
                f"openssl x509 -enddate -noout -in {cert_path} 2>/dev/null"
            )
            if expiry and "notAfter" in expiry:
                result.raw_output += f"VPN cert expiry: {expiry.strip()}\n"
                # Parse and check
                import datetime as _dt
                try:
                    date_str = expiry.strip().split("=")[1]
                    exp_date = _dt.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp_date - _dt.datetime.utcnow()).days
                    if days_left < 0:
                        result.add_finding(Finding(
                            title="VPN Certificate Expired",
                            severity=Severity.CRITICAL,
                            category=Category.VPN,
                            description=f"VPN server certificate expired {abs(days_left)} days ago.",
                            evidence=f"Certificate: {cert_path}, Expired: {date_str}",
                            recommendation="Renew the VPN server certificate immediately.",
                            cwe_id="CWE-295",
                        ))
                    elif days_left < 30:
                        result.add_finding(Finding(
                            title=f"VPN Certificate Expiring Soon ({days_left} days)",
                            severity=Severity.HIGH,
                            category=Category.VPN,
                            description=f"VPN server certificate expires in {days_left} days.",
                            evidence=f"Certificate: {cert_path}, Expires: {date_str}",
                            recommendation="Renew the VPN server certificate.",
                            cwe_id="CWE-295",
                        ))
                except (ValueError, IndexError):
                    pass
                break

    def _check_vpn_requirement_external(self, result: ScanResult):
        """External-only check: determine if VPN is required for access."""
        result.add_finding(Finding(
            title="No VPN Tunnel Required for Access",
            severity=Severity.CRITICAL,
            category=Category.VPN,
            description="Environment is accessible without VPN. "
                        "All non-production environments should require VPN "
                        "to prevent unauthorized access.",
            evidence="Direct SSH/HTTP access possible without VPN",
            recommendation="Deploy WireGuard or OpenVPN. Configure security groups "
                           "to only allow traffic from VPN CIDR range.",
            cwe_id="CWE-284",
            cvss_score=8.5,
        ))
