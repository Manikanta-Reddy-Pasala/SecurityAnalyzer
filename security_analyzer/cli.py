"""CLI entry point for Security Analyzer."""
import argparse
import os
import sys
import yaml
from .network_scanner import NetworkScanner
from .ssh_auditor import SSHAuditor
from .service_scanner import ServiceScanner
from .infra_auditor import InfraAuditor
from .vpn_scanner import VPNScanner
from .auth_analyzer import AuthAnalyzer
from .payload_scanner import PayloadScanner
from .binary_scanner import BinaryScanner
from .database_scanner import DatabaseScanner
from .java_scanner import JavaScanner
from .secrets_scanner import SecretsScanner
from .container_scanner import ContainerScanner
from .report_generator import ReportGenerator
from .models import ScanResult


def load_config(config_path: str) -> dict:
    with open(config_path) as f:
        raw = f.read()
    for key, val in os.environ.items():
        raw = raw.replace(f"${{{key}}}", val)
    return yaml.safe_load(raw)


def run_scan(host: str, user: str = "ec2-user",
             key_path: str = None, output_dir: str = "./reports",
             config_path: str = None) -> list[ScanResult]:
    results = []

    print(f"[*] Security Analyzer v2.1.0")
    print(f"[*] Target: {host}")
    print(f"[*] Output: {output_dir}")
    print()

    os.makedirs(output_dir, exist_ok=True)

    scanners = [
        ("1/12",  "Network Scanner",              lambda: NetworkScanner(host).scan()),
        ("2/12",  "SSH Auditor",                  lambda: SSHAuditor(host, user, key_path).audit()),
        ("3/12",  "Service Scanner",              lambda: ServiceScanner(host, user, key_path).scan()),
        ("4/12",  "Infrastructure Auditor",       lambda: InfraAuditor(host, user, key_path).audit()),
        ("5/12",  "VPN Scanner",                  lambda: VPNScanner(host, user, key_path).scan()),
        ("6/12",  "Auth Analyzer",                lambda: AuthAnalyzer(host, user, key_path).scan()),
        ("7/12",  "Payload Exposure Scanner",     lambda: PayloadScanner(host, user, key_path).scan()),
        ("8/12",  "Binary Vulnerability Scanner", lambda: BinaryScanner(host, user, key_path).scan()),
        ("9/12",  "Database Scanner",             lambda: DatabaseScanner(host, user, key_path).scan()),
        ("10/12", "Java/JVM Scanner",             lambda: JavaScanner(host, user, key_path).scan()),
        ("11/12", "Secrets & Credentials Scanner",lambda: SecretsScanner(host, user, key_path).scan()),
        ("12/12", "Container Security Scanner",   lambda: ContainerScanner(host, user, key_path).scan()),
    ]

    for step, name, scan_fn in scanners:
        print(f"[{step}] Running {name}...")
        try:
            scan_result = scan_fn()
            results.append(scan_result)
            print(f"      Found {len(scan_result.findings)} findings")
        except Exception as e:
            print(f"      ERROR: {e}")
            results.append(ScanResult(scanner_name=name, success=False, error=str(e)))

    # Generate reports
    print()
    print("[*] Generating reports...")
    generator = ReportGenerator(results, host)

    generator.generate_html(os.path.join(output_dir, "security-report.html"))
    generator.generate_markdown(os.path.join(output_dir, "security-report.md"))
    generator.generate_json(os.path.join(output_dir, "security-report.json"))

    total = sum(len(r.findings) for r in results)
    print(f"[*] Total findings: {total}")
    print(f"[*] Reports saved to {output_dir}/")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Security Analyzer - Environment Security Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan with SSH key
  python -m security_analyzer --host <IP> --user ec2-user --key ~/keys/server.pem

  # Using environment variables
  export SCAN_HOST=<IP>
  export SCAN_SSH_KEY_PATH=~/keys/server.pem
  python -m security_analyzer --config configs/sample_config.yaml

  # Network-only scan (no SSH required)
  python -m security_analyzer --host <IP> --network-only
        """,
    )
    parser.add_argument("--host", help="Target host IP or hostname")
    parser.add_argument("--user", default="ec2-user", help="SSH username (default: ec2-user)")
    parser.add_argument("--key", help="Path to SSH private key file")
    parser.add_argument("--config", help="Path to YAML config file")
    parser.add_argument("--output", default="./reports", help="Output directory (default: ./reports)")
    parser.add_argument("--network-only", action="store_true", help="Run network scan only (no SSH)")

    args = parser.parse_args()

    if args.config:
        config = load_config(args.config)
        host = args.host or config.get("target", {}).get("host", "")
        user = args.user if args.user != "ec2-user" else config.get("target", {}).get("ssh_user", "ec2-user")
        key_path = args.key or config.get("target", {}).get("ssh_key_path")
        output_dir = args.output if args.output != "./reports" else config.get("report", {}).get("output_dir", "./reports")
    else:
        host = args.host
        user = args.user
        key_path = args.key
        output_dir = args.output

    if not host:
        print("ERROR: --host is required (or set SCAN_HOST env var with --config)")
        sys.exit(1)

    if args.network_only:
        print(f"[*] Network-only scan of {host}")
        net_scanner = NetworkScanner(host)
        results = [net_scanner.scan()]
        os.makedirs(output_dir, exist_ok=True)
        generator = ReportGenerator(results, host)
        generator.generate_html(os.path.join(output_dir, "security-report.html"))
        generator.generate_markdown(os.path.join(output_dir, "security-report.md"))
        generator.generate_json(os.path.join(output_dir, "security-report.json"))
        print(f"[*] Reports saved to {output_dir}/")
    else:
        run_scan(host, user, key_path, output_dir)


if __name__ == "__main__":
    main()
