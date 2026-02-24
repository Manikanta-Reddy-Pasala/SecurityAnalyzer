"""CLI entry point for Saturn Security Analyzer."""
import argparse
import os
import sys
import yaml
from .network_scanner import NetworkScanner
from .ssh_auditor import SSHAuditor
from .service_scanner import ServiceScanner
from .infra_auditor import InfraAuditor
from .report_generator import ReportGenerator
from .models import ScanResult


def load_config(config_path: str) -> dict:
    with open(config_path) as f:
        raw = f.read()
    # Substitute environment variables
    for key, val in os.environ.items():
        raw = raw.replace(f"${{{key}}}", val)
    return yaml.safe_load(raw)


def run_scan(host: str, user: str = "ec2-user",
             key_path: str = None, output_dir: str = "./reports",
             config_path: str = None) -> list[ScanResult]:
    results = []

    print(f"[*] Saturn Security Analyzer v1.0.0")
    print(f"[*] Target: {host}")
    print(f"[*] Output: {output_dir}")
    print()

    os.makedirs(output_dir, exist_ok=True)

    # 1. Network Scan
    print("[1/4] Running Network Scanner...")
    try:
        net_scanner = NetworkScanner(host)
        net_result = net_scanner.scan()
        results.append(net_result)
        print(f"      Found {len(net_result.findings)} findings")
    except Exception as e:
        print(f"      ERROR: {e}")
        results.append(ScanResult(scanner_name="Network Scanner", success=False, error=str(e)))

    # 2. SSH Audit
    print("[2/4] Running SSH Auditor...")
    try:
        ssh_auditor = SSHAuditor(host, user, key_path)
        ssh_result = ssh_auditor.audit()
        results.append(ssh_result)
        print(f"      Found {len(ssh_result.findings)} findings")
    except Exception as e:
        print(f"      ERROR: {e}")
        results.append(ScanResult(scanner_name="SSH Auditor", success=False, error=str(e)))

    # 3. Service Scan
    print("[3/4] Running Service Scanner...")
    try:
        svc_scanner = ServiceScanner(host, user, key_path)
        svc_result = svc_scanner.scan()
        results.append(svc_result)
        print(f"      Found {len(svc_result.findings)} findings")
    except Exception as e:
        print(f"      ERROR: {e}")
        results.append(ScanResult(scanner_name="Service Scanner", success=False, error=str(e)))

    # 4. Infrastructure Audit
    print("[4/4] Running Infrastructure Auditor...")
    try:
        infra_auditor = InfraAuditor(host, user, key_path)
        infra_result = infra_auditor.audit()
        results.append(infra_result)
        print(f"      Found {len(infra_result.findings)} findings")
    except Exception as e:
        print(f"      ERROR: {e}")
        results.append(ScanResult(scanner_name="Infrastructure Auditor", success=False, error=str(e)))

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
        description="Saturn Security Analyzer - UAT Environment Security Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with SSH key
  python -m saturn_analyzer --host 13.200.186.29 --user ec2-user --key ~/keys/server.pem

  # Using environment variables
  export SATURN_HOST=13.200.186.29
  export SATURN_SSH_KEY_PATH=~/keys/server.pem
  python -m saturn_analyzer --config configs/sample_config.yaml

  # Network-only scan (no SSH required)
  python -m saturn_analyzer --host 13.200.186.29 --network-only
        """,
    )
    parser.add_argument("--host", help="Target host IP or hostname")
    parser.add_argument("--user", default="ec2-user", help="SSH username (default: ec2-user)")
    parser.add_argument("--key", help="Path to SSH private key file")
    parser.add_argument("--config", help="Path to YAML config file")
    parser.add_argument("--output", default="./reports", help="Output directory (default: ./reports)")
    parser.add_argument("--network-only", action="store_true", help="Run network scan only (no SSH)")

    args = parser.parse_args()

    # Load from config if provided
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
        print("ERROR: --host is required (or set SATURN_HOST env var with --config)")
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
