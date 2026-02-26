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
from .runtime_scanner import RuntimeScanner
from .image_scanner import ImageScanner
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
             config_path: str = None, debug: bool = False) -> list[ScanResult]:
    results = []

    print(f"[*] Security Analyzer v2.3.0")
    print(f"[*] Target: {host}")
    print(f"[*] Output: {output_dir}")
    if debug:
        print(f"[*] Debug mode: ON (raw scanner output will be printed)")
    print()

    os.makedirs(output_dir, exist_ok=True)

    scanners = [
        ("1/13",  "Network Scanner",              lambda: NetworkScanner(host).scan()),
        ("2/13",  "SSH Auditor",                  lambda: SSHAuditor(host, user, key_path).audit()),
        ("3/13",  "Service Scanner",              lambda: ServiceScanner(host, user, key_path).scan()),
        ("4/13",  "Infrastructure Auditor",       lambda: InfraAuditor(host, user, key_path).audit()),
        ("5/13",  "VPN Scanner",                  lambda: VPNScanner(host, user, key_path).scan()),
        ("6/13",  "Auth Analyzer",                lambda: AuthAnalyzer(host, user, key_path).scan()),
        ("7/13",  "Payload Exposure Scanner",     lambda: PayloadScanner(host, user, key_path).scan()),
        ("8/13",  "Binary Vulnerability Scanner", lambda: BinaryScanner(host, user, key_path).scan()),
        ("9/13",  "Database Scanner",             lambda: DatabaseScanner(host, user, key_path).scan()),
        ("10/13", "Java/JVM Scanner",             lambda: JavaScanner(host, user, key_path).scan()),
        ("11/13", "Secrets & Credentials Scanner",lambda: SecretsScanner(host, user, key_path).scan()),
        ("12/13", "Container Security Scanner",   lambda: ContainerScanner(host, user, key_path).scan()),
        ("13/13", "Runtime Language Scanner",     lambda: RuntimeScanner(host, user, key_path).scan()),
    ]

    for step, name, scan_fn in scanners:
        print(f"[{step}] Running {name}...")
        try:
            scan_result = scan_fn()
            results.append(scan_result)
            print(f"      Found {len(scan_result.findings)} findings")
            # Always print Runtime Scanner raw output (it contains diagnostics)
            # Also print any scanner raw output in debug mode
            if debug or (name == "Runtime Language Scanner" and len(scan_result.findings) == 0):
                if scan_result.raw_output and scan_result.raw_output.strip():
                    print(f"\n--- {name} Raw Output ---")
                    print(scan_result.raw_output[:8000])
                    print(f"--- End {name} Raw Output ---\n")
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


def run_image_scan(images: list[str], output_dir: str = "./reports",
                   debug: bool = False) -> list[ScanResult]:
    """Scan one or more Docker images locally — no SSH required."""
    results = []

    print(f"[*] Security Analyzer v2.3.0 — Image Scanner")
    print(f"[*] Images: {', '.join(images)}")
    print(f"[*] Output: {output_dir}")
    if debug:
        print(f"[*] Debug mode: ON")
    print()

    os.makedirs(output_dir, exist_ok=True)

    for idx, image in enumerate(images, 1):
        print(f"[{idx}/{len(images)}] Scanning image: {image} ...")
        try:
            scanner = ImageScanner(image)
            scan_result = scanner.scan()
            results.append(scan_result)
            print(f"      Found {len(scan_result.findings)} findings")
            if debug and scan_result.raw_output and scan_result.raw_output.strip():
                print(f"\n--- Image Scanner Raw Output: {image} ---")
                print(scan_result.raw_output[:8000])
                print(f"--- End Raw Output ---\n")
        except Exception as e:
            print(f"      ERROR: {e}")
            results.append(ScanResult(
                scanner_name=f"Image Scanner ({image})", success=False, error=str(e)
            ))

    # Generate reports
    print()
    print("[*] Generating reports...")
    # Use first image name as the "host" label in reports
    label = images[0] if images else "image-scan"
    generator = ReportGenerator(results, label)
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
  # Full SSH-based scan
  python -m security_analyzer --host <IP> --user ec2-user --key ~/keys/server.pem

  # Using a YAML config file
  export SCAN_HOST=<IP>
  python -m security_analyzer --config configs/sample_config.yaml

  # Network-only scan (no SSH required)
  python -m security_analyzer --host <IP> --network-only

  # Scan a Docker image locally (NO SSH required)
  python -m security_analyzer --image nginx:latest
  python -m security_analyzer --image myrepo/myapp:1.2.3 --image redis:7-alpine
        """,
    )
    parser.add_argument("--host", help="Target host IP or hostname")
    parser.add_argument("--user", default="ec2-user", help="SSH username (default: ec2-user)")
    parser.add_argument("--key", help="Path to SSH private key file")
    parser.add_argument("--config", help="Path to YAML config file")
    parser.add_argument("--output", default="./reports", help="Output directory (default: ./reports)")
    parser.add_argument("--network-only", action="store_true", help="Run network scan only (no SSH)")
    parser.add_argument("--debug", action="store_true", help="Print raw scanner output for debugging")
    parser.add_argument(
        "--image", dest="images", action="append", metavar="IMAGE",
        help="Docker image to scan locally (no SSH needed). Can be repeated for multiple images.",
    )

    args = parser.parse_args()

    # ── Image scan mode (no SSH) ─────────────────────────────────────────────
    if args.images:
        run_image_scan(args.images, output_dir=args.output, debug=args.debug)
        return

    # ── SSH-based scan modes ─────────────────────────────────────────────────
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
        print("ERROR: --host is required (or use --image for local image scanning)")
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
        run_scan(host, user, key_path, output_dir, debug=args.debug)


if __name__ == "__main__":
    main()
