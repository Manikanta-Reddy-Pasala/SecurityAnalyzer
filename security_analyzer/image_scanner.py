"""Docker image security scanner — operates locally, no SSH required.

Pulls the image with local Docker, creates a temporary stopped container,
exports its filesystem, and runs a broad set of checks:

  * Image config (USER, ENV secrets, exposed ports, healthcheck)
  * Build-layer history (curl|bash, apt without cleanup, inline secrets)
  * Filesystem (setuid bins, world-writable dirs, private keys, .env files)
  * ELF binary hardening (PIE, stack canary, RELRO)
  * CVE scanning via Trivy (if installed locally)

Usage:
    from security_analyzer.image_scanner import ImageScanner
    result = ImageScanner("nginx:latest").scan()
"""

import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Optional, Tuple

from .models import Category, Finding, ScanResult, Severity

# ──────────────────────────────────────────────────────────────────────────────
# Pattern tables
# ──────────────────────────────────────────────────────────────────────────────

SECRET_ENV_RE = re.compile(
    r"(PASSWORD|PASSWD|SECRET|API[_\-]?KEY|TOKEN|CREDENTIAL|AUTH[_\-]?TOKEN"
    r"|PRIVATE[_\-]?KEY|ACCESS[_\-]?KEY|AWS_SECRET|DATABASE_URL"
    r"|DB_PASS|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD)",
    re.IGNORECASE,
)

SHELL_INJECTION_RE = re.compile(
    r"curl\s+[^\|]+\|\s*(ba)?sh|wget\s+[^\|]+\|\s*(ba)?sh|eval\s+\$\("
)

LAYER_SECRET_RE = re.compile(
    r"(?:password|passwd|secret|token|api.?key)\s*[=:]\s*\S+",
    re.IGNORECASE,
)

# Ports that are suspicious if explicitly EXPOSEd in the image
DANGEROUS_EXPOSED_PORTS = {
    "23/tcp":   ("Telnet",                     Severity.HIGH),
    "2375/tcp": ("Docker API (unauthenticated)", Severity.CRITICAL),
    "2376/tcp": ("Docker API (TLS)",            Severity.MEDIUM),
    "3306/tcp": ("MySQL",                       Severity.MEDIUM),
    "5432/tcp": ("PostgreSQL",                  Severity.MEDIUM),
    "6379/tcp": ("Redis",                       Severity.MEDIUM),
    "27017/tcp":("MongoDB",                     Severity.MEDIUM),
}

# Extensions we try to read and check for PEM private keys
PRIVATE_KEY_EXTS = {".pem", ".key", ".p12", ".pfx", ".jks", ".ppk"}

# Files whose contents should be scanned for secrets
SECRET_FILE_NAMES = {".env", ".env.local", ".env.production", ".env.development",
                     ".npmrc", ".pypirc", "credentials", ".netrc"}


class ImageScanner:
    """Scan a Docker image locally without SSH.

    Creates a temporary stopped container, exports the filesystem, and
    runs security checks against it.  All Docker commands run locally.
    """

    def __init__(self, image: str):
        self.image = image
        self._container_id: Optional[str] = None
        self._tmpdir: Optional[str] = None

    # ──────────────────────────────────────────────────────── public entry point

    def scan(self) -> ScanResult:
        result = ScanResult(scanner_name="Image Scanner")
        result.raw_output += f"[*] Image Scanner — target: {self.image}\n\n"

        if not self._check_docker(result):
            return result

        if not self._pull_image(result):
            return result

        # Config-level checks — no filesystem needed
        inspect_data = self._get_inspect(result)
        if inspect_data:
            self._check_config(result, inspect_data)

        # Build-layer history checks
        self._check_history(result)

        # Filesystem checks — export image FS into a temp dir
        try:
            self._tmpdir = tempfile.mkdtemp(prefix="secanalyzer_img_")
            tar_path = os.path.join(self._tmpdir, "rootfs.tar")
            if self._export_fs(result, tar_path):
                rootfs = os.path.join(self._tmpdir, "rootfs")
                os.makedirs(rootfs, exist_ok=True)
                if self._extract_tar(result, tar_path, rootfs):
                    self._check_filesystem(result, rootfs)
                    self._check_secrets_in_files(result, rootfs)
                    self._check_elf_hardening(result, rootfs)
        finally:
            self._cleanup()

        # Optional CVE scan via Trivy
        self._check_trivy(result)

        total = len(result.findings)
        result.raw_output += f"\n[*] Image scan complete — {total} finding(s)\n"
        return result

    # ──────────────────────────────────────────────────────────────── helpers

    def _run(self, cmd: list, timeout: int = 120) -> Tuple[str, str, int]:
        """Run a local subprocess; returns (stdout, stderr, returncode)."""
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return proc.stdout or "", proc.stderr or "", proc.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", -1
        except FileNotFoundError:
            return "", f"Not found: {cmd[0]}", -1
        except Exception as exc:
            return "", str(exc), -1

    def _check_docker(self, result: ScanResult) -> bool:
        _, stderr, rc = self._run(["docker", "info"], timeout=15)
        if rc != 0:
            result.add_finding(Finding(
                title="Docker Not Available Locally — Image Scan Skipped",
                severity=Severity.INFO,
                category=Category.CONTAINER,
                description="Docker is not running or accessible on this machine. "
                            "Image scanning requires a local Docker daemon.",
                evidence=stderr[:300],
                recommendation="Start the Docker daemon and re-run the scan.",
            ))
            return False
        result.raw_output += "Docker daemon: available\n"
        return True

    def _pull_image(self, result: ScanResult) -> bool:
        result.raw_output += f"[*] Pulling {self.image} ...\n"
        stdout, stderr, rc = self._run(["docker", "pull", self.image], timeout=300)
        result.raw_output += f"docker pull rc={rc}\n"
        if rc != 0:
            result.add_finding(Finding(
                title=f"Cannot Pull Image: {self.image}",
                severity=Severity.INFO,
                category=Category.CONTAINER,
                description=f"Failed to pull Docker image '{self.image}'. "
                            "The image may not exist or the registry may be unreachable.",
                evidence=stderr[:400],
                recommendation="Verify the image name and registry credentials.",
            ))
            return False
        return True

    def _get_inspect(self, result: ScanResult) -> Optional[dict]:
        stdout, stderr, rc = self._run(["docker", "inspect", self.image])
        if rc != 0 or not stdout.strip():
            result.raw_output += f"docker inspect failed: {stderr}\n"
            return None
        try:
            data = json.loads(stdout)
            return data[0] if data else None
        except (json.JSONDecodeError, IndexError):
            result.raw_output += "Could not parse docker inspect JSON\n"
            return None

    def _export_fs(self, result: ScanResult, tar_path: str) -> bool:
        """Create a stopped container and export its filesystem."""
        cname = f"secanalyzer_img_{os.getpid()}"
        stdout, stderr, rc = self._run(
            ["docker", "create", "--name", cname, self.image], timeout=30
        )
        if rc != 0:
            result.raw_output += f"docker create failed: {stderr}\n"
            return False
        self._container_id = stdout.strip()
        result.raw_output += f"Temp container: {self._container_id[:12]}\n"

        result.raw_output += "[*] Exporting filesystem (docker export) ...\n"
        _, stderr, rc = self._run(
            ["docker", "export", "-o", tar_path, self._container_id], timeout=300
        )
        if rc != 0:
            result.raw_output += f"docker export failed: {stderr}\n"
            return False

        size_mb = os.path.getsize(tar_path) / 1024 / 1024
        result.raw_output += f"Exported {size_mb:.1f} MB\n"
        return True

    def _extract_tar(self, result: ScanResult, tar_path: str, rootfs: str) -> bool:
        try:
            result.raw_output += "[*] Extracting rootfs ...\n"
            with tarfile.open(tar_path, "r:") as tf:
                members = []
                for m in tf.getmembers():
                    # Skip devices, sockets, and suspiciously-named paths
                    if m.isdev():
                        continue
                    if m.name.startswith("/") or ".." in m.name:
                        continue
                    members.append(m)
                # Python ≥3.12: use filter="tar" for safety; fall back gracefully
                try:
                    tf.extractall(rootfs, members=members, filter="tar")
                except TypeError:
                    tf.extractall(rootfs, members=members)  # Python <3.12
            result.raw_output += f"Rootfs extracted to {rootfs}\n"
            return True
        except Exception as exc:
            result.raw_output += f"Extraction error: {exc}\n"
            return False

    def _cleanup(self):
        if self._container_id:
            self._run(["docker", "rm", "-f", self._container_id], timeout=30)
            self._container_id = None
        if self._tmpdir and os.path.exists(self._tmpdir):
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None

    # ──────────────────────────────────────────────────── config-level checks

    def _check_config(self, result: ScanResult, data: dict) -> None:
        result.raw_output += "\n--- Image Configuration ---\n"
        config = data.get("Config", {}) or {}

        # ── USER ──────────────────────────────────────────────────────────────
        user = config.get("User", "") or ""
        result.raw_output += f"USER: '{user or '(empty)'}'\n"
        if not user or user.strip() in ("root", "0", "0:0", "0:root"):
            result.add_finding(Finding(
                title=f"Image Runs as Root: {self.image}",
                severity=Severity.HIGH,
                category=Category.CONTAINER,
                description=f"Image '{self.image}' does not specify a non-root USER directive. "
                            "Containers launched from this image default to UID 0 (root). "
                            "A container escape grants full host root access.",
                evidence=f"Config.User: '{user or '(empty)'}' → defaults to root",
                recommendation="Add a non-root USER in the Dockerfile. Create a dedicated "
                               "service account (e.g., RUN adduser --disabled-password appuser && "
                               "USER appuser).",
                cwe_id="CWE-250",
                cvss_score=7.5,
            ))

        # ── ENV secrets ───────────────────────────────────────────────────────
        env_vars = config.get("Env", []) or []
        secret_envs = []
        for var in env_vars:
            if "=" not in var:
                continue
            key, _, value = var.partition("=")
            if SECRET_ENV_RE.search(key) and value and value not in ("", "null", "change_me"):
                masked = (value[:4] + "****") if len(value) > 4 else "****"
                secret_envs.append(f"{key}={masked}")
        if secret_envs:
            result.add_finding(Finding(
                title=f"Secrets Baked into Image ENV: {self.image}",
                severity=Severity.HIGH,
                category=Category.CONTAINER,
                description=f"Image '{self.image}' has environment variables that appear to "
                            "contain secrets. These are baked into the image and visible to "
                            "anyone who can pull or inspect it.",
                evidence="; ".join(secret_envs[:8]),
                recommendation="Remove secrets from ENV. Inject them at runtime using Docker "
                               "secrets, Kubernetes secrets, or a vault solution.",
                cwe_id="CWE-312",
                cvss_score=7.5,
            ))
            result.raw_output += f"Secret envs: {secret_envs}\n"

        # ── ExposedPorts ──────────────────────────────────────────────────────
        exposed = config.get("ExposedPorts", {}) or {}
        result.raw_output += f"ExposedPorts: {list(exposed.keys())}\n"
        for port, (service, severity) in DANGEROUS_EXPOSED_PORTS.items():
            if port in exposed:
                result.add_finding(Finding(
                    title=f"Sensitive Port Exposed in Image: {port} ({service})",
                    severity=severity,
                    category=Category.CONTAINER,
                    description=f"Image '{self.image}' exposes port {port} ({service}). "
                                "This indicates the container may publish a sensitive service.",
                    evidence=f"EXPOSE {port} in image config",
                    recommendation=f"Ensure {service} on port {port} requires strong "
                                   "authentication and is not accidentally internet-accessible.",
                    cwe_id="CWE-284",
                ))

        # ── Healthcheck ───────────────────────────────────────────────────────
        if not config.get("Healthcheck"):
            result.add_finding(Finding(
                title=f"No HEALTHCHECK Defined: {self.image}",
                severity=Severity.LOW,
                category=Category.CONTAINER,
                description="The image has no HEALTHCHECK instruction. Orchestrators cannot "
                            "detect an unhealthy container and remove it from service.",
                evidence="Config.Healthcheck: (not set)",
                recommendation="Add HEALTHCHECK to the Dockerfile.",
            ))

        # ── Image age ─────────────────────────────────────────────────────────
        created = data.get("Created", "")
        result.raw_output += f"Created: {created}\n"

    # ──────────────────────────────────────────────────── history / layer checks

    def _check_history(self, result: ScanResult) -> None:
        result.raw_output += "\n--- Layer History Analysis ---\n"
        stdout, stderr, rc = self._run(
            ["docker", "history", "--no-trunc", "--format", "{{.CreatedBy}}", self.image]
        )
        if rc != 0 or not stdout.strip():
            result.raw_output += f"docker history failed: {stderr}\n"
            return

        layers = stdout.strip().splitlines()
        result.raw_output += f"Total layers: {len(layers)}\n"

        shell_injections: list[str] = []
        apt_no_cleanup: list[str] = []
        inline_secrets: list[str] = []

        for layer in layers:
            if SHELL_INJECTION_RE.search(layer):
                shell_injections.append(layer[:200])

            if "apt-get install" in layer and "rm -rf /var/lib/apt/lists" not in layer:
                apt_no_cleanup.append(layer[:120])

            if LAYER_SECRET_RE.search(layer):
                inline_secrets.append(layer[:200])

        if shell_injections:
            result.add_finding(Finding(
                title="Shell Injection Build Pattern in Image (curl/wget|bash)",
                severity=Severity.HIGH,
                category=Category.CONTAINER,
                description="The image was built using a shell injection pattern "
                            "(curl URL|bash or wget URL|sh). If the URL was compromised, "
                            "arbitrary code ran during the build — a supply chain risk.",
                evidence="\n".join(shell_injections[:3]),
                recommendation="Download scripts separately, verify their checksum (sha256sum), "
                               "then execute. Never pipe directly into a shell.",
                cwe_id="CWE-78",
                cvss_score=7.0,
            ))

        if apt_no_cleanup:
            result.add_finding(Finding(
                title="apt-get Layers Without Cache Cleanup",
                severity=Severity.INFO,
                category=Category.CONTAINER,
                description=f"{len(apt_no_cleanup)} build layer(s) run apt-get install without "
                            "cleaning the package cache (rm -rf /var/lib/apt/lists/*). "
                            "This bloats the image and leaves package metadata that reveals "
                            "the installed software.",
                evidence="\n".join(apt_no_cleanup[:3]),
                recommendation="Combine apt-get update && apt-get install -y ... && "
                               "rm -rf /var/lib/apt/lists/* in a single RUN instruction.",
            ))

        if inline_secrets:
            result.add_finding(Finding(
                title="Possible Secret Hardcoded in Build Layer",
                severity=Severity.HIGH,
                category=Category.CONTAINER,
                description="One or more build layers appear to contain hardcoded secrets "
                            "(password, token, API key). Even if overwritten later, the "
                            "secret remains accessible via image layer history.",
                evidence="\n".join(inline_secrets[:3]),
                recommendation="Never put secrets in RUN commands. Use Docker BuildKit "
                               "secrets (--secret) or multi-stage builds to avoid leaking "
                               "secrets into any layer.",
                cwe_id="CWE-312",
                cvss_score=8.0,
            ))

    # ──────────────────────────────────────────────────── filesystem checks

    def _check_filesystem(self, result: ScanResult, rootfs: str) -> None:
        result.raw_output += "\n--- Filesystem Security Checks ---\n"
        rootfs_path = Path(rootfs)

        setuid_bins: list[str] = []
        setgid_bins: list[str] = []
        ww_dirs: list[str] = []

        SAFE_WW_DIRS = {"tmp", "var/tmp", "run", "dev", "proc", "sys", "dev/shm"}

        for fpath in rootfs_path.rglob("*"):
            try:
                rel = str(fpath.relative_to(rootfs_path))
                if fpath.is_symlink():
                    continue

                if fpath.is_file():
                    mode = fpath.stat().st_mode
                    if mode & 0o4000:
                        setuid_bins.append(rel)
                    elif mode & 0o2000:
                        setgid_bins.append(rel)

                elif fpath.is_dir():
                    if rel in SAFE_WW_DIRS:
                        continue
                    mode = fpath.stat().st_mode
                    if mode & 0o002:
                        ww_dirs.append(rel)

            except (PermissionError, OSError):
                continue

        result.raw_output += (
            f"Setuid: {len(setuid_bins)}, Setgid: {len(setgid_bins)}, "
            f"World-writable dirs: {len(ww_dirs)}\n"
        )

        if setuid_bins:
            result.add_finding(Finding(
                title=f"Setuid Binaries in Image: {len(setuid_bins)} found",
                severity=Severity.MEDIUM,
                category=Category.CONTAINER,
                description=f"{len(setuid_bins)} setuid binary/binaries found in image "
                            f"'{self.image}'. Setuid binaries run with elevated privileges "
                            "regardless of the calling user — common targets for privilege "
                            "escalation inside containers.",
                evidence=f"Setuid binaries: {', '.join(setuid_bins[:12])}",
                recommendation="Remove unnecessary setuid binaries. Use specific Linux "
                               "capabilities (--cap-add) rather than setuid bits.",
                cwe_id="CWE-250",
            ))

        if ww_dirs:
            result.add_finding(Finding(
                title=f"World-Writable Directories in Image: {len(ww_dirs)} found",
                severity=Severity.LOW,
                category=Category.CONTAINER,
                description=f"{len(ww_dirs)} world-writable director(ies) found outside /tmp. "
                            "Attackers who gain code execution can use these to drop and "
                            "execute malicious files.",
                evidence=f"World-writable dirs: {', '.join(ww_dirs[:10])}",
                recommendation="Set correct ownership and mode in the Dockerfile "
                               "(chmod o-w on directories that don't need it).",
                cwe_id="CWE-276",
            ))

        # /etc/passwd — non-root user with UID 0
        passwd_path = rootfs_path / "etc" / "passwd"
        if passwd_path.exists():
            try:
                for line in passwd_path.read_text(errors="replace").splitlines():
                    parts = line.split(":")
                    if len(parts) < 7:
                        continue
                    username, _, uid = parts[0], parts[1], parts[2]
                    if uid == "0" and username != "root":
                        result.add_finding(Finding(
                            title=f"Non-root Username with UID 0 in Image: '{username}'",
                            severity=Severity.CRITICAL,
                            category=Category.CONTAINER,
                            description=f"User '{username}' has UID 0 (root) in /etc/passwd. "
                                        "This is a classic backdoor technique — the user has "
                                        "full root privileges.",
                            evidence=f"/etc/passwd: {line}",
                            recommendation="Remove all non-root users with UID 0.",
                            cwe_id="CWE-269",
                            cvss_score=9.8,
                        ))
            except OSError:
                pass

        # /etc/shadow — world-readable
        shadow_path = rootfs_path / "etc" / "shadow"
        if shadow_path.exists():
            try:
                mode = shadow_path.stat().st_mode
                if mode & 0o004:
                    result.add_finding(Finding(
                        title="World-Readable /etc/shadow in Image",
                        severity=Severity.CRITICAL,
                        category=Category.CONTAINER,
                        description="/etc/shadow is world-readable. It contains hashed passwords "
                                    "and should only be accessible by root/shadow group.",
                        evidence=f"/etc/shadow permissions: {oct(mode)}",
                        recommendation="Fix in Dockerfile: RUN chmod 640 /etc/shadow",
                        cwe_id="CWE-732",
                        cvss_score=8.0,
                    ))
            except OSError:
                pass

    def _check_secrets_in_files(self, result: ScanResult, rootfs: str) -> None:
        result.raw_output += "\n--- Secrets in Image Filesystem ---\n"
        rootfs_path = Path(rootfs)

        found_keys: list[str] = []
        found_aws: list[str] = []
        found_dotenv: list[str] = []
        found_gh_tokens: list[str] = []

        AWS_KEY_RE = re.compile(r"AKIA[A-Z0-9]{16}")
        GH_TOKEN_RE = re.compile(r"ghp_[A-Za-z0-9]{36}")
        OPENAI_RE   = re.compile(r"sk-[A-Za-z0-9]{32,}")

        scanned = 0
        for fpath in rootfs_path.rglob("*"):
            if not fpath.is_file() or fpath.is_symlink():
                continue
            if scanned > 60_000:
                result.raw_output += "(file scan limit reached)\n"
                break
            scanned += 1

            rel = str(fpath.relative_to(rootfs_path))
            name_lower = fpath.name.lower()

            # Private key files by extension
            if fpath.suffix.lower() in PRIVATE_KEY_EXTS:
                try:
                    head = fpath.read_bytes()[:512]
                    if b"PRIVATE KEY" in head:
                        found_keys.append(rel)
                except (PermissionError, OSError):
                    pass
                continue

            # Private key files in SSH directories
            if ".ssh/" in rel or rel.startswith(".ssh/"):
                try:
                    head = fpath.read_bytes()[:512]
                    if b"PRIVATE KEY" in head:
                        found_keys.append(rel)
                except (PermissionError, OSError):
                    pass
                continue

            # AWS credentials
            if ".aws/" in rel or rel.startswith(".aws/") or name_lower == "credentials":
                try:
                    content = fpath.read_text(errors="replace")
                    if "aws_secret_access_key" in content.lower():
                        found_aws.append(rel)
                    elif AWS_KEY_RE.search(content):
                        found_aws.append(rel)
                except (PermissionError, OSError):
                    pass
                continue

            # .env files
            if name_lower in SECRET_FILE_NAMES:
                try:
                    content = fpath.read_text(errors="replace")
                    hits = []
                    for line in content.splitlines():
                        if "=" in line and SECRET_ENV_RE.search(line):
                            key, _, val = line.partition("=")
                            if val.strip():
                                hits.append(f"{key}=****")
                    if hits:
                        found_dotenv.append(f"{rel}: {', '.join(hits[:4])}")
                except (PermissionError, OSError):
                    pass
                continue

            # Quick scan of small files for high-value tokens
            if fpath.stat().st_size < 100_000:
                try:
                    content = fpath.read_text(errors="replace")
                    if "BEGIN PRIVATE KEY" in content or "BEGIN RSA PRIVATE KEY" in content:
                        found_keys.append(rel)
                    elif GH_TOKEN_RE.search(content):
                        found_gh_tokens.append(rel)
                    elif AWS_KEY_RE.search(content):
                        found_aws.append(rel)
                except (PermissionError, OSError, UnicodeDecodeError):
                    pass

        result.raw_output += (
            f"Scanned {scanned} files — "
            f"keys={len(found_keys)}, aws={len(found_aws)}, "
            f"dotenv={len(found_dotenv)}, gh_tokens={len(found_gh_tokens)}\n"
        )

        if found_keys:
            result.add_finding(Finding(
                title=f"Private Keys Embedded in Image: {len(found_keys)} file(s)",
                severity=Severity.CRITICAL,
                category=Category.CONTAINER,
                description=f"{len(found_keys)} private key file(s) found in image "
                            f"'{self.image}'. Anyone who can pull this image has access "
                            "to these private keys.",
                evidence=f"Files: {', '.join(found_keys[:8])}",
                recommendation="Remove private keys from the image immediately. Use "
                               "Docker BuildKit secrets or runtime mounts. Revoke and "
                               "rotate all exposed keys.",
                cwe_id="CWE-312",
                cvss_score=9.5,
            ))

        if found_aws:
            result.add_finding(Finding(
                title="AWS Credentials Found in Image Filesystem",
                severity=Severity.CRITICAL,
                category=Category.CONTAINER,
                description=f"AWS credential files or Access Key IDs were found embedded "
                            f"in image '{self.image}'. These credentials grant AWS API access "
                            "to anyone who pulls the image.",
                evidence=f"Files: {', '.join(found_aws[:8])}",
                recommendation="Remove AWS credentials from the image. Use IAM instance "
                               "profiles, IRSA (EKS), or inject credentials at runtime via "
                               "secrets manager.",
                cwe_id="CWE-312",
                cvss_score=9.5,
            ))

        if found_dotenv:
            result.add_finding(Finding(
                title="Secret .env Files Found in Image Filesystem",
                severity=Severity.HIGH,
                category=Category.CONTAINER,
                description=f".env files containing credentials are embedded in image "
                            f"'{self.image}'.",
                evidence="\n".join(found_dotenv[:6]),
                recommendation="Add .env files to .dockerignore. Inject environment "
                               "variables at runtime.",
                cwe_id="CWE-312",
                cvss_score=8.0,
            ))

        if found_gh_tokens:
            result.add_finding(Finding(
                title="GitHub Personal Access Token Found in Image",
                severity=Severity.CRITICAL,
                category=Category.CONTAINER,
                description=f"GitHub Personal Access Tokens (ghp_...) were found in "
                            f"image '{self.image}'. These tokens grant GitHub API access.",
                evidence=f"Files: {', '.join(found_gh_tokens[:6])}",
                recommendation="Revoke the tokens immediately. Do not embed API tokens "
                               "in images. Use GitHub Actions secrets or vault solutions.",
                cwe_id="CWE-312",
                cvss_score=9.5,
            ))

    def _check_elf_hardening(self, result: ScanResult, rootfs: str) -> None:
        result.raw_output += "\n--- ELF Binary Hardening ---\n"
        rootfs_path = Path(rootfs)

        # Collect ELF binaries from common bin directories
        scan_dirs = [
            "bin", "sbin", "usr/bin", "usr/sbin",
            "usr/local/bin", "usr/local/sbin",
            "app", "opt", "srv",
        ]
        elf_bins: list[Path] = []
        for d in scan_dirs:
            dpath = rootfs_path / d
            if not dpath.is_dir():
                continue
            for fp in dpath.iterdir():
                if not fp.is_file() or fp.is_symlink():
                    continue
                try:
                    with open(fp, "rb") as f:
                        if f.read(4) == b"\x7fELF":
                            elf_bins.append(fp)
                except (PermissionError, OSError):
                    continue

        result.raw_output += f"ELF binaries found: {len(elf_bins)}\n"
        if not elf_bins:
            return

        no_pie:    list[str] = []
        no_canary: list[str] = []
        no_relro:  list[str] = []

        for binpath in elf_bins[:60]:   # cap at 60 to keep scan time reasonable
            rel = str(binpath.relative_to(rootfs_path))
            try:
                # PIE: look for DYN type in ELF header
                rh = subprocess.run(
                    ["readelf", "-h", str(binpath)],
                    capture_output=True, text=True, timeout=5,
                )
                if rh.returncode == 0:
                    if "EXEC (Executable file)" in rh.stdout:
                        no_pie.append(rel)

                # Stack canary: symbol __stack_chk_fail present in binary
                nm = subprocess.run(
                    ["nm", "--dynamic", str(binpath)],
                    capture_output=True, text=True, timeout=5,
                )
                if nm.returncode == 0 and "__stack_chk_fail" not in nm.stdout:
                    # Also try regular nm (static symbols)
                    nm2 = subprocess.run(
                        ["nm", str(binpath)],
                        capture_output=True, text=True, timeout=5,
                    )
                    if nm2.returncode == 0 and "__stack_chk_fail" not in nm2.stdout:
                        no_canary.append(rel)

                # RELRO: GNU_RELRO program header
                rl = subprocess.run(
                    ["readelf", "-l", str(binpath)],
                    capture_output=True, text=True, timeout=5,
                )
                if rl.returncode == 0 and "GNU_RELRO" not in rl.stdout:
                    no_relro.append(rel)

            except (subprocess.TimeoutExpired, Exception):
                continue

        result.raw_output += (
            f"No PIE: {len(no_pie)}, No canary: {len(no_canary)}, No RELRO: {len(no_relro)}\n"
        )

        if no_pie:
            result.add_finding(Finding(
                title=f"Non-PIE Binaries in Image: {len(no_pie)} found",
                severity=Severity.MEDIUM,
                category=Category.BINARY_SECURITY,
                description=f"{len(no_pie)} ELF binary/binaries in image '{self.image}' are "
                            "not compiled as Position Independent Executables. Non-PIE binaries "
                            "have predictable memory layouts, enabling ROP attacks that bypass ASLR.",
                evidence=f"Non-PIE: {', '.join(no_pie[:10])}",
                recommendation="Compile with -fPIE -pie. Modern build systems (GCC, Clang, Go) "
                               "enable this by default.",
                cwe_id="CWE-119",
            ))

        if no_canary:
            result.add_finding(Finding(
                title=f"Binaries Without Stack Canaries in Image: {len(no_canary)} found",
                severity=Severity.MEDIUM,
                category=Category.BINARY_SECURITY,
                description=f"{len(no_canary)} binary/binaries in image '{self.image}' lack "
                            "stack canary protection (__stack_chk_fail). Stack canaries detect "
                            "stack buffer overflows before a return address is overwritten.",
                evidence=f"No canary: {', '.join(no_canary[:10])}",
                recommendation="Compile with -fstack-protector-strong or -fstack-protector-all.",
                cwe_id="CWE-121",
            ))

        if no_relro:
            result.add_finding(Finding(
                title=f"Binaries Without RELRO in Image: {len(no_relro)} found",
                severity=Severity.LOW,
                category=Category.BINARY_SECURITY,
                description=f"{len(no_relro)} binary/binaries in image '{self.image}' lack "
                            "RELRO (Relocation Read-Only). Without RELRO, the GOT is writable "
                            "and can be overwritten by memory corruption bugs.",
                evidence=f"No RELRO: {', '.join(no_relro[:10])}",
                recommendation="Link with -Wl,-z,relro,-z,now for full RELRO.",
                cwe_id="CWE-119",
            ))

    # ──────────────────────────────────────────────────────── trivy CVE scan

    def _check_trivy(self, result: ScanResult) -> None:
        result.raw_output += "\n--- Trivy CVE Scan ---\n"
        _, _, rc = self._run(["which", "trivy"], timeout=5)
        if rc != 0:
            result.add_finding(Finding(
                title="Trivy Not Installed — CVE Scan Skipped",
                severity=Severity.INFO,
                category=Category.CONTAINER,
                description="Trivy is not available locally. Install it for automated "
                            "OS package and application dependency CVE scanning.",
                recommendation="Install Trivy: https://aquasecurity.github.io/trivy/",
            ))
            result.raw_output += "trivy not found — skipping\n"
            return

        result.raw_output += "[*] Running trivy scan ...\n"
        scan_out, stderr, rc = self._run(
            ["trivy", "image", "--format", "json",
             "--severity", "HIGH,CRITICAL", "--quiet", self.image],
            timeout=300,
        )

        if not scan_out or not scan_out.strip():
            result.raw_output += f"trivy returned no output: {stderr}\n"
            return

        try:
            report = json.loads(scan_out)
        except json.JSONDecodeError:
            result.raw_output += "Could not parse trivy JSON\n"
            return

        critical_count = 0
        high_count = 0
        sample_cves: list[str] = []

        for res in report.get("Results", []):
            for vuln in res.get("Vulnerabilities", []) or []:
                sev = vuln.get("Severity", "")
                vid = vuln.get("VulnerabilityID", "")
                if sev == "CRITICAL":
                    critical_count += 1
                    if len(sample_cves) < 5:
                        sample_cves.append(vid)
                elif sev == "HIGH":
                    high_count += 1
                    if len(sample_cves) < 5:
                        sample_cves.append(vid)

        result.raw_output += f"Trivy: CRITICAL={critical_count}, HIGH={high_count}\n"

        if critical_count > 0:
            result.add_finding(Finding(
                title=f"Image Has CRITICAL CVEs: {self.image}",
                severity=Severity.CRITICAL,
                category=Category.CONTAINER,
                description=f"Trivy found {critical_count} CRITICAL and {high_count} HIGH CVEs "
                            f"in image '{self.image}'. CRITICAL CVEs are typically remotely "
                            "exploitable and may lead to full system compromise.",
                evidence=f"CRITICAL: {critical_count}, HIGH: {high_count}. "
                         f"Sample CVEs: {', '.join(sample_cves)}",
                recommendation="Rebuild the image from a patched base image. Update all "
                               "OS packages. Integrate Trivy into CI/CD to block vulnerable images.",
                cvss_score=9.0,
            ))
        elif high_count > 0:
            result.add_finding(Finding(
                title=f"Image Has HIGH CVEs: {self.image}",
                severity=Severity.HIGH,
                category=Category.CONTAINER,
                description=f"Trivy found {high_count} HIGH CVEs in image '{self.image}'.",
                evidence=f"HIGH: {high_count}. Sample CVEs: {', '.join(sample_cves)}",
                recommendation="Update affected packages and rebuild the image.",
            ))
        else:
            result.raw_output += "No HIGH/CRITICAL CVEs found by Trivy ✓\n"
