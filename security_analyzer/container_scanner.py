"""Container security scanner - privileged containers, capabilities, namespaces, images, and daemon config."""
import json
import re
import subprocess
from typing import Optional, Tuple
from .models import Finding, ScanResult, Severity, Category


# Linux capabilities considered dangerous when explicitly added
DANGEROUS_CAPS = [
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO",
    "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG",
    "MKNOD", "AUDIT_WRITE", "AUDIT_CONTROL", "MAC_OVERRIDE", "MAC_ADMIN",
    "NET_BIND_SERVICE", "SETUID", "SETGID", "FOWNER",
]

# Filesystem paths that should never be mounted into a container
DANGEROUS_MOUNTS = [
    "/", "/etc", "/var/run/docker.sock", "/proc", "/sys",
    "/dev", "/boot", "/usr", "/bin", "/sbin",
]

# Database ports that must not be bound to 0.0.0.0
DB_PORTS = {5432, 3306, 27017, 6379, 9200}


class ContainerScanner:
    """Audits Docker containers for misconfigurations, capability abuse, and runtime security issues."""

    def __init__(self, host: str, user: str = "ec2-user", key_path: Optional[str] = None):
        self.host = host
        self.user = user
        self.key_path = key_path

    # ------------------------------------------------------------------ public

    def scan(self) -> ScanResult:
        result = ScanResult(scanner_name="Container Scanner")

        stdout, _, rc = self._run_ssh("docker ps -q 2>/dev/null")
        if rc != 0 or stdout is None:
            result.add_finding(Finding(
                title="Docker Not Running - Container Scanner Skipped",
                severity=Severity.INFO,
                category=Category.CONTAINER,
                description="Docker does not appear to be installed or running on the target host. "
                            "Container security checks were skipped.",
                recommendation="Install and configure Docker if containers are required, "
                               "or remove Docker if it is not needed.",
            ))
            return result

        result.raw_output += f"Docker available. Running container IDs:\n{stdout.strip()}\n\n"

        container_ids = stdout.strip().splitlines()
        if not container_ids or not any(cid.strip() for cid in container_ids):
            result.add_finding(Finding(
                title="No Running Containers Found",
                severity=Severity.INFO,
                category=Category.CONTAINER,
                description="Docker is running but there are no active containers to inspect.",
            ))
            return result

        checks = [
            self._check_privileged_containers,
            self._check_dangerous_capabilities,
            self._check_host_namespace_sharing,
            self._check_seccomp_apparmor,
            self._check_readonly_rootfs,
            self._check_resource_limits,
            self._check_running_as_root,
            self._check_dangerous_mounts,
            self._check_docker_daemon_config,
            self._check_image_vulnerabilities,
            self._check_container_network_exposure,
            self._check_env_secrets,
        ]

        for check in checks:
            try:
                check(result)
            except Exception as exc:
                result.raw_output += f"[WARN] {check.__name__} failed: {exc}\n"

        return result

    # ----------------------------------------------------------------- helpers

    def _run_ssh(self, command: str, timeout: int = 30) -> Tuple[Optional[str], Optional[str], int]:
        """Run a command on the remote host via SSH.

        Returns (stdout, stderr, returncode). On connection failure or timeout
        returns (None, None, -1).
        """
        cmd = [
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10", "-o", "BatchMode=yes",
        ]
        if self.key_path:
            cmd.extend(["-i", self.key_path])
        cmd.append(f"{self.user}@{self.host}")
        cmd.append(command)

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired:
            return None, "SSH command timed out", -1
        except Exception as exc:
            return None, str(exc), -1

    def _inspect_all(self, format_str: str) -> Optional[str]:
        """Run docker inspect against all running containers with the given Go template."""
        stdout, _, rc = self._run_ssh(
            f"docker inspect $(docker ps -q) --format '{format_str}' 2>/dev/null"
        )
        return stdout if rc == 0 and stdout and stdout.strip() else None

    # -------------------------------------------------------- check methods

    def _check_privileged_containers(self, result: ScanResult) -> None:
        result.raw_output += "--- Privileged Containers ---\n"

        output = self._inspect_all(
            "{{.Name}}|||{{.HostConfig.Privileged}}|||{{.HostConfig.NetworkMode}}"
            "|||{{json .HostConfig.CapAdd}}|||{{json .HostConfig.CapDrop}}"
        )
        if not output:
            result.raw_output += "No inspect output for privileged check.\n"
            return

        for line in output.strip().splitlines():
            parts = line.split("|||")
            if len(parts) < 2:
                continue
            name = parts[0].strip().lstrip("/")
            privileged = parts[1].strip().lower()

            if privileged == "true":
                result.add_finding(Finding(
                    title="Privileged Container Detected",
                    severity=Severity.CRITICAL,
                    category=Category.CONTAINER,
                    description=f"Container '{name}' is running in privileged mode. "
                                "A privileged container has near-complete access to the host kernel "
                                "and devices, effectively disabling all container isolation.",
                    evidence=f"Container: {name} — Privileged: true",
                    recommendation="Remove the --privileged flag. Grant only the specific Linux "
                                   "capabilities required (use --cap-add sparingly).",
                    cwe_id="CWE-250",
                    cvss_score=9.0,
                ))

        result.raw_output += output.strip()[:500] + "\n"

    def _check_dangerous_capabilities(self, result: ScanResult) -> None:
        result.raw_output += "\n--- Container Capabilities ---\n"

        output = self._inspect_all("{{.Name}}|||{{json .HostConfig.CapAdd}}")
        if not output:
            result.raw_output += "No inspect output for capabilities check.\n"
            return

        for line in output.strip().splitlines():
            parts = line.split("|||", 1)
            if len(parts) < 2:
                continue
            name = parts[0].strip().lstrip("/")
            caps_raw = parts[1].strip()

            if caps_raw in ("null", "[]", ""):
                continue

            try:
                caps = json.loads(caps_raw)
            except json.JSONDecodeError:
                continue

            if not caps:
                continue

            found_dangerous = [c for c in caps if c in DANGEROUS_CAPS]
            if not found_dangerous:
                continue

            if "SYS_ADMIN" in found_dangerous:
                result.add_finding(Finding(
                    title="Dangerous Linux Capability: SYS_ADMIN",
                    severity=Severity.CRITICAL,
                    category=Category.CONTAINER,
                    description=f"Container '{name}' has the SYS_ADMIN capability. "
                                "SYS_ADMIN grants a wide range of administrative operations "
                                "and is nearly equivalent to running as a privileged container. "
                                "It can be used to mount filesystems, load kernel modules, "
                                "and escape the container.",
                    evidence=f"Container: {name} — CapAdd: {caps_raw}",
                    recommendation="Remove SYS_ADMIN from CapAdd. Audit whether it is truly "
                                   "needed; most use-cases have safer alternatives.",
                    cwe_id="CWE-250",
                    cvss_score=8.8,
                ))
            else:
                result.add_finding(Finding(
                    title=f"Dangerous Linux Capabilities Added: {', '.join(found_dangerous)}",
                    severity=Severity.HIGH,
                    category=Category.CONTAINER,
                    description=f"Container '{name}' has dangerous Linux capabilities granted. "
                                "These capabilities expand the attack surface and may allow "
                                "privilege escalation or host compromise.",
                    evidence=f"Container: {name} — CapAdd: {caps_raw}",
                    recommendation="Apply the principle of least privilege. Remove unnecessary "
                                   "capabilities and audit each retained capability.",
                    cwe_id="CWE-250",
                ))

        result.raw_output += output.strip()[:500] + "\n"

    def _check_host_namespace_sharing(self, result: ScanResult) -> None:
        result.raw_output += "\n--- Host Namespace Sharing ---\n"

        output = self._inspect_all(
            "{{.Name}}|||{{.HostConfig.NetworkMode}}|||{{.HostConfig.PidMode}}|||{{.HostConfig.IpcMode}}"
        )
        if not output:
            result.raw_output += "No inspect output for namespace check.\n"
            return

        for line in output.strip().splitlines():
            parts = line.split("|||")
            if len(parts) < 4:
                continue
            name = parts[0].strip().lstrip("/")
            net_mode = parts[1].strip()
            pid_mode = parts[2].strip()
            ipc_mode = parts[3].strip()

            if net_mode == "host":
                result.add_finding(Finding(
                    title="Container Shares Host Network Namespace",
                    severity=Severity.HIGH,
                    category=Category.CONTAINER,
                    description=f"Container '{name}' is using --network=host. "
                                "The container shares the host's network stack, bypassing "
                                "all network isolation and allowing direct access to host "
                                "network interfaces and services.",
                    evidence=f"Container: {name} — NetworkMode: host",
                    recommendation="Remove --network=host. Use user-defined bridge networks "
                                   "and publish only the required ports.",
                    cwe_id="CWE-653",
                ))

            if pid_mode == "host":
                result.add_finding(Finding(
                    title="Container Shares Host PID Namespace",
                    severity=Severity.CRITICAL,
                    category=Category.CONTAINER,
                    description=f"Container '{name}' is using --pid=host. "
                                "The container can see and signal all processes running on "
                                "the host, enabling process injection, ptrace attacks, and "
                                "access to host process memory.",
                    evidence=f"Container: {name} — PidMode: host",
                    recommendation="Remove --pid=host. Containers should have isolated "
                                   "PID namespaces.",
                    cwe_id="CWE-250",
                    cvss_score=8.8,
                ))

            if ipc_mode == "host":
                result.add_finding(Finding(
                    title="Container Shares Host IPC Namespace",
                    severity=Severity.HIGH,
                    category=Category.CONTAINER,
                    description=f"Container '{name}' is using --ipc=host. "
                                "Shared IPC namespace allows the container to access host "
                                "shared memory, semaphores, and message queues, which can "
                                "be exploited for inter-process attacks.",
                    evidence=f"Container: {name} — IpcMode: host",
                    recommendation="Remove --ipc=host unless strictly required. "
                                   "Use --ipc=private (the default).",
                    cwe_id="CWE-653",
                ))

        result.raw_output += output.strip()[:500] + "\n"

    def _check_seccomp_apparmor(self, result: ScanResult) -> None:
        result.raw_output += "\n--- seccomp / AppArmor Profiles ---\n"

        output = self._inspect_all("{{.Name}}|||{{.HostConfig.SecurityOpt}}")
        if not output:
            result.raw_output += "No inspect output for security profile check.\n"
            return

        for line in output.strip().splitlines():
            parts = line.split("|||", 1)
            if len(parts) < 2:
                continue
            name = parts[0].strip().lstrip("/")
            sec_opt = parts[1].strip()

            is_empty = sec_opt in ("[]", "<no value>", "")

            if is_empty:
                result.add_finding(Finding(
                    title="No Security Profile (seccomp/AppArmor)",
                    severity=Severity.MEDIUM,
                    category=Category.CONTAINER,
                    description=f"Container '{name}' has no seccomp or AppArmor profile "
                                "configured. Without these profiles the container can make "
                                "any syscall available to the kernel, increasing the blast "
                                "radius of a container escape.",
                    evidence=f"Container: {name} — SecurityOpt: {sec_opt}",
                    recommendation="Apply the default Docker seccomp profile or a custom "
                                   "restricted profile. Consider an AppArmor or SELinux profile.",
                    cwe_id="CWE-693",
                ))
                continue

            if "seccomp:unconfined" in sec_opt or "seccomp=unconfined" in sec_opt:
                result.add_finding(Finding(
                    title="seccomp Disabled",
                    severity=Severity.HIGH,
                    category=Category.CONTAINER,
                    description=f"Container '{name}' has seccomp explicitly set to unconfined. "
                                "All syscalls are permitted, removing a critical kernel "
                                "attack-surface reduction layer.",
                    evidence=f"Container: {name} — SecurityOpt: {sec_opt}",
                    recommendation="Remove seccomp=unconfined and apply at minimum the default "
                                   "Docker seccomp profile.",
                    cwe_id="CWE-693",
                    cvss_score=7.5,
                ))

            if "apparmor:unconfined" in sec_opt or "apparmor=unconfined" in sec_opt:
                result.add_finding(Finding(
                    title="AppArmor Disabled",
                    severity=Severity.MEDIUM,
                    category=Category.CONTAINER,
                    description=f"Container '{name}' has AppArmor explicitly set to unconfined. "
                                "AppArmor mandatory access control is disabled for this container.",
                    evidence=f"Container: {name} — SecurityOpt: {sec_opt}",
                    recommendation="Remove apparmor=unconfined and load an appropriate "
                                   "AppArmor profile.",
                    cwe_id="CWE-693",
                ))

        result.raw_output += output.strip()[:500] + "\n"

    def _check_readonly_rootfs(self, result: ScanResult) -> None:
        result.raw_output += "\n--- Read-Only Root Filesystem ---\n"

        output = self._inspect_all("{{.Name}}|||{{.HostConfig.ReadonlyRootfs}}")
        if not output:
            result.raw_output += "No inspect output for readonly rootfs check.\n"
            return

        writable_containers = []
        for line in output.strip().splitlines():
            parts = line.split("|||", 1)
            if len(parts) < 2:
                continue
            name = parts[0].strip().lstrip("/")
            readonly = parts[1].strip().lower()
            if readonly == "false":
                writable_containers.append(name)

        if len(writable_containers) > 1:
            result.add_finding(Finding(
                title="Container Root Filesystem is Writable",
                severity=Severity.LOW,
                category=Category.CONTAINER,
                description=f"{len(writable_containers)} containers are running with a writable "
                            "root filesystem. A read-only rootfs prevents attackers from "
                            "persisting changes or dropping malicious binaries inside the "
                            "container filesystem.",
                evidence=f"Containers with writable rootfs: {', '.join(writable_containers[:10])}",
                recommendation="Add --read-only to container run arguments. Mount writable "
                               "volumes only for paths that genuinely need write access "
                               "(e.g., /tmp, /var/run).",
                cwe_id="CWE-276",
            ))

        result.raw_output += output.strip()[:500] + "\n"

    def _check_resource_limits(self, result: ScanResult) -> None:
        result.raw_output += "\n--- Resource Limits ---\n"

        output = self._inspect_all("{{.Name}}|||{{.HostConfig.Memory}}|||{{.HostConfig.NanoCpus}}")
        if not output:
            result.raw_output += "No inspect output for resource limits check.\n"
            return

        no_memory = []
        no_cpu = []

        for line in output.strip().splitlines():
            parts = line.split("|||")
            if len(parts) < 3:
                continue
            name = parts[0].strip().lstrip("/")
            memory = parts[1].strip()
            nanocpus = parts[2].strip()

            if memory == "0":
                no_memory.append(name)
            if nanocpus == "0":
                no_cpu.append(name)

        if no_memory:
            result.add_finding(Finding(
                title="No Memory Limit Set",
                severity=Severity.MEDIUM,
                category=Category.CONTAINER,
                description=f"{len(no_memory)} container(s) have no memory limit configured. "
                            "An unconstrained container can exhaust host memory, causing an "
                            "out-of-memory condition that affects all workloads on the host.",
                evidence=f"Containers without memory limits: {', '.join(no_memory[:10])}",
                recommendation="Set a memory limit with --memory (e.g., --memory=512m). "
                               "Also set --memory-swap to prevent swap exhaustion.",
                cwe_id="CWE-400",
            ))

        if no_cpu:
            result.add_finding(Finding(
                title="No CPU Limit Set",
                severity=Severity.LOW,
                category=Category.CONTAINER,
                description=f"{len(no_cpu)} container(s) have no CPU limit configured. "
                            "An unconstrained container can monopolise all host CPU cycles.",
                evidence=f"Containers without CPU limits: {', '.join(no_cpu[:10])}",
                recommendation="Set a CPU limit with --cpus or --cpu-period/--cpu-quota.",
                cwe_id="CWE-400",
            ))

        result.raw_output += output.strip()[:500] + "\n"

    def _check_running_as_root(self, result: ScanResult) -> None:
        result.raw_output += "\n--- Container User ---\n"

        output = self._inspect_all("{{.Name}}|||{{.Config.User}}")
        if not output:
            result.raw_output += "No inspect output for user check.\n"
            return

        for line in output.strip().splitlines():
            parts = line.split("|||", 1)
            if len(parts) < 2:
                continue
            name = parts[0].strip().lstrip("/")
            user = parts[1].strip()

            if user == "":
                result.add_finding(Finding(
                    title="Container Running as Root",
                    severity=Severity.HIGH,
                    category=Category.CONTAINER,
                    description=f"Container '{name}' does not specify a non-root user. "
                                "By default Docker containers run as root (UID 0). "
                                "If an application vulnerability is exploited, the attacker "
                                "will have root-level access within the container.",
                    evidence=f"Container: {name} — Config.User: (empty, defaults to root)",
                    recommendation="Add a USER directive in the Dockerfile or specify "
                                   "--user <uid>:<gid> at runtime. Create a dedicated "
                                   "non-root user in the image.",
                    cwe_id="CWE-250",
                    cvss_score=7.5,
                ))

        result.raw_output += output.strip()[:500] + "\n"

    def _check_dangerous_mounts(self, result: ScanResult) -> None:
        result.raw_output += "\n--- Container Mounts ---\n"

        output = self._inspect_all("{{.Name}}|||{{json .Mounts}}")
        if not output:
            result.raw_output += "No inspect output for mounts check.\n"
            return

        for line in output.strip().splitlines():
            parts = line.split("|||", 1)
            if len(parts) < 2:
                continue
            name = parts[0].strip().lstrip("/")
            mounts_raw = parts[1].strip()

            if mounts_raw in ("null", "[]", ""):
                continue

            try:
                mounts = json.loads(mounts_raw)
            except json.JSONDecodeError:
                continue

            for mount in mounts:
                source = mount.get("Source", "")
                if not source:
                    continue

                if source == "/var/run/docker.sock":
                    result.add_finding(Finding(
                        title="Docker Socket Mounted in Container",
                        severity=Severity.CRITICAL,
                        category=Category.CONTAINER,
                        description=f"Container '{name}' has the Docker socket "
                                    "(/var/run/docker.sock) mounted. This grants the container "
                                    "full control over the Docker daemon, enabling complete host "
                                    "escape by spawning a new privileged container.",
                        evidence=f"Container: {name} — Mount source: /var/run/docker.sock",
                        recommendation="Remove the Docker socket mount. If container management "
                                       "is required, use a dedicated API proxy (e.g., "
                                       "docker-socket-proxy) with strict access controls.",
                        cwe_id="CWE-269",
                        cvss_score=9.6,
                    ))
                elif source in ("/", "/etc"):
                    result.add_finding(Finding(
                        title="Host Root/etc Mounted in Container",
                        severity=Severity.CRITICAL,
                        category=Category.CONTAINER,
                        description=f"Container '{name}' has '{source}' mounted from the host. "
                                    "Mounting the root or /etc directory exposes the entire host "
                                    "filesystem or critical configuration files, enabling trivial "
                                    "privilege escalation and persistent backdoors.",
                        evidence=f"Container: {name} — Mount source: {source}",
                        recommendation="Never mount / or /etc from the host. Use named volumes "
                                       "for data that must be shared between host and container.",
                        cwe_id="CWE-552",
                        cvss_score=9.1,
                    ))
                elif source in DANGEROUS_MOUNTS:
                    result.add_finding(Finding(
                        title=f"Dangerous Host Path Mounted in Container: {source}",
                        severity=Severity.HIGH,
                        category=Category.CONTAINER,
                        description=f"Container '{name}' has the sensitive host path '{source}' "
                                    "mounted. This may expose kernel interfaces, system binaries, "
                                    "or device files to the container.",
                        evidence=f"Container: {name} — Mount source: {source}",
                        recommendation=f"Remove the bind mount for '{source}'. Use named Docker "
                                       "volumes or copy only required files into the image.",
                        cwe_id="CWE-552",
                    ))

        result.raw_output += output.strip()[:500] + "\n"

    def _check_docker_daemon_config(self, result: ScanResult) -> None:
        result.raw_output += "\n--- Docker Daemon Configuration ---\n"

        # daemon.json
        daemon_json, _, _ = self._run_ssh("cat /etc/docker/daemon.json 2>/dev/null")
        result.raw_output += f"daemon.json:\n{daemon_json or '(not found)'}\n"

        # dockerd process args
        ps_out, _, _ = self._run_ssh("ps aux 2>/dev/null | grep -E '[d]ockerd'")
        result.raw_output += f"dockerd process: {ps_out or '(not found)'}\n"

        # Unauthenticated Docker API on port 2375
        api_out, _, _ = self._run_ssh(
            "curl -sf --max-time 3 http://localhost:2375/version 2>/dev/null"
        )
        if api_out and api_out.strip():
            result.add_finding(Finding(
                title="Unauthenticated Docker API Exposed on Port 2375",
                severity=Severity.CRITICAL,
                category=Category.CONTAINER,
                description="The Docker daemon is listening on TCP port 2375 without TLS "
                            "authentication. Any user or process that can reach this port has "
                            "complete control over Docker: they can create privileged containers, "
                            "mount the host filesystem, and execute arbitrary commands as root.",
                evidence=f"http://localhost:2375/version responded: {api_out.strip()[:200]}",
                recommendation="Disable the TCP listener or enable mutual TLS authentication "
                               "(--tlsverify). Bind to 127.0.0.1 only if local access is needed. "
                               "Never expose port 2375 externally.",
                cwe_id="CWE-306",
                cvss_score=10.0,
            ))

        # userns-remap check
        userns_configured = False
        if daemon_json and "userns-remap" in daemon_json:
            userns_configured = True
        if ps_out and "--userns-remap" in ps_out:
            userns_configured = True

        if not userns_configured:
            result.add_finding(Finding(
                title="User Namespace Remapping Not Configured",
                severity=Severity.MEDIUM,
                category=Category.CONTAINER,
                description="Docker user namespace remapping (userns-remap) is not enabled. "
                            "Without remapping, root inside a container maps to root on the host, "
                            "meaning a container escape grants full host root access.",
                evidence="userns-remap not found in daemon.json or dockerd arguments",
                recommendation="Enable user namespace remapping in /etc/docker/daemon.json: "
                               '{"userns-remap": "default"}. This maps container root to an '
                               "unprivileged host UID.",
                cwe_id="CWE-250",
            ))

        # live-restore check
        if daemon_json and "live-restore" not in daemon_json:
            result.add_finding(Finding(
                title="Docker live-restore Not Enabled",
                severity=Severity.INFO,
                category=Category.CONTAINER,
                description="live-restore is not configured in daemon.json. "
                            "Without it, all containers stop when the Docker daemon is restarted, "
                            "causing unnecessary downtime during daemon upgrades.",
                evidence="live-restore not present in daemon.json",
                recommendation='Add {"live-restore": true} to /etc/docker/daemon.json.',
            ))

        # --host=tcp:// on all interfaces check
        if ps_out and re.search(r"--host=tcp://0\.0\.0\.0", ps_out):
            result.add_finding(Finding(
                title="Docker Daemon Listening on All Interfaces (TCP)",
                severity=Severity.CRITICAL,
                category=Category.CONTAINER,
                description="The Docker daemon is configured to listen on TCP 0.0.0.0, "
                            "making it reachable from any network interface. "
                            "Combined with missing TLS, this is a critical exposure.",
                evidence=f"dockerd args contain --host=tcp://0.0.0.0",
                recommendation="Bind the TCP listener to 127.0.0.1 only, or remove it entirely "
                               "and use the Unix socket. Enable mutual TLS if remote access is needed.",
                cwe_id="CWE-306",
                cvss_score=10.0,
            ))

    def _check_image_vulnerabilities(self, result: ScanResult) -> None:
        result.raw_output += "\n--- Image Vulnerability Scanning (Trivy) ---\n"

        trivy_path, _, rc = self._run_ssh("which trivy 2>/dev/null")
        if rc != 0 or not trivy_path or not trivy_path.strip():
            result.add_finding(Finding(
                title="Trivy Not Available - Image Vulnerability Scanning Skipped",
                severity=Severity.INFO,
                category=Category.CONTAINER,
                description="Trivy was not found on the target host. "
                            "Automated container image vulnerability scanning was skipped.",
                recommendation="Install Trivy and integrate it into the CI/CD pipeline to "
                               "scan images before deployment.",
            ))
            return

        # Get image names for running containers
        images_out, _, _ = self._run_ssh(
            "docker inspect $(docker ps -q) --format '{{.Config.Image}}' 2>/dev/null"
        )
        if not images_out or not images_out.strip():
            return

        seen_images = set()
        for image in images_out.strip().splitlines():
            image = image.strip()
            if not image or image in seen_images:
                continue
            seen_images.add(image)

            scan_out, _, rc = self._run_ssh(
                f"trivy image --format json --severity HIGH,CRITICAL --quiet {image} 2>/dev/null",
                timeout=120,
            )
            if not scan_out or not scan_out.strip():
                result.raw_output += f"Trivy: no output for {image}\n"
                continue

            try:
                report = json.loads(scan_out)
            except json.JSONDecodeError:
                result.raw_output += f"Trivy: could not parse JSON for {image}\n"
                continue

            critical_count = 0
            high_count = 0
            sample_cves: list = []

            for res in report.get("Results", []):
                for vuln in res.get("Vulnerabilities", []):
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

            result.raw_output += (
                f"Trivy {image}: CRITICAL={critical_count}, HIGH={high_count}\n"
            )

            if critical_count > 0:
                result.add_finding(Finding(
                    title=f"Image Has CRITICAL Vulnerabilities: {image}",
                    severity=Severity.CRITICAL,
                    category=Category.CONTAINER,
                    description=f"Trivy found {critical_count} CRITICAL and {high_count} HIGH "
                                f"CVEs in image '{image}'. Critical vulnerabilities may be "
                                "remotely exploitable and could lead to full system compromise.",
                    evidence=f"Image: {image} — CRITICAL: {critical_count}, HIGH: {high_count}. "
                             f"Sample CVEs: {', '.join(sample_cves[:5])}",
                    recommendation="Update the base image and all packages to patched versions. "
                                   "Rebuild and redeploy. Integrate Trivy into CI/CD to catch "
                                   "vulnerabilities before deployment.",
                ))
            elif high_count > 0:
                result.add_finding(Finding(
                    title=f"Image Has HIGH Vulnerabilities: {image}",
                    severity=Severity.HIGH,
                    category=Category.CONTAINER,
                    description=f"Trivy found {high_count} HIGH CVEs in image '{image}'. "
                                "High-severity vulnerabilities should be remediated promptly.",
                    evidence=f"Image: {image} — HIGH: {high_count}. "
                             f"Sample CVEs: {', '.join(sample_cves[:5])}",
                    recommendation="Update affected packages and rebuild the image.",
                ))

    def _check_container_network_exposure(self, result: ScanResult) -> None:
        result.raw_output += "\n--- Container Network Port Exposure ---\n"

        stdout, _, rc = self._run_ssh(
            "docker ps --format '{{.Names}}|||{{.Ports}}' 2>/dev/null"
        )
        if not stdout or not stdout.strip():
            result.raw_output += "No docker ps output for network exposure check.\n"
            return

        result.raw_output += stdout.strip()[:500] + "\n"

        # Pattern: 0.0.0.0:<host_port>-><container_port>/tcp
        port_pattern = re.compile(r"([\d.]+):(\d+)->(\d+)")

        for line in stdout.strip().splitlines():
            parts = line.split("|||", 1)
            if len(parts) < 2:
                continue
            name = parts[0].strip()
            ports_str = parts[1].strip()

            if not ports_str:
                continue

            for match in port_pattern.finditer(ports_str):
                bind_ip = match.group(1)
                host_port = int(match.group(2))
                container_port = int(match.group(3))

                if bind_ip != "0.0.0.0":
                    continue

                if container_port in DB_PORTS or host_port in DB_PORTS:
                    result.add_finding(Finding(
                        title="Database Container Port Exposed on All Interfaces",
                        severity=Severity.CRITICAL,
                        category=Category.CONTAINER,
                        description=f"Container '{name}' is publishing database port "
                                    f"{container_port} bound to 0.0.0.0, making it accessible "
                                    "from any network interface. Database services should never "
                                    "be exposed directly to public interfaces.",
                        evidence=f"Container: {name} — Ports: {ports_str}",
                        recommendation=f"Bind to 127.0.0.1: use -p 127.0.0.1:{host_port}:{container_port} "
                                       "or place the database on an internal Docker network accessible "
                                       "only to application containers.",
                        cwe_id="CWE-284",
                        cvss_score=9.8,
                    ))
                else:
                    result.add_finding(Finding(
                        title=f"Service Port Exposed on All Interfaces: {name}:{host_port}",
                        severity=Severity.MEDIUM,
                        category=Category.CONTAINER,
                        description=f"Container '{name}' is publishing port {host_port} bound to "
                                    "0.0.0.0. If this service does not need to be publicly "
                                    "accessible, binding to all interfaces unnecessarily expands "
                                    "the attack surface.",
                        evidence=f"Container: {name} — Ports: {ports_str}",
                        recommendation=f"Bind to a specific interface: "
                                       f"-p 127.0.0.1:{host_port}:{container_port} "
                                       "unless external access is intentional and firewall-controlled.",
                        cwe_id="CWE-284",
                    ))

    def _check_env_secrets(self, result: ScanResult) -> None:
        result.raw_output += "\n--- Secrets in Container Environment Variables ---\n"

        output = self._inspect_all("{{.Name}}|||{{json .Config.Env}}")
        if not output:
            result.raw_output += "No inspect output for env secrets check.\n"
            return

        secret_pattern = re.compile(
            r"(PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL|API_KEY|AUTH)",
            re.IGNORECASE,
        )

        for line in output.strip().splitlines():
            parts = line.split("|||", 1)
            if len(parts) < 2:
                continue
            name = parts[0].strip().lstrip("/")
            env_raw = parts[1].strip()

            if env_raw in ("null", "[]", ""):
                continue

            try:
                env_vars = json.loads(env_raw)
            except json.JSONDecodeError:
                continue

            found_secrets = []
            for var in env_vars:
                if "=" not in var:
                    continue
                key, _, value = var.partition("=")
                if secret_pattern.search(key):
                    masked = (value[:4] + "****") if len(value) > 4 else "****"
                    found_secrets.append(f"{key}={masked}")

            if found_secrets:
                result.add_finding(Finding(
                    title="Secret in Container Environment Variable",
                    severity=Severity.HIGH,
                    category=Category.CONTAINER,
                    description=f"Container '{name}' has environment variables that appear to "
                                "contain secrets or credentials. Environment variables are "
                                "visible to all processes in the container, appear in "
                                "docker inspect output, and may be logged by orchestration tools.",
                    evidence=f"Container: {name} — {'; '.join(found_secrets[:8])}",
                    recommendation="Use Docker secrets, a secrets manager (HashiCorp Vault, "
                                   "AWS Secrets Manager), or mounted secret files. "
                                   "Rotate any credentials that have been exposed as environment variables.",
                    cwe_id="CWE-312",
                    cvss_score=7.5,
                ))

        result.raw_output += "(env vars inspected — values masked in evidence)\n"
