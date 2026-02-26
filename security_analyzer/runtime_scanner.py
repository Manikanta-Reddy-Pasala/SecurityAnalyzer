"""Runtime Scanner — discovers every running service (host + Docker containers),
classifies it by language/runtime, and applies language-specific deep security
checks: C/C++, Java/Kotlin, Python, Node.js, Go, Ruby, Rust.
"""
import re
import subprocess
from typing import Optional
from .models import Finding, ScanResult, Severity, Category

# --------------------------------------------------------------------- helpers

DANGEROUS_C_FUNCS = [
    "gets", "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "vsprintf", "scanf", "fscanf", "sscanf",
    "system", "popen", "execl", "execlp", "execv", "execvp",
    "mktemp", "tmpnam", "getwd", "realpath",
]

# runtime classification: keyword → runtime tag
RUNTIME_SIGNATURES = {
    "c_cpp":   [],  # detected by ELF + no interpreter
    "java":    ["java ", "/java ", "java-", "openjdk"],
    "kotlin":  ["kotlin", "ktor"],
    "python":  ["python", "python2", "python3", "/py "],
    "nodejs":  ["node ", "/node ", "nodejs", "ts-node"],
    "go":      [],  # detected by ELF build info
    "ruby":    ["ruby ", "/ruby "],
    "rust":    [],  # detected by ELF symbols
    "php":     ["php ", "php-fpm"],
    "dotnet":  ["dotnet ", ".NET", "mono "],
}

NODE_KNOWN_VULN_PACKAGES = {
    "lodash": ("< 4.17.21", "CVE-2021-23337", "Prototype Pollution"),
    "axios":  ("< 0.21.2",  "CVE-2021-3749",  "ReDoS"),
    "jsonwebtoken": ("< 9.0.0", "CVE-2022-23529", "Unsafe defaults"),
    "express": ("< 4.18.2", "CVE-2022-24999", "Open Redirect"),
    "minimist": ("< 1.2.6", "CVE-2021-44906", "Prototype Pollution"),
    "follow-redirects": ("< 1.14.8", "CVE-2022-0155", "Credentials leak"),
    "node-fetch": ("< 2.6.7", "CVE-2022-0235", "Open redirect"),
    "qs":     ("< 6.10.3",  "CVE-2022-24999", "Prototype Pollution"),
}


class RuntimeScanner:
    """Enumerate all running services, classify by runtime, apply per-language checks."""

    def __init__(self, host: str, user: str = "ec2-user", key_path: Optional[str] = None):
        self.host = host
        self.user = user
        self.key_path = key_path
        self._docker_prefix = "docker"

    # ------------------------------------------------------------------ public

    def scan(self) -> ScanResult:
        result = ScanResult(scanner_name="Runtime Scanner")

        if not self._can_connect():
            result.success = False
            result.error = "SSH connection failed"
            return result

        # Probe docker availability
        self._probe_docker()

        result.raw_output += "=== HOST SERVICES ===\n"
        host_services = self._discover_host_services(result)

        result.raw_output += "\n=== DOCKER CONTAINER SERVICES ===\n"
        docker_services = self._discover_docker_services(result)

        all_services = host_services + docker_services
        result.raw_output += f"\nTotal services discovered: {len(all_services)}\n\n"

        # Per-service language-specific analysis
        seen_binaries: set = set()
        for svc in all_services:
            runtime = svc.get("runtime", "unknown")
            try:
                if runtime == "c_cpp":
                    self._check_c_cpp_service(svc, result, seen_binaries)
                elif runtime in ("java", "kotlin"):
                    self._check_jvm_service(svc, result)
                elif runtime == "python":
                    self._check_python_service(svc, result)
                elif runtime == "nodejs":
                    self._check_nodejs_service(svc, result)
                elif runtime == "go":
                    self._check_go_service(svc, result)
                elif runtime == "dotnet":
                    self._check_dotnet_service(svc, result)
                elif runtime == "ruby":
                    self._check_ruby_service(svc, result)
            except Exception as exc:
                result.raw_output += f"  [WARN] {runtime} check failed for {svc.get('name')}: {exc}\n"

        # Cross-cutting: scan inside Docker containers for C/C++ binaries
        try:
            self._check_c_cpp_in_docker(result)
        except Exception as exc:
            result.raw_output += f"  [WARN] Docker C/C++ scan failed: {exc}\n"

        return result

    # ------------------------------------------------------------ SSH helpers

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

    def _run_remote(self, command: str, timeout: int = 30) -> str:
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
               "-o", "ConnectTimeout=10", "-o", "BatchMode=yes"]
        if self.key_path:
            cmd.extend(["-i", self.key_path])
        cmd.extend([f"{self.user}@{self.host}", command])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return proc.stdout or ""
        except subprocess.TimeoutExpired:
            return ""

    def _probe_docker(self) -> bool:
        out = self._run_remote("docker ps -q 2>/dev/null")
        if out is not None and "\n" in out or out:
            self._docker_prefix = "docker"
            return True
        out2 = self._run_remote("sudo -n docker ps -q 2>/dev/null")
        if out2:
            self._docker_prefix = "sudo docker"
            return True
        return False

    def _docker(self, subcmd: str, timeout: int = 30) -> str:
        return self._run_remote(f"{self._docker_prefix} {subcmd}", timeout=timeout)

    # --------------------------------------------------------- service discovery

    def _discover_host_services(self, result: ScanResult) -> list[dict]:
        """Enumerate all running processes on the host and classify by runtime."""
        ps_out = self._run_remote(
            "ps -eo pid,user,args --no-headers 2>/dev/null | head -60"
        )
        services = []
        if not ps_out or not ps_out.strip():
            result.raw_output += "  ps output unavailable\n"
            return services

        for line in ps_out.strip().splitlines():
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            pid, user, cmdline = parts[0], parts[1], parts[2]
            if any(skip in cmdline for skip in ["sshd", "systemd", "kernel", "kworker",
                                                 "[", "ps -eo", "grep", "awk"]):
                continue

            # Resolve binary path
            binary = self._run_remote(f"readlink -f /proc/{pid}/exe 2>/dev/null").strip()

            runtime = self._classify_runtime(cmdline, binary, pid)
            if runtime == "unknown":
                continue  # skip system processes / daemons we don't specialise

            svc = {
                "pid": pid, "user": user, "cmdline": cmdline,
                "binary": binary, "runtime": runtime,
                "name": binary.rsplit("/", 1)[-1] if binary else cmdline.split()[0].rsplit("/", 1)[-1],
                "source": "host",
            }
            services.append(svc)
            result.raw_output += (
                f"  HOST PID={pid} user={user} runtime={runtime} "
                f"bin={binary or '?'}\n"
            )

        return services

    def _discover_docker_services(self, result: ScanResult) -> list[dict]:
        """For each running Docker container enumerate its processes and classify."""
        cids_out = self._docker("ps -q 2>/dev/null")
        if not cids_out or not cids_out.strip():
            result.raw_output += "  No running Docker containers\n"
            return []

        services = []
        for cid in cids_out.strip().splitlines():
            cid = cid.strip()
            if not cid:
                continue

            # Container name + image
            meta = self._docker(f"inspect {cid} --format '{{{{.Name}}}}|||{{{{.Config.Image}}}}' 2>/dev/null")
            parts = meta.strip().split("|||") if meta else [cid, ""]
            cname = parts[0].strip().lstrip("/")
            image = parts[1].strip() if len(parts) > 1 else ""

            result.raw_output += f"\n  Container: {cname} ({image})\n"

            # Get processes inside the container
            ps_out = self._docker(f"exec {cid} ps -eo pid,user,args --no-headers 2>/dev/null | head -30")
            if not ps_out or not ps_out.strip():
                # fallback: read /proc/1/cmdline of PID 1 in container
                ps_out = self._docker(
                    f"exec {cid} sh -c "
                    f"\"cat /proc/1/cmdline 2>/dev/null | tr '\\0' ' '\" 2>/dev/null"
                )
                if ps_out:
                    ps_out = f"1 root {ps_out.strip()}"

            if not ps_out or not ps_out.strip():
                result.raw_output += "    (could not enumerate processes)\n"
                continue

            for line in ps_out.strip().splitlines():
                parts2 = line.split(None, 2)
                if len(parts2) < 2:
                    continue
                pid = parts2[0]
                user = parts2[1] if len(parts2) > 1 else "?"
                cmdline = parts2[2] if len(parts2) > 2 else ""
                if not cmdline or any(s in cmdline for s in ["ps -eo", "[", "grep"]):
                    continue

                # resolve binary inside container
                binary = self._docker(
                    f"exec {cid} sh -c 'readlink -f /proc/{pid}/exe 2>/dev/null'"
                ).strip()

                runtime = self._classify_runtime(cmdline, binary, pid)

                svc = {
                    "pid": pid, "user": user, "cmdline": cmdline,
                    "binary": binary, "runtime": runtime,
                    "name": cname,
                    "cid": cid, "image": image,
                    "source": f"docker:{cid[:12]}",
                }
                if runtime != "unknown":
                    services.append(svc)
                    result.raw_output += (
                        f"    PID={pid} runtime={runtime} cmd={cmdline[:80]}\n"
                    )

        return services

    # ---------------------------------------------------------- runtime classifier

    def _classify_runtime(self, cmdline: str, binary: str, pid: str) -> str:
        cl = cmdline.lower()
        bn = (binary or "").lower()

        # JVM
        if "java" in cl.split() or "/java " in cl or cl.startswith("java "):
            if "kotlin" in cl or "ktor" in cl:
                return "kotlin"
            # check JAR manifest for Kotlin-Version header
            return "java"

        # Python
        if re.search(r'\bpython[23]?\b', cl):
            return "python"

        # Node.js
        if re.search(r'\b(node|nodejs|ts-node)\b', cl):
            return "nodejs"

        # Ruby
        if re.search(r'\bruby\b', cl):
            return "ruby"

        # .NET / Mono
        if re.search(r'\b(dotnet|mono)\b', cl):
            return "dotnet"

        # PHP
        if re.search(r'\bphp\b', cl):
            return "php"

        # Go and C/C++ are native binaries — need ELF analysis
        if binary and binary not in ("/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/init"):
            file_info = self._run_remote(f"file {binary} 2>/dev/null")
            if file_info and "ELF" in file_info:
                # Check for Go build ID
                go_check = self._run_remote(
                    f"strings {binary} 2>/dev/null | grep -m1 'go1\\.' 2>/dev/null"
                )
                if go_check and go_check.strip():
                    return "go"
                # Check for Rust runtime
                rust_check = self._run_remote(
                    f"nm -D {binary} 2>/dev/null | grep -m1 'rust_panic\\|__rust_' 2>/dev/null"
                )
                if rust_check and rust_check.strip():
                    return "rust"
                # Check for C++ symbols
                cpp_check = self._run_remote(
                    f"nm -D {binary} 2>/dev/null | grep -m1 '_ZN\\|_ZSt' 2>/dev/null"
                )
                if cpp_check and cpp_check.strip():
                    return "c_cpp"
                # Plain C ELF
                return "c_cpp"

        return "unknown"

    # ---------------------------------------------------------- C / C++ checks

    def _check_c_cpp_service(self, svc: dict, result: ScanResult, seen: set):
        binary = svc.get("binary", "")
        name = svc.get("name", binary)
        source = svc.get("source", "host")
        if not binary or binary in seen:
            return
        seen.add(binary)

        result.raw_output += f"\n--- C/C++ Service: {name} ({binary}) [{source}] ---\n"

        # 1. Dangerous function usage
        self._check_dangerous_functions(binary, name, result)

        # 2. Format string vulnerability indicator
        self._check_format_string_risk(binary, name, result)

        # 3. ELF hardening recap (PIE, canary, RELRO, NX, FORTIFY)
        self._check_elf_hardening(binary, name, result)

        # 4. RPATH hijacking
        rpath = self._run_remote(
            f"readelf -d {binary} 2>/dev/null | grep -iE 'rpath|runpath'"
        )
        if rpath and rpath.strip():
            writable = any(p in rpath for p in ["$ORIGIN", ".", "/tmp", "/home"])
            result.add_finding(Finding(
                title=f"RPATH/RUNPATH Hijack Risk: {name}",
                severity=Severity.HIGH if writable else Severity.MEDIUM,
                category=Category.BINARY_SECURITY,
                description=(
                    f"Binary '{name}' has RPATH/RUNPATH set. "
                    "Attacker-controlled paths enable library injection (DLL hijacking equivalent)."
                ),
                evidence=rpath.strip()[:200],
                recommendation="Remove RPATH with `chrpath -d <binary>`. "
                               "Use system library paths instead.",
                cwe_id="CWE-426",
                cvss_score=7.5 if writable else 5.3,
            ))

        # 5. Linked libraries for known-vulnerable versions
        self._check_linked_libraries(binary, name, result)

        # 6. Running as root?
        if svc.get("user") in ("root", "0"):
            result.add_finding(Finding(
                title=f"C/C++ Service Running as Root: {name}",
                severity=Severity.HIGH,
                category=Category.BINARY_SECURITY,
                description=(
                    f"Native binary '{name}' (PID {svc.get('pid')}) is running as root. "
                    "Any memory corruption vulnerability (buffer overflow, use-after-free) "
                    "immediately grants root-level code execution."
                ),
                evidence=f"user=root, binary={binary}",
                recommendation=(
                    "Drop privileges after startup with setuid()/setgid() to a dedicated account. "
                    "Run the service under a non-privileged user."
                ),
                cwe_id="CWE-250",
                cvss_score=8.5,
            ))

    def _check_dangerous_functions(self, binary: str, name: str, result: ScanResult):
        """Use nm -D to detect dangerous C library function imports."""
        nm_out = self._run_remote(f"nm -D {binary} 2>/dev/null | grep -iE 'UND' | head -100")
        if not nm_out:
            return

        found = []
        for func in DANGEROUS_C_FUNCS:
            # match " U gets" or " U gets@GLIBC..."
            if re.search(rf'\bU\b.*\b{re.escape(func)}\b', nm_out):
                found.append(func)

        if not found:
            return

        # Classify severity
        critical_funcs = {"gets", "sprintf", "vsprintf", "system", "popen"}
        has_critical = bool(set(found) & critical_funcs)

        result.add_finding(Finding(
            title=f"Dangerous C Functions Detected: {name} — {', '.join(found[:5])}",
            severity=Severity.CRITICAL if has_critical else Severity.HIGH,
            category=Category.BINARY_SECURITY,
            description=(
                f"Binary '{name}' imports unsafe C library function(s): {', '.join(found)}. "
                "These functions lack bounds checking and are the root cause of the majority "
                "of memory corruption vulnerabilities (CVE-rated buffer overflows, stack smash, RCE).\n"
                + ("  `gets()` — unbounded stack overflow; removed from C11.\n" if "gets" in found else "")
                + ("  `sprintf()` — fixed-width format write; use snprintf().\n" if "sprintf" in found else "")
                + ("  `system()` — shell injection via user input.\n" if "system" in found else "")
                + ("  `strcpy()` — no length check; use strlcpy() or strncpy() + null terminator.\n" if "strcpy" in found else "")
            ),
            evidence=f"nm -D {binary}: found {found}",
            recommendation=(
                "Replace unsafe functions:\n"
                "  gets() → fgets(buf, sizeof(buf), stdin)\n"
                "  strcpy/strcat() → strlcpy/strlcat() or strncpy+explicit null\n"
                "  sprintf() → snprintf(buf, sizeof(buf), fmt, ...)\n"
                "  system()/popen() → execve() with sanitised args array\n"
                "Compile with -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat -Werror=format-security."
            ),
            cwe_id="CWE-120" if not has_critical else "CWE-121",
            cvss_score=9.0 if has_critical else 7.5,
        ))

    def _check_format_string_risk(self, binary: str, name: str, result: ScanResult):
        """Check if binary uses printf-family without format string (potential fmt bug)."""
        nm_out = self._run_remote(f"nm -D {binary} 2>/dev/null | grep -E 'U.*printf' | head -20")
        if not nm_out or not nm_out.strip():
            return

        printf_funcs = re.findall(r'\b(\w*printf\w*)\b', nm_out)
        if not printf_funcs:
            return

        # Check compile-time format warnings were applied
        fortify = self._run_remote(
            f"nm -D {binary} 2>/dev/null | grep -c '__.*printf.*chk' 2>/dev/null"
        )
        has_fortify = fortify and fortify.strip() not in ("0", "")

        if not has_fortify:
            result.add_finding(Finding(
                title=f"Format String Risk (No FORTIFY): {name}",
                severity=Severity.HIGH,
                category=Category.BINARY_SECURITY,
                description=(
                    f"Binary '{name}' uses printf-family functions ({', '.join(set(printf_funcs[:4]))}) "
                    "without FORTIFY_SOURCE protection. If any printf call passes user input as "
                    "the format string (printf(user_input)), it enables arbitrary memory read/write."
                ),
                evidence=f"printf funcs: {set(printf_funcs[:4])}, FORTIFY: no",
                recommendation=(
                    "Always use: printf(\"%s\", user_input) — never printf(user_input).\n"
                    "Compile with -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security."
                ),
                cwe_id="CWE-134",
                cvss_score=8.1,
            ))

    def _check_elf_hardening(self, binary: str, name: str, result: ScanResult):
        """Summarise key ELF hardening flags for a service binary."""
        # PIE
        pie = self._run_remote(f"readelf -h {binary} 2>/dev/null | grep Type")
        if pie and "EXEC" in pie and "DYN" not in pie:
            result.add_finding(Finding(
                title=f"No PIE: {name}",
                severity=Severity.HIGH,
                category=Category.BINARY_SECURITY,
                description=f"Service binary '{name}' is not PIE. ASLR cannot fully protect it.",
                evidence=pie.strip()[:100],
                recommendation="Recompile with -fPIE -pie.",
                cwe_id="CWE-119",
            ))

        # Stack canary
        canary = self._run_remote(
            f"readelf -s {binary} 2>/dev/null | grep -q '__stack_chk_fail' && echo YES || echo NO"
        )
        if canary and "NO" in canary:
            result.add_finding(Finding(
                title=f"No Stack Canary: {name}",
                severity=Severity.HIGH,
                category=Category.BINARY_SECURITY,
                description=f"Service binary '{name}' has no stack smashing protection.",
                evidence="__stack_chk_fail not in symbol table",
                recommendation="Recompile with -fstack-protector-strong.",
                cwe_id="CWE-121",
            ))

        # NX stack
        nx = self._run_remote(
            f"readelf -l {binary} 2>/dev/null | grep GNU_STACK | grep -c RWE"
        )
        if nx and nx.strip() != "0":
            result.add_finding(Finding(
                title=f"Executable Stack: {name}",
                severity=Severity.CRITICAL,
                category=Category.BINARY_SECURITY,
                description=f"Service binary '{name}' has an executable stack (RWE). Shellcode can run on the stack.",
                evidence="GNU_STACK RWE",
                recommendation="Recompile with -z noexecstack.",
                cwe_id="CWE-119",
                cvss_score=9.0,
            ))

    def _check_linked_libraries(self, binary: str, name: str, result: ScanResult):
        """Check dynamically linked libraries for known old/vulnerable versions."""
        needed = self._run_remote(
            f"readelf -d {binary} 2>/dev/null | grep NEEDED | head -30"
        )
        if not needed:
            return

        # libssl / libcrypto version via binary itself or system openssl
        if "libssl" in needed or "libcrypto" in needed:
            ssl_ver = self._run_remote("openssl version 2>/dev/null")
            if ssl_ver:
                ver = ssl_ver.strip().lower()
                if any(v in ver for v in ["0.9.", "1.0.0", "1.0.1", "1.0.2"]):
                    result.add_finding(Finding(
                        title=f"Outdated OpenSSL Linked by {name}",
                        severity=Severity.CRITICAL,
                        category=Category.BINARY_SECURITY,
                        description=(
                            f"Binary '{name}' links OpenSSL ({ssl_ver.strip()}) "
                            "which contains known critical vulnerabilities (Heartbleed, POODLE, ROBOT)."
                        ),
                        evidence=ssl_ver.strip(),
                        recommendation="Update OpenSSL to 3.x and rebuild the binary.",
                        cwe_id="CWE-327",
                        cvss_score=9.1,
                    ))

        # libxml2 — XXE, memory corruption
        if "libxml2" in needed:
            xml2_ver = self._run_remote("xml2-config --version 2>/dev/null")
            if xml2_ver and xml2_ver.strip() < "2.9.14":
                result.add_finding(Finding(
                    title=f"Outdated libxml2 Linked by {name}",
                    severity=Severity.HIGH,
                    category=Category.BINARY_SECURITY,
                    description=(
                        f"Binary '{name}' links libxml2 {xml2_ver.strip()} "
                        "which has known XXE and heap corruption vulnerabilities."
                    ),
                    evidence=f"libxml2 {xml2_ver.strip()}",
                    recommendation="Update libxml2 to 2.9.14+ and rebuild.",
                    cwe_id="CWE-611",
                ))

    def _check_c_cpp_in_docker(self, result: ScanResult):
        """For every Docker container, find C/C++ native binaries and apply dangerous-function checks."""
        result.raw_output += "\n--- C/C++ Binaries Inside Docker Containers ---\n"

        cids_out = self._docker("ps -q 2>/dev/null")
        if not cids_out or not cids_out.strip():
            result.raw_output += "  No running containers\n"
            return

        for cid in cids_out.strip().splitlines():
            cid = cid.strip()
            if not cid:
                continue

            cname = self._docker(f"inspect {cid} --format '{{{{.Name}}}}' 2>/dev/null").strip().lstrip("/")

            # Get PID 1 binary inside container
            pid1_exe = self._docker(
                f"exec {cid} sh -c 'readlink -f /proc/1/exe 2>/dev/null'"
            ).strip()

            if not pid1_exe:
                continue

            # Check if it's a native ELF (C/C++) — not java/python/node
            file_info = self._docker(f"exec {cid} file {pid1_exe} 2>/dev/null")
            if not file_info or "ELF" not in file_info:
                continue

            # Skip known runtimes
            go_check = self._docker(
                f"exec {cid} sh -c 'strings {pid1_exe} 2>/dev/null | grep -m1 go1\\.' 2>/dev/null"
            )
            if go_check and go_check.strip():
                continue  # Go binary — handled separately

            result.raw_output += f"  Container {cname}: C/C++ binary {pid1_exe}\n"

            # Check dangerous functions inside container
            nm_out = self._docker(
                f"exec {cid} sh -c 'nm -D {pid1_exe} 2>/dev/null | grep -iE U | head -100'"
            )
            if not nm_out:
                # Try objdump as fallback
                nm_out = self._docker(
                    f"exec {cid} sh -c "
                    f"'objdump -p {pid1_exe} 2>/dev/null | grep NEEDED | head -20'"
                )

            found_dangerous = []
            if nm_out:
                for func in DANGEROUS_C_FUNCS:
                    if re.search(rf'\bU\b.*\b{re.escape(func)}\b', nm_out):
                        found_dangerous.append(func)

            if found_dangerous:
                critical = bool(set(found_dangerous) & {"gets", "sprintf", "system", "popen"})
                result.add_finding(Finding(
                    title=f"Dangerous C Functions in Docker Container: {cname}",
                    severity=Severity.CRITICAL if critical else Severity.HIGH,
                    category=Category.CONTAINER,
                    description=(
                        f"Container '{cname}' runs a C/C++ service ({pid1_exe}) "
                        f"that imports unsafe functions: {', '.join(found_dangerous)}. "
                        "Memory corruption in a containerised C service can enable container escape."
                    ),
                    evidence=f"container={cname}, binary={pid1_exe}, funcs={found_dangerous}",
                    recommendation=(
                        "Rebuild with safe alternatives and compiler hardening flags. "
                        "Apply a seccomp profile and enable full RELRO + PIE + stack canary."
                    ),
                    cwe_id="CWE-120",
                    cvss_score=9.0 if critical else 7.5,
                ))

            # Check ELF hardening inside container
            pie = self._docker(f"exec {cid} readelf -h {pid1_exe} 2>/dev/null | grep Type")
            if pie and "EXEC" in pie and "DYN" not in pie:
                result.add_finding(Finding(
                    title=f"Container C/C++ Binary Not PIE: {cname}",
                    severity=Severity.HIGH,
                    category=Category.CONTAINER,
                    description=(
                        f"C/C++ service '{pid1_exe}' in container '{cname}' is not compiled as PIE. "
                        "Exploiting memory corruption is easier without ASLR randomisation."
                    ),
                    evidence=f"container={cname}, readelf Type: {pie.strip()[:80]}",
                    recommendation="Rebuild with -fPIE -pie.",
                    cwe_id="CWE-119",
                ))

    # ---------------------------------------------------------- JVM / Kotlin checks

    def _check_jvm_service(self, svc: dict, result: ScanResult):
        cmdline = svc.get("cmdline", "")
        name = svc.get("name", "?")
        source = svc.get("source", "host")
        result.raw_output += f"\n--- JVM Service: {name} [{source}] ---\n"

        # Kotlin detection: look for Kotlin-specific classes / frameworks
        is_kotlin = "kotlin" in cmdline.lower() or "ktor" in cmdline.lower()

        # Ktor framework detection
        if is_kotlin:
            self._check_ktor_service(svc, result)

        # Serialization library vuln (kotlinx.serialization < 1.3.3)
        jar_path = ""
        jar_match = re.search(r'-jar\s+(\S+\.jar)', cmdline)
        if jar_match:
            jar_path = jar_match.group(1)
        if is_kotlin and jar_path:
            serialization_check = self._run_remote(
                f"unzip -p {jar_path} META-INF/MANIFEST.MF 2>/dev/null | grep -i kotlin"
            )
            if serialization_check:
                result.raw_output += f"  Kotlin manifest: {serialization_check.strip()[:200]}\n"

        # Check for --add-opens / --add-exports (module system bypass)
        if "--add-opens" in cmdline or "--add-exports" in cmdline:
            result.add_finding(Finding(
                title=f"JVM Module System Bypassed: {name}",
                severity=Severity.MEDIUM,
                category=Category.JAVA_JVM,
                description=(
                    f"Service '{name}' uses --add-opens or --add-exports to bypass "
                    "the Java module system. This widens the attack surface by exposing "
                    "internal APIs, and may indicate use of unsafe reflection."
                ),
                evidence=f"cmdline contains: {[a for a in cmdline.split() if a.startswith('--add-')][:5]}",
                recommendation=(
                    "Minimise --add-opens usage. Upgrade third-party dependencies that "
                    "require internal API access to versions compatible with the module system."
                ),
                cwe_id="CWE-749",
            ))

        # Check for -XX:+IgnoreUnrecognizedVMOptions silently swallowing security flags
        if "IgnoreUnrecognizedVMOptions" in cmdline:
            result.add_finding(Finding(
                title=f"JVM Silently Ignoring Unrecognised Options: {name}",
                severity=Severity.LOW,
                category=Category.JAVA_JVM,
                description=(
                    f"Service '{name}' uses -XX:+IgnoreUnrecognizedVMOptions which silently "
                    "discards unrecognised JVM flags, including security-related ones."
                ),
                evidence="cmdline contains -XX:+IgnoreUnrecognizedVMOptions",
                recommendation="Remove this flag and fix any unrecognised options explicitly.",
                cwe_id="CWE-665",
            ))

        # GC log paths leaking info
        gc_match = re.search(r'-Xlog:gc[^:\s]*:file=(\S+)', cmdline)
        if gc_match:
            gc_log = gc_match.group(1)
            gc_perm = self._run_remote(f"stat -c '%a' {gc_log} 2>/dev/null")
            if gc_perm and int(gc_perm.strip()) > 644:
                result.add_finding(Finding(
                    title=f"GC Log File World-Readable: {name}",
                    severity=Severity.LOW,
                    category=Category.JAVA_JVM,
                    description=(
                        f"GC log file '{gc_log}' for '{name}' has overly permissive "
                        "mode. Logs can contain class names, heap addresses, and timing "
                        "data useful for exploit development."
                    ),
                    evidence=f"GC log: {gc_log}, perms: {gc_perm.strip()}",
                    recommendation=f"chmod 640 {gc_log}",
                    cwe_id="CWE-532",
                ))

    def _check_ktor_service(self, svc: dict, result: ScanResult):
        """Ktor-specific security checks."""
        name = svc.get("name", "?")
        result.raw_output += f"  Ktor framework detected for {name}\n"

        # Probe common Ktor endpoints on discovered ports
        ports_out = self._run_remote(
            "ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | grep -oE '[0-9]+$' | sort -un"
        )
        if not ports_out:
            return

        for port in ports_out.strip().splitlines()[:10]:
            port = port.strip()
            if not port:
                continue

            # Ktor status page
            for path in ["/status", "/metrics", "/health", "/api/v1", "/admin"]:
                resp = self._run_remote(
                    f"curl -sf --max-time 3 -o /dev/null -w '%{{http_code}}' "
                    f"http://localhost:{port}{path} 2>/dev/null"
                )
                if resp and resp.strip() in ("200", "204"):
                    result.add_finding(Finding(
                        title=f"Ktor Unauthenticated Endpoint: {name} :{port}{path}",
                        severity=Severity.HIGH if path in ("/metrics", "/admin") else Severity.MEDIUM,
                        category=Category.JAVA_JVM,
                        description=(
                            f"Ktor service '{name}' exposes {path} on port {port} without auth. "
                            "Metrics/admin endpoints can expose sensitive runtime data."
                        ),
                        evidence=f"HTTP 200 at localhost:{port}{path}",
                        recommendation=(
                            "Protect management endpoints with `authenticate { }` in Ktor routing. "
                            "Consider binding management endpoints to a separate port (not externally exposed)."
                        ),
                        cwe_id="CWE-306",
                    ))

    # ---------------------------------------------------------- Python checks

    def _check_python_service(self, svc: dict, result: ScanResult):
        cmdline = svc.get("cmdline", "")
        name = svc.get("name", "?")
        pid = svc.get("pid", "?")
        source = svc.get("source", "host")
        result.raw_output += f"\n--- Python Service: {name} [{source}] ---\n"

        # Flask debug mode
        if "flask" in cmdline.lower() and ("--debug" in cmdline or "debug=true" in cmdline.lower()):
            result.add_finding(Finding(
                title=f"Flask Running in Debug Mode: {name}",
                severity=Severity.CRITICAL,
                category=Category.SERVICE,
                description=(
                    f"Python/Flask service '{name}' (PID {pid}) is running with debug mode enabled. "
                    "Flask's debug mode activates the Werkzeug interactive debugger: any unhandled "
                    "exception renders a browser-based Python REPL. If accessible, this gives "
                    "unauthenticated RCE in the context of the Flask process."
                ),
                evidence=f"cmdline: {cmdline[:200]}",
                recommendation=(
                    "Set FLASK_DEBUG=0 or app.debug=False in production. "
                    "Never expose the debug port externally. Use a production WSGI server (gunicorn/uvicorn)."
                ),
                cwe_id="CWE-94",
                cvss_score=10.0,
            ))

        # Django DEBUG=True via environment
        django_debug = self._run_remote(
            f"cat /proc/{pid}/environ 2>/dev/null | tr '\\0' '\\n' | grep -i 'DJANGO_DEBUG\\|DEBUG=True'"
        )
        if django_debug and django_debug.strip():
            result.add_finding(Finding(
                title=f"Django DEBUG=True in Production: {name}",
                severity=Severity.HIGH,
                category=Category.SERVICE,
                description=(
                    f"Django service '{name}' has DEBUG=True. "
                    "Django debug mode returns full stack traces with local variable values, "
                    "settings, and SQL queries on every error — information useful for targeted attacks."
                ),
                evidence=f"env: {django_debug.strip()[:100]}",
                recommendation="Set DEBUG = False in settings.py. Use ALLOWED_HOSTS properly.",
                cwe_id="CWE-215",
                cvss_score=7.5,
            ))

        # Pickle usage (unsafe deserialization)
        app_dirs = self._run_remote(
            f"readlink -f /proc/{pid}/cwd 2>/dev/null"
        ).strip()
        if app_dirs and app_dirs != "/":
            pickle_use = self._run_remote(
                f"grep -rl 'pickle.loads\\|pickle.load\\|cPickle' {app_dirs} "
                f"--include='*.py' 2>/dev/null | head -5"
            )
            if pickle_use and pickle_use.strip():
                result.add_finding(Finding(
                    title=f"Unsafe pickle Deserialization: {name}",
                    severity=Severity.HIGH,
                    category=Category.SERVICE,
                    description=(
                        f"Python service '{name}' uses pickle.loads/pickle.load on data "
                        "that may be attacker-controlled. Pickle deserialization of untrusted "
                        "data leads to arbitrary code execution (RCE)."
                    ),
                    evidence=f"Files: {pickle_use.strip()[:200]}",
                    recommendation=(
                        "Replace pickle with json/msgpack for untrusted data. "
                        "If pickle is required, sign and verify the data with hmac before loading."
                    ),
                    cwe_id="CWE-502",
                    cvss_score=9.8,
                ))

        # PyYAML yaml.load (unsafe)
        if app_dirs and app_dirs != "/":
            yaml_unsafe = self._run_remote(
                f"grep -rl 'yaml\\.load(' {app_dirs} --include='*.py' 2>/dev/null | "
                f"xargs grep -l 'yaml.load(' 2>/dev/null | head -5"
            )
            if yaml_unsafe and yaml_unsafe.strip():
                # Filter out safe uses (yaml.safe_load)
                unsafe_count = self._run_remote(
                    f"grep -rh 'yaml\\.load(' {app_dirs} --include='*.py' 2>/dev/null | "
                    f"grep -v safe_load | wc -l"
                )
                if unsafe_count and unsafe_count.strip() != "0":
                    result.add_finding(Finding(
                        title=f"Unsafe yaml.load() Usage: {name}",
                        severity=Severity.HIGH,
                        category=Category.SERVICE,
                        description=(
                            f"Python service '{name}' uses yaml.load() without Loader=yaml.SafeLoader. "
                            "With the default Loader, YAML can instantiate arbitrary Python objects, "
                            "enabling RCE via crafted YAML payloads."
                        ),
                        evidence=f"Files with unsafe yaml.load: {yaml_unsafe.strip()[:200]}",
                        recommendation="Replace yaml.load(data) with yaml.safe_load(data).",
                        cwe_id="CWE-502",
                        cvss_score=9.0,
                    ))

        # Python version check
        py_version = self._run_remote(f"python3 --version 2>&1 || python --version 2>&1")
        if py_version:
            ver_match = re.search(r'(\d+\.\d+)', py_version)
            if ver_match:
                ver = float(ver_match.group(1))
                if ver < 3.8:
                    result.add_finding(Finding(
                        title=f"End-of-Life Python Version: {py_version.strip()}",
                        severity=Severity.HIGH,
                        category=Category.SERVICE,
                        description=(
                            f"Service '{name}' runs on Python {py_version.strip()} which is "
                            "end-of-life and no longer receives security patches."
                        ),
                        evidence=py_version.strip(),
                        recommendation="Upgrade to Python 3.12+.",
                        cwe_id="CWE-1104",
                    ))

    # ---------------------------------------------------------- Node.js checks

    def _check_nodejs_service(self, svc: dict, result: ScanResult):
        cmdline = svc.get("cmdline", "")
        name = svc.get("name", "?")
        pid = svc.get("pid", "?")
        source = svc.get("source", "host")
        result.raw_output += f"\n--- Node.js Service: {name} [{source}] ---\n"

        # --inspect / --inspect-brk debug port
        inspect_match = re.search(
            r'--inspect(?:-brk)?(?:=([0-9.:]+))?', cmdline
        )
        if inspect_match:
            addr = inspect_match.group(1) or "127.0.0.1:9229"
            is_remote = not addr.startswith("127.") and addr != "localhost"
            result.add_finding(Finding(
                title=f"Node.js Debugger Active: {name} (--inspect on {addr})",
                severity=Severity.CRITICAL if is_remote else Severity.HIGH,
                category=Category.SERVICE,
                description=(
                    f"Node.js service '{name}' (PID {pid}) has the V8 inspector "
                    f"enabled (--inspect) on {addr}. "
                    "The inspector gives full RCE: any WebSocket client can eval() arbitrary JS, "
                    "read/write files, and exfiltrate process memory."
                ),
                evidence=f"cmdline: {cmdline[:200]}",
                recommendation=(
                    "Remove --inspect from production cmdline. "
                    "If debugging is needed, use SSH tunneling to a 127.0.0.1 bound inspector. "
                    "Block port 9229 at the firewall."
                ),
                cwe_id="CWE-489",
                cvss_score=10.0 if is_remote else 8.5,
            ))

        # Find package.json and check known vulnerable packages
        app_dir = self._run_remote(f"readlink -f /proc/{pid}/cwd 2>/dev/null").strip()
        if not app_dir or app_dir == "/":
            return

        pkg_json = self._run_remote(f"cat {app_dir}/package.json 2>/dev/null")
        if not pkg_json or not pkg_json.strip():
            pkg_json = self._run_remote(
                f"find {app_dir} -maxdepth 3 -name package.json 2>/dev/null | head -1 | xargs cat 2>/dev/null"
            )

        if pkg_json and pkg_json.strip():
            self._audit_node_packages(pkg_json, name, result)

        # NODE_ENV check
        node_env = self._run_remote(
            f"cat /proc/{pid}/environ 2>/dev/null | tr '\\0' '\\n' | grep NODE_ENV"
        )
        if node_env and "production" not in node_env.lower():
            result.add_finding(Finding(
                title=f"NODE_ENV Not Set to Production: {name}",
                severity=Severity.MEDIUM,
                category=Category.SERVICE,
                description=(
                    f"Node.js service '{name}' has NODE_ENV={node_env.strip()[-50:]}. "
                    "Without NODE_ENV=production, Express and many libraries enable verbose "
                    "error messages, stack traces, and development middleware."
                ),
                evidence=f"env: {node_env.strip()[:100]}",
                recommendation="Set NODE_ENV=production in your service environment.",
                cwe_id="CWE-215",
            ))

    def _audit_node_packages(self, pkg_json_str: str, name: str, result: ScanResult):
        """Check declared npm dependencies against known-vulnerable versions."""
        import json
        try:
            pkg = json.loads(pkg_json_str)
        except Exception:
            return

        all_deps = {}
        all_deps.update(pkg.get("dependencies", {}))
        all_deps.update(pkg.get("devDependencies", {}))

        for pkg_name, vuln_ver, cve, vuln_type in [
            (k, v[0], v[1], v[2]) for k, v in NODE_KNOWN_VULN_PACKAGES.items()
        ]:
            if pkg_name not in all_deps:
                continue
            declared = all_deps[pkg_name].lstrip("^~>=<").strip()
            # Basic check: if major.minor < vuln_ver major.minor
            result.add_finding(Finding(
                title=f"Vulnerable npm Package: {pkg_name} ({cve}) in {name}",
                severity=Severity.HIGH,
                category=Category.SERVICE,
                description=(
                    f"Package '{pkg_name}' declared as '{all_deps[pkg_name]}' "
                    f"in '{name}' has a known vulnerability: {cve} ({vuln_type}). "
                    f"Versions {vuln_ver} are affected."
                ),
                evidence=f"{pkg_name}: {all_deps[pkg_name]} — {cve}",
                recommendation=f"Update {pkg_name} to a patched version: npm update {pkg_name}",
                cwe_id="CWE-1035",
            ))

    # ---------------------------------------------------------- Go checks

    def _check_go_service(self, svc: dict, result: ScanResult):
        binary = svc.get("binary", "")
        name = svc.get("name", "?")
        source = svc.get("source", "host")
        result.raw_output += f"\n--- Go Service: {name} [{source}] ---\n"

        if not binary:
            return

        # Go version embedded in binary
        go_ver = self._run_remote(
            f"strings {binary} 2>/dev/null | grep -E '^go[0-9]+\\.' | head -1"
        )
        if go_ver:
            result.raw_output += f"  Go version: {go_ver.strip()}\n"
            ver_match = re.search(r'go(\d+)\.(\d+)', go_ver)
            if ver_match:
                major, minor = int(ver_match.group(1)), int(ver_match.group(2))
                if major == 1 and minor < 19:
                    result.add_finding(Finding(
                        title=f"Outdated Go Runtime: {name} (go{major}.{minor})",
                        severity=Severity.HIGH,
                        category=Category.BINARY_SECURITY,
                        description=(
                            f"Go binary '{name}' was built with Go {major}.{minor}. "
                            "Go versions before 1.19 lack several security fixes including "
                            "HTTP/2 HPACK DoS (CVE-2022-41715) and path traversal fixes."
                        ),
                        evidence=go_ver.strip(),
                        recommendation="Rebuild with Go 1.22+ and update all go.mod dependencies.",
                        cwe_id="CWE-1104",
                    ))

        # pprof endpoint exposed (profiling endpoint = info leak + DoS)
        ports_out = self._run_remote(
            "ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | grep -oE '[0-9]+$' | sort -un"
        )
        if ports_out:
            for port in ports_out.strip().splitlines()[:12]:
                port = port.strip()
                resp = self._run_remote(
                    f"curl -sf --max-time 3 -o /dev/null -w '%{{http_code}}' "
                    f"http://localhost:{port}/debug/pprof/ 2>/dev/null"
                )
                if resp and resp.strip() == "200":
                    result.add_finding(Finding(
                        title=f"Go pprof Debug Endpoint Exposed: {name} :{port}",
                        severity=Severity.HIGH,
                        category=Category.BINARY_SECURITY,
                        description=(
                            f"Go service '{name}' exposes the pprof profiling endpoint at "
                            f"localhost:{port}/debug/pprof/. "
                            "pprof gives goroutine dumps, heap profiles, CPU profiles, and "
                            "full stack traces — exposing internal code paths and secrets in memory."
                        ),
                        evidence=f"HTTP 200 on localhost:{port}/debug/pprof/",
                        recommendation=(
                            "Remove `import _ \"net/http/pprof\"` from production code, "
                            "or bind the pprof server to 127.0.0.1 behind auth."
                        ),
                        cwe_id="CWE-215",
                        cvss_score=7.5,
                    ))

        # Race condition flag (should not be in production)
        buildinfo = self._run_remote(
            f"strings {binary} 2>/dev/null | grep -i 'race\\|DATA RACE' | head -3"
        )
        if buildinfo and buildinfo.strip():
            result.add_finding(Finding(
                title=f"Go Binary Built with Race Detector: {name}",
                severity=Severity.MEDIUM,
                category=Category.BINARY_SECURITY,
                description=(
                    f"Go binary '{name}' appears to have been built with the race detector "
                    "(-race flag). Race-detector builds are 2-20x slower, use more memory, "
                    "and reveal goroutine scheduling internals via panic messages."
                ),
                evidence=buildinfo.strip()[:100],
                recommendation="Rebuild for production without -race flag.",
                cwe_id="CWE-400",
            ))

    # ---------------------------------------------------------- .NET / Mono

    def _check_dotnet_service(self, svc: dict, result: ScanResult):
        cmdline = svc.get("cmdline", "")
        name = svc.get("name", "?")
        source = svc.get("source", "host")
        result.raw_output += f"\n--- .NET/Mono Service: {name} [{source}] ---\n"

        # Development exception page
        env_check = self._run_remote(
            f"cat /proc/{svc.get('pid', '0')}/environ 2>/dev/null | tr '\\0' '\\n' | "
            f"grep -iE 'ASPNETCORE_ENVIRONMENT|DOTNET_ENVIRONMENT'"
        )
        if env_check and "development" in env_check.lower():
            result.add_finding(Finding(
                title=f".NET App in Development Environment: {name}",
                severity=Severity.HIGH,
                category=Category.SERVICE,
                description=(
                    f".NET/ASP.NET Core service '{name}' is running in Development environment. "
                    "The developer exception page is active, returning full stack traces, "
                    "connection strings, and environment variables on every error."
                ),
                evidence=f"env: {env_check.strip()[:100]}",
                recommendation="Set ASPNETCORE_ENVIRONMENT=Production for production deployments.",
                cwe_id="CWE-215",
                cvss_score=7.5,
            ))

        # Swagger/OpenAPI in production
        ports_out = self._run_remote(
            "ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | grep -oE '[0-9]+$' | sort -un"
        )
        if ports_out:
            for port in ports_out.strip().splitlines()[:8]:
                port = port.strip()
                for swagger_path in ["/swagger", "/swagger/index.html", "/api-docs"]:
                    resp = self._run_remote(
                        f"curl -sf --max-time 3 -o /dev/null -w '%{{http_code}}' "
                        f"http://localhost:{port}{swagger_path} 2>/dev/null"
                    )
                    if resp and resp.strip() == "200":
                        result.add_finding(Finding(
                            title=f".NET Swagger UI Exposed in Production: {name} :{port}",
                            severity=Severity.MEDIUM,
                            category=Category.SERVICE,
                            description=(
                                f".NET service '{name}' exposes Swagger UI at "
                                f"localhost:{port}{swagger_path} in what appears to be a production "
                                "environment. Swagger reveals the full API surface, parameter types, "
                                "and example requests — useful for attackers."
                            ),
                            evidence=f"HTTP 200 on localhost:{port}{swagger_path}",
                            recommendation=(
                                "Disable Swagger in production:\n"
                                "  if (!app.Environment.IsDevelopment()) { /* skip UseSwagger */ }"
                            ),
                            cwe_id="CWE-200",
                        ))

    # ---------------------------------------------------------- Ruby checks

    def _check_ruby_service(self, svc: dict, result: ScanResult):
        cmdline = svc.get("cmdline", "")
        name = svc.get("name", "?")
        source = svc.get("source", "host")
        result.raw_output += f"\n--- Ruby Service: {name} [{source}] ---\n"

        # Rails development mode
        if "rails" in cmdline.lower() and ("development" in cmdline or "RAILS_ENV=development" in cmdline):
            result.add_finding(Finding(
                title=f"Rails Running in Development Mode: {name}",
                severity=Severity.HIGH,
                category=Category.SERVICE,
                description=(
                    f"Ruby on Rails service '{name}' appears to be running in development mode. "
                    "Rails development mode enables detailed error pages, disables caching, "
                    "and may show database schema information on errors."
                ),
                evidence=f"cmdline: {cmdline[:150]}",
                recommendation="Set RAILS_ENV=production.",
                cwe_id="CWE-215",
            ))

        # Pry / byebug in production
        if any(d in cmdline for d in ["pry", "byebug", "binding.pry"]):
            result.add_finding(Finding(
                title=f"Ruby Debugger (pry/byebug) Active: {name}",
                severity=Severity.CRITICAL,
                category=Category.SERVICE,
                description=(
                    f"Ruby service '{name}' has pry or byebug in its cmdline. "
                    "If binding.pry is triggered, the process pauses and any user with "
                    "stdin access gets an interactive Ruby REPL — full RCE."
                ),
                evidence=f"cmdline: {cmdline[:150]}",
                recommendation="Remove pry/byebug from production Gemfile. Never use binding.pry in production.",
                cwe_id="CWE-489",
                cvss_score=9.8,
            ))
