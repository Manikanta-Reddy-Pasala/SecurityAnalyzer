"""Binary vulnerability scanner - ELF binary security analysis."""
import subprocess
from typing import Optional
from .models import Finding, ScanResult, Severity, Category


class BinaryScanner:
    """Analyzes ELF binaries for security hardening features."""

    def __init__(self, host: str, user: str, key_path: Optional[str] = None):
        self.host = host
        self.user = user
        self.key_path = key_path

    def scan(self) -> ScanResult:
        result = ScanResult(scanner_name="Binary Vulnerability Scanner")

        if not self._can_connect():
            result.success = False
            result.error = "Cannot connect to host via SSH"
            return result

        # System-wide security checks
        self._check_aslr(result)
        self._check_exec_shield(result)
        self._check_ptrace_scope(result)
        self._check_dmesg_restrict(result)
        self._check_kernel_hardening(result)

        # Find and analyze binaries
        binaries = self._discover_binaries(result)
        for binary in binaries[:15]:
            self._analyze_binary(binary, result)

        # Check for known vulnerable libraries
        self._check_vulnerable_libraries(result)

        # Check SUID/SGID binaries
        self._check_suid_binaries(result)

        # Additional security checks
        self._check_seccomp(result)
        self._check_apparmor(result)
        self._check_coredump_filter(result)
        self._check_mprotect(result)

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

    def _check_aslr(self, result: ScanResult):
        """Check Address Space Layout Randomization (ASLR)."""
        aslr = self._run_remote("cat /proc/sys/kernel/randomize_va_space 2>/dev/null")
        if aslr:
            val = aslr.strip()
            result.raw_output += f"ASLR level: {val}\n"
            if val == "0":
                result.add_finding(Finding(
                    title="ASLR Disabled",
                    severity=Severity.CRITICAL,
                    category=Category.BINARY_SECURITY,
                    description="Address Space Layout Randomization (ASLR) is disabled. "
                                "This makes buffer overflow and ROP attacks significantly easier.",
                    evidence=f"randomize_va_space = {val}",
                    recommendation="Enable ASLR: sysctl -w kernel.randomize_va_space=2",
                    cwe_id="CWE-119",
                    cvss_score=8.0,
                ))
            elif val == "1":
                result.add_finding(Finding(
                    title="ASLR Partially Enabled",
                    severity=Severity.MEDIUM,
                    category=Category.BINARY_SECURITY,
                    description="ASLR is set to level 1 (partial). Level 2 (full) "
                                "is recommended for maximum protection.",
                    evidence=f"randomize_va_space = {val}",
                    recommendation="Set full ASLR: sysctl -w kernel.randomize_va_space=2",
                    cwe_id="CWE-119",
                ))

    def _check_exec_shield(self, result: ScanResult):
        """Check NX/XD bit enforcement."""
        nx_check = self._run_remote(
            "grep -c ' nx ' /proc/cpuinfo 2>/dev/null || echo 0"
        )
        if nx_check and nx_check.strip() == "0":
            result.add_finding(Finding(
                title="NX (No-Execute) Bit Not Available",
                severity=Severity.HIGH,
                category=Category.BINARY_SECURITY,
                description="CPU does not support or has disabled NX bit. "
                            "This allows execution of code in data segments.",
                evidence="nx flag not found in /proc/cpuinfo",
                recommendation="Enable NX bit in BIOS/UEFI settings.",
                cwe_id="CWE-119",
            ))

    def _check_ptrace_scope(self, result: ScanResult):
        """Check ptrace scope for process debugging restrictions."""
        ptrace = self._run_remote("cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null")
        if ptrace:
            val = ptrace.strip()
            result.raw_output += f"ptrace_scope: {val}\n"
            if val == "0":
                result.add_finding(Finding(
                    title="Unrestricted ptrace (Process Debugging)",
                    severity=Severity.MEDIUM,
                    category=Category.BINARY_SECURITY,
                    description="Any process can ptrace any other process by the same user. "
                                "Attackers can extract secrets from running processes.",
                    evidence=f"ptrace_scope = {val}",
                    recommendation="Restrict ptrace: sysctl -w kernel.yama.ptrace_scope=1",
                    cwe_id="CWE-269",
                ))

    def _check_dmesg_restrict(self, result: ScanResult):
        """Check kernel message access restriction."""
        dmesg = self._run_remote("cat /proc/sys/kernel/dmesg_restrict 2>/dev/null")
        if dmesg and dmesg.strip() == "0":
            result.add_finding(Finding(
                title="Kernel Messages Accessible to All Users",
                severity=Severity.LOW,
                category=Category.BINARY_SECURITY,
                description="dmesg is not restricted. Kernel messages may leak "
                            "memory addresses useful for exploit development.",
                evidence="dmesg_restrict = 0",
                recommendation="Restrict dmesg: sysctl -w kernel.dmesg_restrict=1",
                cwe_id="CWE-200",
            ))

    def _check_kernel_hardening(self, result: ScanResult):
        """Check kernel hardening parameters."""
        checks = [
            ("kernel.kptr_restrict", "2", "Kernel Pointer Restriction",
             "Kernel pointers are not hidden, aiding exploit development.",
             Severity.MEDIUM, "CWE-200"),
            ("kernel.perf_event_paranoid", "3", "Performance Events Restriction",
             "perf events may leak kernel addresses.",
             Severity.LOW, None),
            ("net.ipv4.conf.all.rp_filter", "1", "Reverse Path Filtering",
             "Reverse path filtering is disabled, allowing IP spoofing.",
             Severity.MEDIUM, "CWE-290"),
            ("net.ipv4.conf.all.accept_redirects", "0", "ICMP Redirect Acceptance",
             "ICMP redirects are accepted, enabling MitM attacks.",
             Severity.MEDIUM, "CWE-300"),
            ("net.ipv4.conf.all.send_redirects", "0", "ICMP Redirect Sending",
             "ICMP redirect sending is enabled.",
             Severity.LOW, None),
        ]

        for param, expected, title, desc, severity, cwe in checks:
            val = self._run_remote(f"sysctl -n {param} 2>/dev/null")
            if val:
                val = val.strip()
                result.raw_output += f"{param} = {val}\n"
                if val != expected and param in ("kernel.kptr_restrict",):
                    if val == "0":
                        result.add_finding(Finding(
                            title=f"Weak {title}",
                            severity=severity,
                            category=Category.BINARY_SECURITY,
                            description=desc,
                            evidence=f"{param} = {val} (expected: {expected})",
                            recommendation=f"Set {param} = {expected}",
                            cwe_id=cwe,
                        ))

    def _discover_binaries(self, result: ScanResult) -> list[str]:
        """Find application binaries to analyze."""
        output = self._run_remote(
            "find /opt /srv /app /usr/local/bin -type f -executable "
            "\\( -name '*.so' -o -name '*.so.*' -o ! -name '*.*' \\) "
            "2>/dev/null | head -30"
        )
        binaries = []
        if output:
            binaries = [b.strip() for b in output.strip().split("\n") if b.strip()]
            result.raw_output += f"Found {len(binaries)} binaries to analyze\n"
        return binaries

    def _analyze_binary(self, binary: str, result: ScanResult):
        """Analyze a single ELF binary for security features."""
        # Check file type
        file_info = self._run_remote(f"file {binary} 2>/dev/null")
        if not file_info or "ELF" not in file_info:
            return

        result.raw_output += f"\n--- Analyzing: {binary} ---\n"

        # Check PIE (Position Independent Executable)
        pie_check = self._run_remote(f"readelf -h {binary} 2>/dev/null | grep Type")
        if pie_check:
            result.raw_output += f"  Type: {pie_check.strip()}\n"
            if "EXEC" in pie_check and "DYN" not in pie_check:
                result.add_finding(Finding(
                    title=f"Binary Not PIE: {binary}",
                    severity=Severity.HIGH,
                    category=Category.BINARY_SECURITY,
                    description=f"{binary} is not compiled as Position Independent "
                                "Executable (PIE). This weakens ASLR protection.",
                    evidence=pie_check.strip(),
                    recommendation=f"Recompile with -fPIE -pie flags.",
                    cwe_id="CWE-119",
                ))

        # Check Stack Canary
        canary_check = self._run_remote(
            f"readelf -s {binary} 2>/dev/null | grep -q '__stack_chk_fail' && echo 'YES' || echo 'NO'"
        )
        if canary_check and "NO" in canary_check:
            result.add_finding(Finding(
                title=f"No Stack Canary: {binary}",
                severity=Severity.HIGH,
                category=Category.BINARY_SECURITY,
                description=f"{binary} was compiled without stack canaries. "
                            "Stack buffer overflows can overwrite return addresses undetected.",
                evidence="__stack_chk_fail symbol not found",
                recommendation="Recompile with -fstack-protector-strong flag.",
                cwe_id="CWE-121",
            ))

        # Check FORTIFY_SOURCE
        fortify_check = self._run_remote(
            f"readelf -s {binary} 2>/dev/null | grep -c '__.*_chk' || echo 0"
        )
        if fortify_check and fortify_check.strip() == "0":
            result.add_finding(Finding(
                title=f"No FORTIFY_SOURCE: {binary}",
                severity=Severity.MEDIUM,
                category=Category.BINARY_SECURITY,
                description=f"{binary} was compiled without FORTIFY_SOURCE. "
                            "Buffer overflow protections for standard library functions "
                            "are not active.",
                evidence="No *_chk symbols found",
                recommendation="Recompile with -D_FORTIFY_SOURCE=2 -O2.",
                cwe_id="CWE-120",
            ))

        # Check RELRO (Relocation Read-Only)
        relro_check = self._run_remote(
            f"readelf -l {binary} 2>/dev/null | grep -i 'gnu_relro'"
        )
        full_relro = self._run_remote(
            f"readelf -d {binary} 2>/dev/null | grep -i 'bind_now'"
        )
        if not relro_check or "GNU_RELRO" not in (relro_check or ""):
            result.add_finding(Finding(
                title=f"No RELRO: {binary}",
                severity=Severity.HIGH,
                category=Category.BINARY_SECURITY,
                description=f"{binary} has no RELRO protection. GOT overwrite "
                            "attacks can redirect function calls.",
                evidence="No GNU_RELRO segment found",
                recommendation="Recompile with -Wl,-z,relro,-z,now for Full RELRO.",
                cwe_id="CWE-119",
            ))
        elif not full_relro or "BIND_NOW" not in (full_relro or ""):
            result.add_finding(Finding(
                title=f"Partial RELRO Only: {binary}",
                severity=Severity.MEDIUM,
                category=Category.BINARY_SECURITY,
                description=f"{binary} has only Partial RELRO. GOT entries are still "
                            "writable after program startup.",
                evidence="GNU_RELRO present but no BIND_NOW",
                recommendation="Recompile with -Wl,-z,relro,-z,now for Full RELRO.",
                cwe_id="CWE-119",
            ))

        # Check NX bit on binary
        nx_check = self._run_remote(
            f"readelf -l {binary} 2>/dev/null | grep 'GNU_STACK' | grep -c 'RWE'"
        )
        if nx_check and nx_check.strip() != "0":
            result.add_finding(Finding(
                title=f"Executable Stack: {binary}",
                severity=Severity.CRITICAL,
                category=Category.BINARY_SECURITY,
                description=f"{binary} has an executable stack (RWE). "
                            "This allows shellcode execution on the stack.",
                evidence="GNU_STACK has RWE flags",
                recommendation="Recompile with -z noexecstack. Do not use -z execstack.",
                cwe_id="CWE-119",
                cvss_score=8.0,
            ))

        # Check if stripped
        strip_check = self._run_remote(f"file {binary} 2>/dev/null")
        if strip_check and "not stripped" in strip_check:
            result.add_finding(Finding(
                title=f"Binary Not Stripped: {binary}",
                severity=Severity.LOW,
                category=Category.BINARY_SECURITY,
                description=f"{binary} contains debug symbols. This aids "
                            "reverse engineering and exploit development.",
                evidence="Binary is not stripped",
                recommendation=f"Strip the binary: strip {binary}",
                cwe_id="CWE-215",
            ))

        # Check RPATH/RUNPATH
        rpath = self._run_remote(f"readelf -d {binary} 2>/dev/null | grep -i 'rpath\\|runpath'")
        if rpath and rpath.strip():
            result.add_finding(Finding(
                title=f"RPATH/RUNPATH Set: {binary}",
                severity=Severity.MEDIUM,
                category=Category.BINARY_SECURITY,
                description=f"{binary} has RPATH/RUNPATH set. This can be exploited "
                            "for library injection attacks.",
                evidence=rpath.strip()[:200],
                recommendation="Remove RPATH: chrpath -d or recompile without -rpath.",
                cwe_id="CWE-426",
            ))

    def _check_vulnerable_libraries(self, result: ScanResult):
        """Check for known vulnerable shared libraries."""
        # Check OpenSSL version
        openssl = self._run_remote("openssl version 2>/dev/null")
        if openssl:
            result.raw_output += f"OpenSSL: {openssl.strip()}\n"
            version = openssl.strip().lower()
            if any(v in version for v in ["0.9.", "1.0.1", "1.0.0"]):
                result.add_finding(Finding(
                    title="Outdated OpenSSL Version",
                    severity=Severity.CRITICAL,
                    category=Category.BINARY_SECURITY,
                    description=f"OpenSSL version ({openssl.strip()}) is severely "
                                "outdated and has known vulnerabilities (Heartbleed, etc.).",
                    evidence=openssl.strip(),
                    recommendation="Update OpenSSL to latest version (3.x recommended).",
                    cwe_id="CWE-327",
                    cvss_score=9.1,
                ))

        # Check glibc version
        glibc = self._run_remote("ldd --version 2>/dev/null | head -1")
        if glibc:
            result.raw_output += f"glibc: {glibc.strip()}\n"

        # Check for libraries with known vulns
        libs_check = self._run_remote(
            "ldconfig -p 2>/dev/null | grep -iE 'libxml2|libcurl|libpng|libjpeg|zlib' | head -10"
        )
        if libs_check:
            result.raw_output += f"Key libraries:\n{libs_check}\n"

    def _check_suid_binaries(self, result: ScanResult):
        """Check for SUID/SGID binaries (privilege escalation vectors)."""
        suid = self._run_remote(
            "find / -perm -4000 -type f 2>/dev/null | "
            "grep -vE '^/(usr/(bin|sbin|lib)|bin|sbin)/' | head -20"
        )
        if suid and suid.strip():
            result.add_finding(Finding(
                title="Non-Standard SUID Binaries Found",
                severity=Severity.HIGH,
                category=Category.BINARY_SECURITY,
                description="SUID binaries found outside standard system directories. "
                            "These are potential privilege escalation vectors.",
                evidence=suid.strip()[:300],
                recommendation="Audit each SUID binary. Remove SUID bit if not needed: "
                               "chmod u-s <binary>",
                cwe_id="CWE-250",
            ))

        # Check SGID binaries
        sgid = self._run_remote(
            "find / -perm -2000 -type f 2>/dev/null | "
            "grep -vE '^/(usr/(bin|sbin|lib)|bin|sbin)/' | head -20"
        )
        if sgid and sgid.strip():
            result.add_finding(Finding(
                title="Non-Standard SGID Binaries Found",
                severity=Severity.MEDIUM,
                category=Category.BINARY_SECURITY,
                description="SGID binaries found outside standard system directories.",
                evidence=sgid.strip()[:300],
                recommendation="Audit each SGID binary. Remove SGID bit if not needed: "
                               "chmod g-s <binary>",
                cwe_id="CWE-250",
            ))

        # Check for world-writable SUID binaries
        writable_suid = self._run_remote(
            "find / -perm -4000 -perm -0002 -type f 2>/dev/null | head -10"
        )
        if writable_suid and writable_suid.strip():
            result.add_finding(Finding(
                title="World-Writable SUID Binaries",
                severity=Severity.CRITICAL,
                category=Category.BINARY_SECURITY,
                description="SUID binaries that are world-writable were found. "
                            "Any user can replace these with malicious code "
                            "that runs as root.",
                evidence=writable_suid.strip()[:300],
                recommendation="Fix permissions immediately: chmod o-w <binary>",
                cwe_id="CWE-732",
                cvss_score=9.8,
            ))

    def _check_seccomp(self, result: ScanResult):
        """Check if seccomp is available and used."""
        seccomp = self._run_remote("grep -c Seccomp /proc/1/status 2>/dev/null")
        if seccomp:
            result.raw_output += f"Seccomp support: {'yes' if seccomp.strip() != '0' else 'no'}\n"

        seccomp_mode = self._run_remote("grep Seccomp /proc/1/status 2>/dev/null")
        if seccomp_mode:
            result.raw_output += f"PID 1 seccomp: {seccomp_mode.strip()}\n"
            if "0" in seccomp_mode:
                result.add_finding(Finding(
                    title="Seccomp Not Enabled on PID 1",
                    severity=Severity.LOW,
                    category=Category.BINARY_SECURITY,
                    description="Seccomp (syscall filtering) is not enabled on the init process. "
                                "Seccomp restricts available syscalls to reduce attack surface.",
                    evidence=seccomp_mode.strip(),
                    recommendation="Use seccomp profiles for containerized workloads. "
                                   "Docker uses seccomp by default.",
                ))

    def _check_apparmor(self, result: ScanResult):
        """Check AppArmor status."""
        aa_status = self._run_remote("apparmor_status 2>/dev/null || aa-status 2>/dev/null")
        if aa_status:
            result.raw_output += f"AppArmor: {aa_status[:300]}\n"
            if "0 profiles" in aa_status:
                result.add_finding(Finding(
                    title="AppArmor Has No Profiles Loaded",
                    severity=Severity.MEDIUM,
                    category=Category.BINARY_SECURITY,
                    description="AppArmor is installed but has no profiles loaded.",
                    evidence="0 profiles in apparmor_status",
                    recommendation="Load AppArmor profiles for running services.",
                ))
        else:
            # Check if SELinux is also absent (no MAC at all)
            selinux = self._run_remote("getenforce 2>/dev/null")
            if not selinux or "disabled" in (selinux or "").lower():
                result.add_finding(Finding(
                    title="No Mandatory Access Control (MAC) Active",
                    severity=Severity.MEDIUM,
                    category=Category.BINARY_SECURITY,
                    description="Neither AppArmor nor SELinux is active. "
                                "No mandatory access control to limit process capabilities.",
                    evidence="AppArmor not found, SELinux disabled/absent",
                    recommendation="Enable SELinux or install AppArmor for mandatory access control.",
                    cwe_id="CWE-284",
                ))

    def _check_coredump_filter(self, result: ScanResult):
        """Check core dump filter for sensitive data leaks."""
        core_filter = self._run_remote("cat /proc/self/coredump_filter 2>/dev/null")
        if core_filter:
            try:
                val = int(core_filter.strip(), 16)
            except ValueError:
                val = 0
            result.raw_output += f"coredump_filter: {core_filter.strip()} (decimal: {val})\n"
            if val & 0x10:
                result.add_finding(Finding(
                    title="Core Dump Filter Includes ELF Headers",
                    severity=Severity.LOW,
                    category=Category.BINARY_SECURITY,
                    description="Core dump filter includes ELF headers, which can leak "
                                "memory layout information useful for exploits.",
                    evidence=f"coredump_filter = {core_filter.strip()}",
                    recommendation="Set coredump_filter to 0x00 or disable core dumps entirely.",
                    cwe_id="CWE-528",
                ))

    def _check_mprotect(self, result: ScanResult):
        """Check mmap/mprotect restrictions."""
        mmap_min = self._run_remote("cat /proc/sys/vm/mmap_min_addr 2>/dev/null")
        if mmap_min:
            try:
                val = int(mmap_min.strip())
            except ValueError:
                val = 0
            result.raw_output += f"mmap_min_addr: {val}\n"
            if val < 65536:
                result.add_finding(Finding(
                    title="Low mmap_min_addr (NULL Page Mapping Risk)",
                    severity=Severity.MEDIUM,
                    category=Category.BINARY_SECURITY,
                    description=f"mmap_min_addr is set to {val}. Low values allow mapping "
                                "near-NULL addresses, enabling NULL pointer dereference exploits.",
                    evidence=f"mmap_min_addr = {val}",
                    recommendation="Set vm.mmap_min_addr = 65536",
                    cwe_id="CWE-119",
                ))
