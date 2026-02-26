"""Java/JVM security scanner - detects JDWP debug ports, JMX exposure, Log4Shell, Spring Boot actuators."""
import re
import subprocess
from typing import Optional
from .models import Finding, ScanResult, Severity, Category


class JavaScanner:
    """Audits JVM processes, Docker Java containers, and Java-specific attack surfaces."""

    def __init__(self, host: str, user: str, key_path: Optional[str] = None):
        self.host = host
        self.user = user
        self.key_path = key_path

    def scan(self) -> ScanResult:
        result = ScanResult(scanner_name="Java/JVM Scanner")
        can_ssh = self._can_connect()
        result.raw_output += f"SSH access: {'yes' if can_ssh else 'no'}\n\n"

        if can_ssh:
            java_procs = self._check_jvm_processes(result)
            self._check_jdwp_exposure(result, java_procs)
            self._check_jmx_exposure(result, java_procs)
            self._check_java_version(result)
            self._check_log4j(result)
            self._check_docker_java(result)
            self._check_jolokia(result)
            self._check_spring_default_password(result)

        # Spring Boot actuator probes (network-level, no SSH needed)
        self._check_spring_actuators(result)

        return result

    # ------------------------------------------------------------------ helpers

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

    def _tcp_probe(self, port: int, timeout: int = 3) -> bool:
        """Check if a TCP port is open on the target host (network-level)."""
        import socket
        try:
            with socket.create_connection((self.host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _http_probe(self, port: int, path: str = "/", timeout: int = 4) -> Optional[str]:
        """Perform an HTTP GET and return status code + first 500 chars of body."""
        try:
            import urllib.request
            import urllib.error
            req = urllib.request.Request(f"http://{self.host}:{port}{path}")
            req.add_header("User-Agent", "SecurityAnalyzer/2.0")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(500).decode(errors="replace")
                return f"{r.status}:{body}"
        except urllib.error.HTTPError as e:
            return f"{e.code}:"
        except Exception:
            return None

    # ----------------------------------------------------- JVM process detection

    def _check_jvm_processes(self, result: ScanResult) -> list[dict]:
        """Enumerate all running Java processes and parse their JVM arguments."""
        result.raw_output += "--- JVM Processes ---\n"

        ps_out = self._run_remote(
            "ps -eo pid,user,args 2>/dev/null | grep -E '[j]ava ' | head -20"
        )
        if not ps_out or not ps_out.strip():
            result.raw_output += "No Java processes detected\n"
            return []

        result.raw_output += ps_out + "\n"
        procs = []

        for line in ps_out.strip().splitlines():
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            pid, proc_user, cmdline = parts[0], parts[1], parts[2]
            procs.append({"pid": pid, "user": proc_user, "cmdline": cmdline})

            # Report what's running
            # Find main class or jar name
            jar_match = re.search(r'(-jar\s+\S+\.jar|-cp\s+\S+)', cmdline)
            main_class = jar_match.group(0) if jar_match else "(inline class)"
            result.raw_output += f"  PID {pid} [{proc_user}]: {main_class}\n"

        return procs

    # ---------------------------------------- JDWP (Java Debug Wire Protocol)

    def _check_jdwp_exposure(self, result: ScanResult, java_procs: list[dict]):
        """
        Detect Java Debug Wire Protocol (JDWP) — allows arbitrary code execution
        on the JVM if the port is reachable.
        """
        result.raw_output += "\n--- JDWP Debug Port Check ---\n"

        jdwp_ports = []
        for proc in java_procs:
            cmdline = proc["cmdline"]

            # Match: -agentlib:jdwp=transport=dt_socket,...,address=*:5005
            #        -Xrunjdwp:transport=dt_socket,...,address=5005
            jdwp_match = re.search(
                r'(?:-agentlib:jdwp|-Xrunjdwp)[^\\s]*'
                r'address=(?:\*:|\[::\]:)?(\d+)',
                cmdline,
            )
            if jdwp_match:
                port = int(jdwp_match.group(1))
                suspend_match = re.search(r'suspend=([yn])', cmdline)
                server_match = re.search(r'server=([yn])', cmdline)
                jdwp_ports.append({
                    "port": port,
                    "pid": proc["pid"],
                    "user": proc["user"],
                    "suspend": suspend_match.group(1) if suspend_match else "?",
                    "server": server_match.group(1) if server_match else "?",
                    "cmdline_snippet": cmdline[:300],
                })
                result.raw_output += (
                    f"  JDWP found: PID={proc['pid']}, port={port}, "
                    f"server={server_match.group(1) if server_match else '?'}\n"
                )

        # Also check common JDWP ports directly
        common_debug_ports = [5005, 5006, 8000, 8787, 4000, 9009]
        for port in common_debug_ports:
            if self._tcp_probe(port):
                if not any(e["port"] == port for e in jdwp_ports):
                    jdwp_ports.append({"port": port, "pid": "?", "user": "?",
                                       "cmdline_snippet": f"tcp/{port} open"})
                    result.raw_output += f"  JDWP candidate: port {port} is open\n"

        for entry in jdwp_ports:
            port = entry["port"]
            reachable = self._tcp_probe(port)
            severity = Severity.CRITICAL if reachable else Severity.HIGH

            result.add_finding(Finding(
                title=f"Java JDWP Debug Port Exposed: {port}"
                      + (" (REACHABLE)" if reachable else " (localhost only)"),
                severity=severity,
                category=Category.JAVA_JVM,
                description=(
                    f"Java Debug Wire Protocol (JDWP) is listening on port {port} "
                    f"(PID {entry.get('pid','?')}, user {entry.get('user','?')}). "
                    "JDWP allows an attacker to attach a debugger, read/write heap memory, "
                    "and execute arbitrary code inside the JVM — equivalent to full RCE."
                ),
                evidence=entry.get("cmdline_snippet", f"port {port} open")[:300],
                recommendation=(
                    "Remove -agentlib:jdwp or -Xdebug/-Xrunjdwp from production JVM args. "
                    "If debugging is needed, bind to 127.0.0.1 and use SSH tunneling. "
                    "Block debug ports (5005, 8000, 8787) at the firewall."
                ),
                cwe_id="CWE-489",
                cvss_score=9.8 if reachable else 7.5,
            ))

        if not jdwp_ports:
            result.raw_output += "  No JDWP debug ports detected\n"

    # ---------------------------------------------------- JMX remote exposure

    def _check_jmx_exposure(self, result: ScanResult, java_procs: list[dict]):
        """Detect JMX remote management exposure — allows MBean invocation and code execution."""
        result.raw_output += "\n--- JMX Remote Exposure Check ---\n"

        jmx_entries = []
        for proc in java_procs:
            cmdline = proc["cmdline"]

            if "jmxremote" not in cmdline.lower():
                continue

            # Extract JMX port
            port_match = re.search(
                r'-Dcom\.sun\.management\.jmxremote\.port=(\d+)', cmdline
            )
            rmi_port_match = re.search(
                r'-Dcom\.sun\.management\.jmxremote\.rmi\.port=(\d+)', cmdline
            )
            auth_disabled = "jmxremote.authenticate=false" in cmdline
            ssl_disabled = "jmxremote.ssl=false" in cmdline
            auth_enabled = "jmxremote.authenticate=true" in cmdline

            port = int(port_match.group(1)) if port_match else None
            rmi_port = int(rmi_port_match.group(1)) if rmi_port_match else port

            if port or auth_disabled:
                jmx_entries.append({
                    "port": port,
                    "rmi_port": rmi_port,
                    "pid": proc["pid"],
                    "user": proc["user"],
                    "auth_disabled": auth_disabled,
                    "ssl_disabled": ssl_disabled,
                    "auth_enabled": auth_enabled,
                    "cmdline": cmdline[:300],
                })
                result.raw_output += (
                    f"  JMX: PID={proc['pid']}, port={port}, "
                    f"auth={'disabled' if auth_disabled else 'enabled' if auth_enabled else 'default'}, "
                    f"ssl={'disabled' if ssl_disabled else 'default'}\n"
                )

        # Also check common JMX ports
        common_jmx_ports = [9999, 1099, 9010, 7199, 10099]
        for port in common_jmx_ports:
            if self._tcp_probe(port) and not any(e["port"] == port for e in jmx_entries):
                jmx_entries.append({
                    "port": port, "pid": "?", "user": "?",
                    "auth_disabled": False, "ssl_disabled": False, "auth_enabled": False,
                    "cmdline": f"port {port} open",
                })
                result.raw_output += f"  JMX candidate: port {port} is open\n"

        for entry in jmx_entries:
            port = entry["port"]
            reachable = self._tcp_probe(port) if port else False

            if entry["auth_disabled"]:
                result.add_finding(Finding(
                    title=f"JMX Remote: Authentication Disabled (PID {entry['pid']})",
                    severity=Severity.CRITICAL,
                    category=Category.JAVA_JVM,
                    description=(
                        f"JMX remote management is running without authentication "
                        f"(-Dcom.sun.management.jmxremote.authenticate=false) on port {port}. "
                        "Any client can connect to JMX and invoke MBeans, "
                        "including MLet which allows loading remote classes for full RCE."
                    ),
                    evidence=entry["cmdline"][:300],
                    recommendation=(
                        "Remove jmxremote.authenticate=false. Enable authentication with a "
                        "jmxremote.password file. Better yet, use JVM local attach only "
                        "and remove jmxremote.port entirely."
                    ),
                    cwe_id="CWE-306",
                    cvss_score=9.8,
                ))

            if entry["ssl_disabled"] and entry["auth_disabled"]:
                result.add_finding(Finding(
                    title=f"JMX Remote: No Auth AND No SSL (PID {entry['pid']})",
                    severity=Severity.CRITICAL,
                    category=Category.JAVA_JVM,
                    description=(
                        "JMX is running with both authentication and SSL disabled. "
                        "All JMX traffic is in plaintext and any host can connect."
                    ),
                    evidence=f"port={port}, jmxremote.authenticate=false, jmxremote.ssl=false",
                    recommendation=(
                        "Enable both auth and SSL, or remove remote JMX entirely "
                        "and use jconsole/jvisualvm via SSH tunnel."
                    ),
                    cwe_id="CWE-306",
                    cvss_score=9.8,
                ))
            elif port and reachable:
                result.add_finding(Finding(
                    title=f"JMX Remote Port Reachable: {port}",
                    severity=Severity.HIGH,
                    category=Category.JAVA_JVM,
                    description=(
                        f"JMX remote management port {port} is network-reachable. "
                        "Even with authentication, JMX exposes a large attack surface "
                        "including heap inspection and class loading."
                    ),
                    evidence=f"TCP port {port} accepting connections",
                    recommendation=(
                        "Block JMX ports at the firewall. Use SSH tunneling "
                        "for remote JMX access instead of direct port exposure."
                    ),
                    cwe_id="CWE-284",
                ))

        if not jmx_entries:
            result.raw_output += "  No JMX remote configuration detected\n"

    # ----------------------------------------------------- Java version check

    def _check_java_version(self, result: ScanResult):
        result.raw_output += "\n--- Java Version Check ---\n"

        java_ver = self._run_remote("java -version 2>&1 | head -3")
        if not java_ver:
            # Try finding java via alternatives or common paths
            java_ver = self._run_remote(
                "ls /usr/lib/jvm/*/bin/java 2>/dev/null | head -1 | "
                "xargs -I{} {} -version 2>&1 | head -3"
            )

        if not java_ver or not java_ver.strip():
            result.raw_output += "  java binary not found in PATH\n"
            return

        result.raw_output += f"Java version:\n{java_ver}\n"

        # Extract major version (handles "1.8.x" and "11.x.x" / "17.x.x" formats)
        ver_match = re.search(r'version "(?:1\.)?(\d+)', java_ver)
        if not ver_match:
            return

        major = int(ver_match.group(1))

        if major < 8:
            result.add_finding(Finding(
                title=f"Severely Outdated Java Version: {major}",
                severity=Severity.CRITICAL,
                category=Category.JAVA_JVM,
                description=(
                    f"Java major version {major} is end-of-life and has numerous unpatched "
                    "CVEs including deserialization gadgets, sandbox escapes, and JVM exploits."
                ),
                evidence=java_ver.strip()[:200],
                recommendation="Upgrade to Java 21 LTS (latest LTS) immediately.",
                cwe_id="CWE-1104",
                cvss_score=8.0,
            ))
        elif major == 8:
            result.add_finding(Finding(
                title="Java 8 In Use (End-of-Free-Updates)",
                severity=Severity.MEDIUM,
                category=Category.JAVA_JVM,
                description=(
                    "Java 8 is in extended commercial support. Public free updates ended in 2019. "
                    "Many deserialization vulnerabilities and CVEs exist in older Java 8 builds."
                ),
                evidence=java_ver.strip()[:200],
                recommendation="Migrate to Java 21 LTS. At minimum, use the latest Java 8 "
                               "build from a supported vendor (Amazon Corretto, Eclipse Temurin).",
                cwe_id="CWE-1104",
            ))
        elif major < 17:
            result.add_finding(Finding(
                title=f"Java {major} — Non-LTS or Older LTS Version",
                severity=Severity.LOW,
                category=Category.JAVA_JVM,
                description=(
                    f"Java {major} is not a current LTS release. "
                    "Java 17 and 21 are the current LTS versions with active security patches."
                ),
                evidence=java_ver.strip()[:200],
                recommendation="Upgrade to Java 21 LTS for long-term security support.",
                cwe_id="CWE-1104",
            ))
        else:
            result.raw_output += f"  Java {major} — current LTS, OK\n"

    # ------------------------------------------------------ Log4Shell (Log4j)

    def _check_log4j(self, result: ScanResult):
        """Detect Log4j versions vulnerable to CVE-2021-44228 (Log4Shell) and siblings."""
        result.raw_output += "\n--- Log4j / Log4Shell Check ---\n"

        # Find log4j-core JARs on the filesystem
        jar_find = self._run_remote(
            "find /opt /srv /app /home /var/lib /usr/share "
            "-name 'log4j-core-*.jar' -o -name 'log4j-*.jar' "
            "2>/dev/null | grep -v '.bak' | head -20"
        )
        # Also search open file descriptors of running processes
        fd_find = self._run_remote(
            "find /proc/*/fd -xtype f -name 'log4j*.jar' 2>/dev/null | head -10"
        )

        all_jars = set()
        for output in [jar_find, fd_find]:
            if output and output.strip():
                for jar in output.strip().splitlines():
                    jar = jar.strip()
                    if jar:
                        all_jars.add(jar)

        if not all_jars:
            result.raw_output += "  No log4j JARs found on filesystem\n"
            return

        result.raw_output += "Log4j JARs found:\n"
        for jar in sorted(all_jars):
            result.raw_output += f"  {jar}\n"

        for jar in sorted(all_jars):
            # Extract version from filename: log4j-core-2.14.1.jar
            ver_match = re.search(r'log4j(?:-core)?-(\d+\.\d+(?:\.\d+)?)', jar)
            if not ver_match:
                result.add_finding(Finding(
                    title="Log4j JAR Found (Version Unknown)",
                    severity=Severity.HIGH,
                    category=Category.JAVA_JVM,
                    description=(
                        f"A log4j JAR was found at {jar} but its version could not be "
                        "determined from the filename. Manually verify it is not "
                        "vulnerable to Log4Shell (CVE-2021-44228)."
                    ),
                    evidence=jar,
                    recommendation="Upgrade to log4j-core 2.17.1+ (Java 8) or 2.12.4+ (Java 7).",
                    cwe_id="CWE-917",
                ))
                continue

            ver_str = ver_match.group(1)
            parts = ver_str.split(".")
            try:
                major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2]) if len(parts) > 2 else 0
            except (ValueError, IndexError):
                continue

            if major == 2:
                if minor < 15:
                    # CVE-2021-44228 — original Log4Shell (JNDI injection)
                    result.add_finding(Finding(
                        title=f"Log4Shell CRITICAL: log4j-core {ver_str} (CVE-2021-44228)",
                        severity=Severity.CRITICAL,
                        category=Category.JAVA_JVM,
                        description=(
                            f"log4j-core {ver_str} found at {jar}. "
                            "This version is vulnerable to CVE-2021-44228 (Log4Shell) — "
                            "a remote code execution vulnerability via JNDI lookup injection "
                            "in log messages. CVSS 10.0."
                        ),
                        evidence=f"JAR: {jar}, version: {ver_str}",
                        recommendation=(
                            "Upgrade to log4j-core 2.17.1+ immediately. "
                            "Interim mitigation: set -Dlog4j2.formatMsgNoLookups=true "
                            "or remove JndiLookup class from JAR."
                        ),
                        cwe_id="CWE-917",
                        cvss_score=10.0,
                    ))
                elif minor == 15 and patch == 0:
                    # CVE-2021-45046 — bypass of 2.15.0 fix
                    result.add_finding(Finding(
                        title=f"Log4j 2.15.0 Bypass Vulnerability (CVE-2021-45046)",
                        severity=Severity.CRITICAL,
                        category=Category.JAVA_JVM,
                        description=(
                            f"log4j {ver_str} at {jar} is vulnerable to CVE-2021-45046, "
                            "a bypass of the 2.15.0 Log4Shell fix allowing RCE in certain configs."
                        ),
                        evidence=f"JAR: {jar}, version: {ver_str}",
                        recommendation="Upgrade to log4j-core 2.17.1+.",
                        cwe_id="CWE-917",
                        cvss_score=9.0,
                    ))
                elif minor < 17 or (minor == 17 and patch == 0):
                    # CVE-2021-45105 (DoS) or CVE-2021-44832 (RCE with config control)
                    result.add_finding(Finding(
                        title=f"Log4j {ver_str} — Partial Remediation (CVE-2021-45105)",
                        severity=Severity.HIGH,
                        category=Category.JAVA_JVM,
                        description=(
                            f"log4j {ver_str} at {jar} may be vulnerable to "
                            "CVE-2021-45105 (infinite recursion DoS) or CVE-2021-44832 "
                            "(RCE when attacker controls log4j config). "
                            "2.17.1+ is the fully patched version."
                        ),
                        evidence=f"JAR: {jar}, version: {ver_str}",
                        recommendation="Upgrade to log4j-core 2.17.1+.",
                        cwe_id="CWE-917",
                        cvss_score=7.5,
                    ))
                else:
                    result.raw_output += f"  log4j {ver_str} — patched (2.17.1+)\n"

            elif major == 1:
                result.add_finding(Finding(
                    title=f"Log4j 1.x End-of-Life Found: {ver_str}",
                    severity=Severity.HIGH,
                    category=Category.JAVA_JVM,
                    description=(
                        f"log4j 1.x ({ver_str}) at {jar} is end-of-life since 2015 "
                        "and has multiple known CVEs including deserialization RCE "
                        "(CVE-2019-17571, CVE-2022-23302/23303/23305)."
                    ),
                    evidence=f"JAR: {jar}, version: {ver_str}",
                    recommendation="Migrate to log4j 2.17.1+ or SLF4J/Logback.",
                    cwe_id="CWE-502",
                    cvss_score=8.1,
                ))

    # ---------------------------------------- Spring Boot Actuator endpoints

    def _check_spring_actuators(self, result: ScanResult):
        """
        Probe Spring Boot Actuator endpoints on common HTTP ports.
        Unauthenticated /actuator/env or /heapdump = credential exfiltration.
        """
        result.raw_output += "\n--- Spring Boot Actuator Probe ---\n"

        ports_to_check = [8080, 8081, 8090, 8443, 9090, 3000, 5000, 4000, 8888]
        sensitive_paths = {
            "/actuator/env":       ("Environment Variables & Config Exposed",    Severity.CRITICAL, "CWE-215", 9.1),
            "/actuator/heapdump":  ("Heap Dump Download (All In-Memory Secrets)", Severity.CRITICAL, "CWE-312", 9.1),
            "/actuator/logfile":   ("Log File Exposed",                           Severity.HIGH,     "CWE-532", 7.5),
            "/actuator/threaddump":("Thread Dump Exposed (Internal Code Paths)",  Severity.MEDIUM,   "CWE-200", 5.3),
            "/actuator/mappings":  ("All URL Mappings Disclosed",                 Severity.MEDIUM,   "CWE-200", 5.3),
            "/actuator/beans":     ("All Spring Beans Disclosed",                 Severity.LOW,      "CWE-200", 4.0),
            "/actuator/health":    ("Health Endpoint Accessible",                 Severity.INFO,     None,       0),
            "/actuator":           ("Actuator Root Accessible",                   Severity.MEDIUM,   "CWE-200", 5.3),
        }

        for port in ports_to_check:
            # First check if the port is open at all
            import socket
            try:
                with socket.create_connection((self.host, port), timeout=2):
                    pass
            except Exception:
                continue

            result.raw_output += f"\nProbing port {port} for Spring Boot actuators:\n"

            for path, (title, severity, cwe, cvss) in sensitive_paths.items():
                resp = self._http_probe(port, path, timeout=4)
                if resp is None:
                    continue

                code_str, body = resp.split(":", 1) if ":" in resp else (resp, "")
                try:
                    code = int(code_str)
                except ValueError:
                    continue

                result.raw_output += f"  {path} -> HTTP {code}\n"

                if code in (200, 204):
                    # For env, try to extract any visible secrets from body
                    evidence = f"HTTP {code} on {self.host}:{port}{path}"
                    if body and path in ("/actuator/env",):
                        # Show snippet - may contain property names/values
                        evidence += f"\nResponse snippet: {body[:300]}"

                    result.add_finding(Finding(
                        title=f"Spring Boot Actuator: {title} (port {port})",
                        severity=severity,
                        category=Category.JAVA_JVM,
                        description=(
                            f"{title} at {self.host}:{port}{path}. "
                            "Unauthenticated actuator endpoints leak sensitive information "
                            "and can expose application secrets."
                        ),
                        evidence=evidence,
                        recommendation=(
                            "Restrict actuator exposure in application.properties:\n"
                            "  management.endpoints.web.exposure.include=health,info\n"
                            "  management.endpoint.health.show-details=never\n"
                            "Add Spring Security to protect all /actuator/** paths."
                        ),
                        cwe_id=cwe,
                        cvss_score=cvss if cvss > 0 else None,
                    ))

    # ------------------------------------------------- Jolokia (JMX over HTTP)

    def _check_jolokia(self, result: ScanResult):
        """Jolokia is a JMX-HTTP bridge — if exposed without auth, gives full JMX access."""
        result.raw_output += "\n--- Jolokia JMX-HTTP Bridge Check ---\n"

        ports_to_check = [8080, 8081, 8090, 8443, 9090, 8161, 8778]

        for port in ports_to_check:
            import socket
            try:
                with socket.create_connection((self.host, port), timeout=2):
                    pass
            except Exception:
                continue

            for path in ["/jolokia/", "/jolokia/list", "/hawtio/jolokia/"]:
                resp = self._http_probe(port, path, timeout=4)
                if resp is None:
                    continue

                code_str, body = resp.split(":", 1) if ":" in resp else (resp, "")
                try:
                    code = int(code_str)
                except ValueError:
                    continue

                if code == 200 and ("jolokia" in body.lower() or "request" in body.lower()):
                    result.add_finding(Finding(
                        title=f"Jolokia JMX Bridge Exposed on Port {port}",
                        severity=Severity.HIGH,
                        category=Category.JAVA_JVM,
                        description=(
                            f"Jolokia JMX-HTTP bridge is accessible at "
                            f"{self.host}:{port}{path} without authentication. "
                            "Jolokia provides HTTP access to all JMX MBeans, "
                            "enabling memory inspection, class loading, and potential RCE."
                        ),
                        evidence=f"HTTP {code} at {self.host}:{port}{path}; "
                                 f"response: {body[:200]}",
                        recommendation=(
                            "Configure Jolokia authentication in jolokia-access.xml. "
                            "Restrict to localhost via Spring Security or a reverse proxy. "
                            "Disable if not required."
                        ),
                        cwe_id="CWE-284",
                        cvss_score=8.8,
                    ))
                    break  # one finding per port

    # ----------------------------------------- Docker containers running Java

    def _check_docker_java(self, result: ScanResult):
        """Find Docker containers running Java apps and check their JVM args for issues."""
        result.raw_output += "\n--- Docker Java Containers ---\n"

        containers = self._run_remote(
            "docker ps --format '{{.Names}}\\t{{.Image}}\\t{{.Ports}}' 2>/dev/null"
        )
        if not containers or not containers.strip():
            result.raw_output += "No Docker containers found\n"
            return

        java_images = ["java", "jdk", "jre", "openjdk", "temurin", "corretto",
                       "spring", "tomcat", "wildfly", "jboss", "payara", "glassfish",
                       "kafka", "zookeeper", "jenkins", "sonar", "nexus", "artifactory"]

        for line in containers.strip().splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            name, image = parts[0], parts[1]
            ports = parts[2] if len(parts) > 2 else ""

            if not any(kw in image.lower() for kw in java_images):
                # Also check CMD/Entrypoint for java keyword
                cmd_check = self._run_remote(
                    f"docker inspect {name} 2>/dev/null | "
                    "python3 -c \""
                    "import sys,json; c=json.load(sys.stdin)[0]; "
                    "cfg=c.get('Config',{}); "
                    "print(' '.join((cfg.get('Cmd') or []) + (cfg.get('Entrypoint') or [])))"
                    "\" 2>/dev/null"
                )
                if not cmd_check or "java" not in cmd_check.lower():
                    continue

            result.raw_output += f"Java container: {name} ({image}) ports: {ports}\n"

            # Get full JVM args from the container CMD/Entrypoint + Env
            inspect_out = self._run_remote(
                f"docker inspect {name} 2>/dev/null | "
                "python3 -c \""
                "import sys,json; c=json.load(sys.stdin)[0]; "
                "cfg=c.get('Config',{}); "
                "args=' '.join((cfg.get('Cmd') or [])+(cfg.get('Entrypoint') or [])); "
                "env='\\n'.join(cfg.get('Env') or []); "
                "print('CMD:'+args); print('ENV:'+env)"
                "\" 2>/dev/null"
            )
            if not inspect_out:
                continue

            # Check for JDWP in container args
            if "jdwp" in inspect_out.lower() or "xdebug" in inspect_out.lower():
                debug_port_match = re.search(
                    r'address=(?:\*:|\[::\]:)?(\d+)', inspect_out
                )
                debug_port = debug_port_match.group(1) if debug_port_match else "?"
                result.add_finding(Finding(
                    title=f"Docker Java Container With JDWP Debug Enabled: {name}",
                    severity=Severity.CRITICAL,
                    category=Category.JAVA_JVM,
                    description=(
                        f"Docker container '{name}' ({image}) is running with JDWP "
                        f"debug agent on port {debug_port}. "
                        "If the debug port is published, any host can attach a debugger "
                        "and achieve full RCE inside the container."
                    ),
                    evidence=inspect_out[:300],
                    recommendation=(
                        "Remove debug JVM flags from the Docker image CMD/Entrypoint. "
                        "Never run JDWP in production containers."
                    ),
                    cwe_id="CWE-489",
                    cvss_score=9.8,
                ))

            # Check for JMX without auth in container
            if "jmxremote" in inspect_out.lower() and "authenticate=false" in inspect_out.lower():
                result.add_finding(Finding(
                    title=f"Docker Java Container With Unauthenticated JMX: {name}",
                    severity=Severity.CRITICAL,
                    category=Category.JAVA_JVM,
                    description=(
                        f"Container '{name}' ({image}) has JMX remote enabled without "
                        "authentication. Attackers can use JMX to execute arbitrary code."
                    ),
                    evidence=inspect_out[:300],
                    recommendation=(
                        "Remove jmxremote.authenticate=false from container JVM args. "
                        "Use SSH tunneling for remote JMX monitoring."
                    ),
                    cwe_id="CWE-306",
                    cvss_score=9.8,
                ))

            # Check for debug port published externally
            if "0.0.0.0" in ports:
                debug_port_check = re.search(r'0\.0\.0\.0:(\d+)->(5005|8000|8787|4000)', ports)
                if debug_port_check:
                    result.add_finding(Finding(
                        title=f"Docker Java Debug Port Published Externally: {name}",
                        severity=Severity.CRITICAL,
                        category=Category.JAVA_JVM,
                        description=(
                            f"Container '{name}' is publishing debug port "
                            f"{debug_port_check.group(1)} on 0.0.0.0. "
                            "Any host can attach a Java debugger and achieve RCE."
                        ),
                        evidence=f"Ports: {ports}",
                        recommendation=(
                            "Remove debug port from Docker port mapping. "
                            "Change 0.0.0.0:5005 to 127.0.0.1:5005 if local access is needed."
                        ),
                        cwe_id="CWE-489",
                        cvss_score=9.8,
                    ))

    # --------------------------------- Spring Security auto-generated password

    def _check_spring_default_password(self, result: ScanResult):
        """Check if Spring Security auto-generated password appears in application logs."""
        result.raw_output += "\n--- Spring Security Default Password Check ---\n"

        log_search = self._run_remote(
            "grep -rl 'Using generated security password' "
            "/var/log /opt /srv /app /home 2>/dev/null | head -5"
        )
        if log_search and log_search.strip():
            # Extract the actual password if visible
            password_line = self._run_remote(
                f"grep -h 'Using generated security password' "
                f"{' '.join(log_search.strip().splitlines()[:3])} 2>/dev/null | head -3"
            )
            result.add_finding(Finding(
                title="Spring Security Auto-Generated Password in Logs",
                severity=Severity.HIGH,
                category=Category.JAVA_JVM,
                description=(
                    "Spring Boot application is using the auto-generated security password "
                    "(no security config provided). The password is written to application logs, "
                    "making it readable to anyone with log access."
                ),
                evidence=(
                    f"Found in log files: {log_search.strip()[:200]}"
                    + (f"\nLine: {password_line.strip()[:150]}" if password_line else "")
                ),
                recommendation=(
                    "Configure Spring Security with a proper UserDetailsService or "
                    "set spring.security.user.password in application.properties "
                    "(use environment variable or secrets manager, not plaintext)."
                ),
                cwe_id="CWE-521",
            ))
        else:
            result.raw_output += "  No Spring auto-generated password found in logs\n"
