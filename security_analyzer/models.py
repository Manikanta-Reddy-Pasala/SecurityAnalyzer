"""Data models for security findings."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import datetime


class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Category(Enum):
    NETWORK = "Network Security"
    SSH = "SSH Configuration"
    AUTH = "Authentication & Authorization"
    TLS = "TLS/SSL"
    SERVICE = "Service Security"
    INFRASTRUCTURE = "Infrastructure"
    SAST = "Static Analysis"
    SECRETS = "Secrets Management"
    ACCESS_CONTROL = "Access Control"
    VPN = "VPN Security"
    PAYLOAD_EXPOSURE = "System Payload Exposure"
    BINARY_SECURITY = "Binary Security"
    DATABASE = "Database Security"
    JAVA_JVM = "Java/JVM Security"


@dataclass
class Finding:
    title: str
    severity: Severity
    category: Category
    description: str
    evidence: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None

    def to_dict(self):
        return {
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
        }


@dataclass
class ScanResult:
    scanner_name: str
    findings: list = field(default_factory=list)
    raw_output: str = ""
    scan_time: str = field(
        default_factory=lambda: datetime.datetime.now().isoformat()
    )
    success: bool = True
    error: Optional[str] = None

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
