# Security Audit Report

**Target:** `13.200.186.29`
**Date:** 2026-02-25 21:54:52
**Scanners:** Network Scanner, SSH Auditor, Service Scanner, Infrastructure Auditor, VPN Scanner, Auth Analyzer, Payload Exposure Scanner, Binary Vulnerability Scanner

---

## Executive Summary

| Severity | Count |
|----------|-------|
| !!! CRITICAL | 2 |
| !! HIGH | 2 |
| ! MEDIUM | 1 |
| - LOW | 0 |
| i INFO | 2 |

**Total Findings: 7**

---

## CRITICAL Findings

### 1. No VPN Tunnel Required for Access

- **Severity:** CRITICAL
- **Category:** Access Control
- **Description:** UAT environment is accessible without VPN. All non-production environments should require VPN to prevent unauthorized access.
- **Evidence:** `Direct SSH/HTTP access possible without VPN`
- **CWE:** [CWE-284](https://cwe.mitre.org/data/definitions/284.html)
- **Recommendation:** Deploy WireGuard or OpenVPN. Configure security groups to only allow traffic from VPN CIDR range.

### 2. No VPN Tunnel Required for Access

- **Severity:** CRITICAL
- **Category:** VPN Security
- **Description:** Environment is accessible without VPN. All non-production environments should require VPN to prevent unauthorized access.
- **Evidence:** `Direct SSH/HTTP access possible without VPN`
- **CWE:** [CWE-284](https://cwe.mitre.org/data/definitions/284.html)
- **Recommendation:** Deploy WireGuard or OpenVPN. Configure security groups to only allow traffic from VPN CIDR range.

## HIGH Findings

### 3. No IP Whitelisting Configured

- **Severity:** HIGH
- **Category:** Access Control
- **Description:** No IP whitelisting detected. Security groups should restrict access to known IP ranges only.
- **Evidence:** `Services accessible from arbitrary source IPs`
- **CWE:** [CWE-284](https://cwe.mitre.org/data/definitions/284.html)
- **Recommendation:** Configure AWS security groups with specific IP ranges. Use a bastion host pattern for SSH access.

### 4. No VPN Service Detected

- **Severity:** HIGH
- **Category:** VPN Security
- **Description:** No VPN service ports (WireGuard, OpenVPN, IPSec) were detected on the target host.
- **Evidence:** `Checked ports: 1194, 51820, 500, 4500, 1701, 1723`
- **CWE:** [CWE-284](https://cwe.mitre.org/data/definitions/284.html)
- **Recommendation:** Deploy a VPN solution (WireGuard recommended) and restrict all service access to VPN clients only.

## MEDIUM Findings

### 5. Public IP Address Detected

- **Severity:** MEDIUM
- **Category:** Network Security
- **Description:** Host 13.200.186.29 resolves to public IP 13.200.186.29. Public IPs are directly reachable from the internet.
- **Evidence:** `IP: 13.200.186.29`
- **CWE:** [CWE-284](https://cwe.mitre.org/data/definitions/284.html)
- **Recommendation:** Use private IPs with VPN/bastion host for UAT environments.

## INFO Findings

### 6. All Scanned Ports Filtered

- **Severity:** INFO
- **Category:** Network Security
- **Description:** No open ports detected from scan origin. This could mean security groups are restricting access, or the host is unreachable.
- **Evidence:** `Scanned 18 ports, all filtered/closed`
- **Recommendation:** Verify security group rules to confirm intentional filtering.

### 7. SSH Connection Failed

- **Severity:** INFO
- **Category:** SSH Configuration
- **Description:** Could not connect via SSH. Port may be filtered or credentials are invalid.
- **Evidence:** `Host: 13.200.186.29, User: ec2-user`
- **Recommendation:** Verify SSH access and retry from an authorized network.

---

## Scanner Raw Output

### Network Scanner
```
DNS Resolution: 13.200.186.29 -> 13.200.186.29
Open ports: []
No open ports found (all filtered/closed)
nmap not available, skipping advanced scan

```

### SSH Auditor
```
SSH key permissions: 600
Key info: 256 SHA256:rjt1WWsoWSnxQ9E+IJjIjNwppHi56q3urqD/KmYsfBs  (ED25519)
Key type ED25519 - good
Cannot establish SSH connection

```

### VPN Scanner
```
SSH not available, running external-only VPN checks

```

### Auth Analyzer
```
HTTP services found on ports: []

```

### Payload Exposure Scanner
```
Testing ports: []

```
