"""Report generator - produces HTML, JSON, and Markdown security reports."""
import json
import datetime
from collections import Counter, defaultdict
from .models import Finding, ScanResult, Severity


class ReportGenerator:
    def __init__(self, scan_results: list[ScanResult], target_host: str):
        self.scan_results = scan_results
        self.target_host = target_host
        self.all_findings = []
        for sr in scan_results:
            self.all_findings.extend(sr.findings)

    def _severity_order(self, finding: Finding) -> int:
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                 Severity.LOW: 3, Severity.INFO: 4}
        return order.get(finding.severity, 5)

    def _group_by_category(self) -> dict:
        """Group findings by category, sorted by severity within each group."""
        groups = defaultdict(list)
        for f in self.all_findings:
            groups[f.category.value].append(f)
        for cat in groups:
            groups[cat].sort(key=self._severity_order)
        return dict(sorted(groups.items()))

    def generate_json(self, output_path: str):
        report = {
            "report_metadata": {
                "target": self.target_host,
                "scan_date": datetime.datetime.now().isoformat(),
                "total_findings": len(self.all_findings),
                "scanners_run": [sr.scanner_name for sr in self.scan_results],
            },
            "summary": dict(Counter(f.severity.value for f in self.all_findings)),
            "findings_by_category": {
                cat: [f.to_dict() for f in findings]
                for cat, findings in self._group_by_category().items()
            },
            "raw_outputs": {sr.scanner_name: sr.raw_output for sr in self.scan_results},
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

    def generate_markdown(self, output_path: str):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        severity_counts = Counter(f.severity.value for f in self.all_findings)
        sev_badge = {
            "CRITICAL": "🔴 CRITICAL",
            "HIGH":     "🟠 HIGH",
            "MEDIUM":   "🟡 MEDIUM",
            "LOW":      "🔵 LOW",
            "INFO":     "⚪ INFO",
        }

        lines = [
            "# Security Audit Report",
            "",
            "## Target Information",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Host** | `{self.target_host}` |",
            f"| **Scan Date** | {now} |",
            f"| **Scanners Run** | {', '.join(sr.scanner_name for sr in self.scan_results)} |",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            lines.append(f"| {sev_badge.get(sev, sev)} | {count} |")

        lines.extend([
            "",
            f"**Total Vulnerabilities: {len(self.all_findings)}**",
            "",
            "---",
            "",
            "## Vulnerabilities by Category",
            "",
        ])

        category_groups = self._group_by_category()
        finding_num = 1
        for cat_name, findings in category_groups.items():
            lines.extend([f"## {cat_name}", ""])
            for f in findings:
                badge = sev_badge.get(f.severity.value, f.severity.value)
                lines.extend([
                    f"### {finding_num}. {badge} — {f.title}",
                    "",
                    f"- **Severity:** {f.severity.value}",
                    f"- **Host:** `{self.target_host}`",
                    f"- **Description:** {f.description}",
                ])
                if f.evidence:
                    lines.append(f"- **Evidence:** `{f.evidence}`")
                if f.cwe_id:
                    lines.append(
                        f"- **CWE:** [{f.cwe_id}]"
                        f"(https://cwe.mitre.org/data/definitions/{f.cwe_id.split('-')[1]}.html)"
                    )
                if f.cvss_score:
                    lines.append(f"- **CVSS Score:** {f.cvss_score}")
                if f.recommendation:
                    lines.append(f"- **Recommendation:** {f.recommendation}")
                lines.append("")
                finding_num += 1

        lines.extend(["---", "", "## Scanner Raw Output", ""])
        for sr in self.scan_results:
            if sr.raw_output:
                lines.extend([
                    f"### {sr.scanner_name}",
                    "```",
                    sr.raw_output[:3000],
                    "```",
                    "",
                ])

        with open(output_path, "w") as f:
            f.write("\n".join(lines))

    def generate_html(self, output_path: str):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        severity_counts = Counter(f.severity.value for f in self.all_findings)
        category_groups = self._group_by_category()

        severity_colors = {
            "CRITICAL": "#dc2626",
            "HIGH":     "#ea580c",
            "MEDIUM":   "#d97706",
            "LOW":      "#2563eb",
            "INFO":     "#6b7280",
        }
        category_icons = {
            "Network Security":          "🌐",
            "SSH Configuration":         "🔐",
            "Authentication & Authorization": "🛡️",
            "TLS/SSL":                   "🔒",
            "Service Security":          "⚙️",
            "Infrastructure":            "🏗️",
            "Static Analysis":           "📋",
            "Secrets Management":        "🗝️",
            "Access Control":            "🚦",
            "VPN Security":              "🔭",
            "System Payload Exposure":   "📤",
            "Binary Security":           "💾",
        }

        # Build findings HTML grouped by category
        findings_html = ""
        finding_num = 1
        for cat_name, findings in category_groups.items():
            icon = category_icons.get(cat_name, "🔍")
            findings_html += f'<div class="category-section">\n'
            findings_html += (
                f'<h2 class="category-header">'
                f'<span class="cat-icon">{icon}</span> {cat_name}'
                f'<span class="cat-count">{len(findings)} finding{"s" if len(findings)!=1 else ""}</span>'
                f'</h2>\n'
            )
            for f in findings:
                color = severity_colors.get(f.severity.value, "#6b7280")
                evidence_html = (
                    f"<div class='finding-evidence'>"
                    f"<strong>Evidence:</strong> <code>{f.evidence}</code></div>"
                    if f.evidence else ""
                )
                cwe_html = (
                    f"<span class='finding-meta'><strong>CWE:</strong> "
                    f"<a href='https://cwe.mitre.org/data/definitions/{f.cwe_id.split('-')[1]}.html'>"
                    f"{f.cwe_id}</a></span>"
                    if f.cwe_id else ""
                )
                cvss_html = (
                    f"<span class='finding-meta'><strong>CVSS:</strong> {f.cvss_score}</span>"
                    if f.cvss_score else ""
                )
                rec_html = (
                    f"<div class='finding-rec'><strong>Recommendation:</strong> {f.recommendation}</div>"
                    if f.recommendation else ""
                )
                findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color};">
                <div class="finding-header">
                    <span class="badge" style="background:{color};">{f.severity.value}</span>
                    <strong class="finding-title">{finding_num}. {f.title}</strong>
                    <span class="finding-host">🖥 {self.target_host}</span>
                </div>
                <p class="finding-desc">{f.description}</p>
                {evidence_html}
                <div class="finding-meta-row">{cwe_html}{cvss_html}</div>
                {rec_html}
            </div>"""
                finding_num += 1
            findings_html += "\n</div>\n"

        # Summary bars
        summary_bars = ""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            color = severity_colors.get(sev, "#6b7280")
            width = min(count * 40, 300)
            summary_bars += f"""
            <div class="summary-row">
                <span class="summary-label">{sev}</span>
                <div class="bar" style="width:{max(width,4)}px;background:{color};"></div>
                <span class="summary-count">{count}</span>
            </div>"""

        scanners_list = ", ".join(sr.scanner_name for sr in self.scan_results)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit Report — {self.target_host}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f1f5f9; color: #1e293b; line-height: 1.6; }}
    .container {{ max-width: 980px; margin: 0 auto; padding: 2rem; }}
    h1 {{ font-size: 1.9rem; margin-bottom: 0.5rem; }}

    /* Host info banner */
    .host-banner {{ background: #0f172a; color: #e2e8f0; border-radius: 10px;
                    padding: 1.25rem 1.75rem; margin-bottom: 1.75rem;
                    display: flex; align-items: center; gap: 2rem; flex-wrap: wrap; }}
    .host-banner .host-ip {{ font-size: 1.5rem; font-weight: 800; color: #38bdf8; }}
    .host-banner .host-detail {{ font-size: 0.85rem; color: #94a3b8; }}
    .host-banner .host-detail span {{ color: #cbd5e1; font-weight: 600; }}

    /* Summary */
    .summary {{ background: white; border-radius: 10px; padding: 1.5rem;
                box-shadow: 0 1px 4px rgba(0,0,0,0.08); margin-bottom: 2rem; }}
    .summary h2 {{ margin-bottom: 1rem; font-size: 1.15rem; }}
    .summary-row {{ display: flex; align-items: center; gap: 1rem; margin-bottom: 0.5rem; }}
    .summary-label {{ width: 90px; font-weight: 700; font-size: 0.82rem; }}
    .bar {{ height: 22px; border-radius: 4px; min-width: 4px; transition: width 0.3s; }}
    .summary-count {{ font-weight: 700; font-size: 1rem; }}
    .total {{ font-size: 1.4rem; font-weight: 800; margin-top: 1rem;
              padding-top: 0.75rem; border-top: 1px solid #e2e8f0; }}

    /* Category sections */
    .section-heading {{ font-size: 1.3rem; font-weight: 800; margin-bottom: 1.25rem;
                        padding-bottom: 0.4rem; border-bottom: 2px solid #e2e8f0; }}
    .category-section {{ margin-bottom: 2.5rem; }}
    .category-header {{ font-size: 1.1rem; font-weight: 700; margin-bottom: 0.75rem;
                        padding: 0.6rem 1rem; background: #e2e8f0; border-radius: 7px;
                        display: flex; align-items: center; gap: 0.5rem; }}
    .cat-icon {{ font-size: 1.1rem; }}
    .cat-count {{ margin-left: auto; font-size: 0.78rem; font-weight: 600;
                  background: #94a3b8; color: white; padding: 2px 8px; border-radius: 12px; }}

    /* Findings */
    .finding {{ background: white; border-radius: 8px; padding: 1.1rem 1.25rem;
                margin-bottom: 0.85rem; box-shadow: 0 1px 3px rgba(0,0,0,0.07); }}
    .finding-header {{ display: flex; align-items: center; gap: 0.75rem;
                       margin-bottom: 0.6rem; flex-wrap: wrap; }}
    .badge {{ color: white; padding: 3px 9px; border-radius: 4px;
              font-size: 0.73rem; font-weight: 800; white-space: nowrap; }}
    .finding-title {{ font-size: 0.95rem; }}
    .finding-host {{ margin-left: auto; font-size: 0.78rem; color: #64748b;
                     background: #f1f5f9; padding: 2px 8px; border-radius: 4px; }}
    .finding-desc {{ color: #475569; font-size: 0.9rem; margin-bottom: 0.5rem; }}
    .finding-evidence {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 5px;
                         padding: 0.4rem 0.7rem; margin: 0.4rem 0; font-size: 0.85rem; }}
    .finding-meta-row {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 0.3rem 0; }}
    .finding-meta {{ font-size: 0.83rem; color: #64748b; }}
    .finding-rec {{ font-size: 0.85rem; color: #1e293b; margin-top: 0.4rem;
                    padding-top: 0.4rem; border-top: 1px dashed #e2e8f0; }}
    code {{ background: #f1f5f9; padding: 1px 5px; border-radius: 3px;
            font-size: 0.82rem; word-break: break-all; }}
    a {{ color: #2563eb; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<div class="container">
    <h1>Security Audit Report</h1>

    <div class="host-banner">
        <div>
            <div style="font-size:0.75rem;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:2px;">Target Host</div>
            <div class="host-ip">🖥 {self.target_host}</div>
        </div>
        <div class="host-detail">
            <div><span>Scan Date:</span> {now}</div>
            <div><span>Scanners:</span> {scanners_list}</div>
        </div>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        {summary_bars}
        <p class="total">Total Vulnerabilities: {len(self.all_findings)}</p>
    </div>

    <h2 class="section-heading">Vulnerabilities by Category</h2>
    {findings_html}
</div>
</body>
</html>"""

        with open(output_path, "w") as f:
            f.write(html)
