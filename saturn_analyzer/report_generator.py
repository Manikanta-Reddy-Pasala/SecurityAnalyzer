"""Report generator - produces HTML, JSON, and Markdown security reports."""
import json
import datetime
from collections import Counter
from typing import Optional
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

    def generate_json(self, output_path: str):
        report = {
            "report_metadata": {
                "target": self.target_host,
                "scan_date": datetime.datetime.now().isoformat(),
                "total_findings": len(self.all_findings),
                "scanners_run": [sr.scanner_name for sr in self.scan_results],
            },
            "summary": dict(Counter(f.severity.value for f in self.all_findings)),
            "findings": [f.to_dict() for f in sorted(self.all_findings, key=self._severity_order)],
            "raw_outputs": {sr.scanner_name: sr.raw_output for sr in self.scan_results},
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

    def generate_markdown(self, output_path: str):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        severity_counts = Counter(f.severity.value for f in self.all_findings)

        lines = [
            f"# Security Audit Report - Saturn UAT Environment",
            f"",
            f"**Target:** `{self.target_host}`",
            f"**Date:** {now}",
            f"**Scanners:** {', '.join(sr.scanner_name for sr in self.scan_results)}",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            emoji = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "-", "INFO": "i"}
            lines.append(f"| {emoji.get(sev, '')} {sev} | {count} |")

        lines.extend([
            f"",
            f"**Total Findings: {len(self.all_findings)}**",
            f"",
            f"---",
            f"",
        ])

        sorted_findings = sorted(self.all_findings, key=self._severity_order)

        current_severity = None
        for i, f in enumerate(sorted_findings, 1):
            if f.severity != current_severity:
                current_severity = f.severity
                lines.append(f"## {current_severity.value} Findings")
                lines.append("")

            lines.extend([
                f"### {i}. {f.title}",
                f"",
                f"- **Severity:** {f.severity.value}",
                f"- **Category:** {f.category.value}",
                f"- **Description:** {f.description}",
            ])
            if f.evidence:
                lines.append(f"- **Evidence:** `{f.evidence}`")
            if f.cwe_id:
                lines.append(f"- **CWE:** [{f.cwe_id}](https://cwe.mitre.org/data/definitions/{f.cwe_id.split('-')[1]}.html)")
            if f.recommendation:
                lines.append(f"- **Recommendation:** {f.recommendation}")
            lines.append("")

        # Raw output section
        lines.extend(["---", "", "## Scanner Raw Output", ""])
        for sr in self.scan_results:
            if sr.raw_output:
                lines.extend([
                    f"### {sr.scanner_name}",
                    f"```",
                    sr.raw_output[:3000],
                    f"```",
                    "",
                ])

        with open(output_path, "w") as f:
            f.write("\n".join(lines))

    def generate_html(self, output_path: str):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        severity_counts = Counter(f.severity.value for f in self.all_findings)
        sorted_findings = sorted(self.all_findings, key=self._severity_order)

        severity_colors = {
            "CRITICAL": "#dc2626", "HIGH": "#ea580c",
            "MEDIUM": "#d97706", "LOW": "#2563eb", "INFO": "#6b7280",
        }

        findings_html = ""
        for i, f in enumerate(sorted_findings, 1):
            color = severity_colors.get(f.severity.value, "#6b7280")
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color};">
                <div class="finding-header">
                    <span class="badge" style="background:{color};">{f.severity.value}</span>
                    <strong>{i}. {f.title}</strong>
                    <span class="category">{f.category.value}</span>
                </div>
                <p>{f.description}</p>
                {"<p><strong>Evidence:</strong> <code>" + f.evidence + "</code></p>" if f.evidence else ""}
                {"<p><strong>CWE:</strong> <a href='https://cwe.mitre.org/data/definitions/" + f.cwe_id.split('-')[1] + ".html'>" + f.cwe_id + "</a></p>" if f.cwe_id else ""}
                {"<p><strong>Recommendation:</strong> " + f.recommendation + "</p>" if f.recommendation else ""}
            </div>"""

        summary_bars = ""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            color = severity_colors.get(sev, "#6b7280")
            width = min(count * 40, 300)
            summary_bars += f"""
            <div class="summary-row">
                <span class="summary-label">{sev}</span>
                <div class="bar" style="width:{width}px;background:{color};"></div>
                <span class="summary-count">{count}</span>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit Report - Saturn UAT</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f8fafc; color: #1e293b; line-height: 1.6; }}
    .container {{ max-width: 960px; margin: 0 auto; padding: 2rem; }}
    h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
    .meta {{ color: #64748b; margin-bottom: 2rem; }}
    .summary {{ background: white; border-radius: 8px; padding: 1.5rem;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 2rem; }}
    .summary h2 {{ margin-bottom: 1rem; font-size: 1.2rem; }}
    .summary-row {{ display: flex; align-items: center; gap: 1rem; margin-bottom: 0.5rem; }}
    .summary-label {{ width: 80px; font-weight: 600; font-size: 0.85rem; }}
    .bar {{ height: 24px; border-radius: 4px; min-width: 4px; }}
    .summary-count {{ font-weight: 600; }}
    .finding {{ background: white; border-radius: 8px; padding: 1.25rem;
                margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    .finding-header {{ display: flex; align-items: center; gap: 0.75rem;
                       margin-bottom: 0.75rem; flex-wrap: wrap; }}
    .badge {{ color: white; padding: 2px 8px; border-radius: 4px;
              font-size: 0.75rem; font-weight: 700; }}
    .category {{ color: #64748b; font-size: 0.85rem; }}
    .finding p {{ margin-bottom: 0.5rem; }}
    code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 3px;
            font-size: 0.85rem; word-break: break-all; }}
    a {{ color: #2563eb; }}
    .total {{ font-size: 1.5rem; font-weight: 700; margin-top: 1rem; }}
</style>
</head>
<body>
<div class="container">
    <h1>Security Audit Report</h1>
    <p class="meta">Target: <code>{self.target_host}</code> | Date: {now}</p>

    <div class="summary">
        <h2>Executive Summary</h2>
        {summary_bars}
        <p class="total">Total Findings: {len(self.all_findings)}</p>
    </div>

    <h2 style="margin-bottom:1rem;">Findings</h2>
    {findings_html}
</div>
</body>
</html>"""

        with open(output_path, "w") as f:
            f.write(html)
