#!/usr/bin/env python3
"""Reporting module for Hoover WiFi Security Toolkit.

Generates HTML, PDF, and JSON reports from scan results, handshake
captures, client fingerprints, vulnerability findings, and other
attack module output. For authorized security testing and research
only.
"""

import argparse
import glob
import html
import json
import os
from datetime import datetime, timezone
from typing import Optional

from utils import setup_logging

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High": "#f97316",
    "Medium": "#eab308",
    "Low": "#3b82f6",
    "Info": "#6b7280",
}

SUPPORTED_FORMATS = ("html", "pdf", "json", "all")
SUPPORTED_TEMPLATES = ("default", "executive", "technical")


def _now_iso() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


class ReportGenerator:
    """Builds and renders WiFi security assessment reports.

    Accumulates sections of narrative text and structured data from
    scan/attack modules, then renders them as HTML, PDF, or JSON.
    """

    def __init__(self, title: str = "WiFi Security Assessment",
                 author: str = "Hoover Toolkit",
                 output_dir: str = "reports",
                 template: str = "default") -> None:
        self.title = title
        self.author = author
        self.output_dir = output_dir
        self.template = template
        self.sections: list[dict] = []
        self.logger = setup_logging("reporting")

    # -- Section builders ----------------------------------------------

    def add_section(self, title: str, content: str,
                     data: Optional[dict] = None) -> None:
        """Add a report section with narrative text and optional data."""
        self.sections.append({
            "title": title,
            "type": "generic",
            "content": content,
            "data": data or {},
            "timestamp": _now_iso(),
        })

    def add_scan_results(self, ap_data: dict) -> None:
        """Add AP scan results as a formatted table section."""
        aps = ap_data.get("access_points", ap_data.get("aps", []))
        if not isinstance(aps, list):
            aps = []
        self.sections.append({
            "title": "Access Point Scan Results",
            "type": "scan_results",
            "content": f"Discovered {len(aps)} access point(s) during the scan.",
            "data": {"access_points": aps},
            "timestamp": _now_iso(),
        })

    def add_handshake_results(self, handshake_data: dict) -> None:
        """Add handshake capture results with verification status."""
        handshakes = handshake_data.get("handshakes", [])
        if not isinstance(handshakes, list):
            handshakes = []
        verified = sum(1 for h in handshakes if h.get("verified"))
        self.sections.append({
            "title": "Handshake Capture Results",
            "type": "handshake_results",
            "content": (
                f"Captured {len(handshakes)} handshake(s); "
                f"{verified} verified."
            ),
            "data": {"handshakes": handshakes},
            "timestamp": _now_iso(),
        })

    def add_client_data(self, fingerprints: dict) -> None:
        """Add client fingerprint data section."""
        clients = fingerprints.get("clients", [])
        if not isinstance(clients, list):
            clients = []
        self.sections.append({
            "title": "Client Fingerprints",
            "type": "client_data",
            "content": f"Identified {len(clients)} client device(s).",
            "data": {"clients": clients},
            "timestamp": _now_iso(),
        })

    def add_vulnerability_findings(self, findings: list[dict]) -> None:
        """Add vulnerability findings with severity."""
        if not isinstance(findings, list):
            findings = []
        counts: dict[str, int] = {}
        for finding in findings:
            severity = finding.get("severity", "Info")
            counts[severity] = counts.get(severity, 0) + 1
        self.sections.append({
            "title": "Vulnerability Findings",
            "type": "vulnerability_findings",
            "content": f"Identified {len(findings)} finding(s).",
            "data": {"findings": findings, "severity_counts": counts},
            "timestamp": _now_iso(),
        })

    def add_attack_results(self, attack_name: str, results: dict) -> None:
        """Add results from any attack module."""
        self.sections.append({
            "title": f"Attack Results: {attack_name}",
            "type": "attack_results",
            "content": f"Results from the '{attack_name}' module.",
            "data": {"attack_name": attack_name, "results": results or {}},
            "timestamp": _now_iso(),
        })

    # -- Helpers ----------------------------------------------------

    def _all_findings(self) -> list[dict]:
        findings: list[dict] = []
        for section in self.sections:
            if section.get("type") == "vulnerability_findings":
                findings.extend(section.get("data", {}).get("findings", []))
        return findings

    # -- Rendering ----------------------------------------------------

    def _render_executive_summary(self) -> str:
        """Generate executive summary from findings."""
        findings = self._all_findings()
        counts = dict.fromkeys(SEVERITY_ORDER, 0)
        affected_targets: set = set()
        for finding in findings:
            severity = finding.get("severity", "Info")
            if severity not in counts:
                counts[severity] = 0
            counts[severity] += 1
            target = finding.get("affected_target")
            if target:
                affected_targets.add(target)

        weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Info": 0}
        risk_score = sum(weights.get(sev, 0) * n for sev, n in counts.items())

        parts = [f"<p>Total findings: {len(findings)}</p>"]
        parts.append("<ul>")
        for sev in SEVERITY_ORDER:
            if counts.get(sev):
                color = SEVERITY_COLORS.get(sev, "#6b7280")
                parts.append(
                    f'<li><span class="severity-badge" '
                    f'style="background:{color}">{html.escape(sev)}</span> '
                    f"{counts[sev]}</li>"
                )
        parts.append("</ul>")
        if affected_targets:
            targets_html = ", ".join(html.escape(str(t)) for t in sorted(affected_targets))
            parts.append(f"<p>Affected targets: {targets_html}</p>")
        parts.append(f"<p>Overall risk score: {risk_score}</p>")
        return "\n".join(parts)

    def _render_section_data_html(self, section: dict) -> str:
        """Render a section's structured data as HTML (tables, badges)."""
        data = section.get("data") or {}
        section_type = section.get("type")
        out = []

        if section_type == "scan_results" and data.get("access_points"):
            out.append('<table class="data-table"><thead><tr>'
                        "<th>SSID</th><th>BSSID</th><th>Channel</th>"
                        "<th>Signal</th><th>Encryption</th></tr></thead><tbody>")
            for ap in data["access_points"]:
                out.append(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                        html.escape(str(ap.get("ssid", ""))),
                        html.escape(str(ap.get("bssid", ""))),
                        html.escape(str(ap.get("channel", ""))),
                        html.escape(str(ap.get("signal", ""))),
                        html.escape(str(ap.get("encryption", ""))),
                    )
                )
            out.append("</tbody></table>")

        elif section_type == "handshake_results" and data.get("handshakes"):
            out.append('<table class="data-table"><thead><tr>'
                        "<th>SSID</th><th>BSSID</th><th>Verified</th></tr></thead><tbody>")
            for hs in data["handshakes"]:
                verified = "Yes" if hs.get("verified") else "No"
                out.append(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                        html.escape(str(hs.get("ssid", ""))),
                        html.escape(str(hs.get("bssid", ""))),
                        html.escape(verified),
                    )
                )
            out.append("</tbody></table>")

        elif section_type == "client_data" and data.get("clients"):
            out.append('<table class="data-table"><thead><tr>'
                        "<th>MAC</th><th>Vendor</th><th>Device</th></tr></thead><tbody>")
            for client in data["clients"]:
                out.append(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                        html.escape(str(client.get("mac", ""))),
                        html.escape(str(client.get("vendor", ""))),
                        html.escape(str(client.get("device", ""))),
                    )
                )
            out.append("</tbody></table>")

        elif section_type == "vulnerability_findings" and data.get("findings"):
            out.append('<table class="data-table"><thead><tr>'
                        "<th>ID</th><th>Name</th><th>Severity</th>"
                        "<th>Target</th><th>Description</th></tr></thead><tbody>")
            for finding in data["findings"]:
                severity = finding.get("severity", "Info")
                color = SEVERITY_COLORS.get(severity, "#6b7280")
                out.append(
                    "<tr><td>{}</td><td>{}</td>"
                    '<td><span class="severity-badge" style="background:{}">{}</span></td>'
                    "<td>{}</td><td>{}</td></tr>".format(
                        html.escape(str(finding.get("id", ""))),
                        html.escape(str(finding.get("name", ""))),
                        color,
                        html.escape(severity),
                        html.escape(str(finding.get("affected_target", ""))),
                        html.escape(str(finding.get("description", ""))),
                    )
                )
            out.append("</tbody></table>")

        elif section_type == "attack_results":
            results = data.get("results", {})
            out.append(
                f"<pre>{html.escape(json.dumps(results, indent=2, default=str))}</pre>"
            )

        return "\n".join(out)

    def _render_html(self) -> str:
        """Render full HTML report from accumulated sections."""
        css = """
        body { background:#0f172a; color:#e2e8f0; font-family: -apple-system, Segoe UI, Arial, sans-serif; margin:0; padding:0; }
        .container { max-width:960px; margin:0 auto; padding:32px; }
        h1 { color:#38bdf8; }
        h2 { color:#7dd3fc; border-bottom:1px solid #334155; padding-bottom:4px; }
        .meta { color:#94a3b8; font-size:0.9em; margin-bottom:24px; }
        .section { background:#1e293b; border-radius:8px; padding:20px; margin-bottom:20px; }
        .data-table { width:100%; border-collapse:collapse; margin-top:12px; }
        .data-table th, .data-table td { border:1px solid #334155; padding:8px; text-align:left; font-size:0.9em; }
        .data-table th { background:#0f172a; }
        .severity-badge { color:#fff; padding:2px 8px; border-radius:4px; font-size:0.85em; }
        pre { background:#0f172a; padding:12px; border-radius:6px; overflow-x:auto; }
        """

        body_parts = [
            '<div class="container">',
            f"<h1>{html.escape(self.title)}</h1>",
            '<div class="meta">',
            f"Author: {html.escape(self.author)} &middot; ",
            f"Generated: {html.escape(_now_iso())} &middot; ",
            f"Template: {html.escape(self.template)}",
            "</div>",
            "<h2>Executive Summary</h2>",
            f'<div class="section">{self._render_executive_summary()}</div>',
        ]

        for section in self.sections:
            body_parts.append(f"<h2>{html.escape(section['title'])}</h2>")
            body_parts.append('<div class="section">')
            body_parts.append(f"<p>{html.escape(section.get('content', ''))}</p>")
            body_parts.append(self._render_section_data_html(section))
            body_parts.append(
                f'<div class="meta">Added: {html.escape(section.get("timestamp", ""))}</div>'
            )
            body_parts.append("</div>")

        body_parts.append("</div>")

        return (
            "<!DOCTYPE html>\n"
            "<html lang=\"en\">\n<head>\n"
            f"<meta charset=\"utf-8\">\n<title>{html.escape(self.title)}</title>\n"
            f"<style>{css}</style>\n</head>\n<body>\n"
            + "\n".join(body_parts)
            + "\n</body>\n</html>\n"
        )

    # -- Output generation ----------------------------------------------

    def _resolve_output_path(self, output_path: Optional[str], ext: str) -> str:
        if output_path:
            return output_path
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"report_{timestamp}.{ext}"
        return os.path.join(self.output_dir, filename)

    def generate_html(self, output_path: Optional[str] = None) -> str:
        """Generate HTML report file, return path."""
        path = self._resolve_output_path(output_path, "html")
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        content = self._render_html()
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        self.logger.info("HTML report written to %s", path)
        return path

    def generate_pdf(self, output_path: Optional[str] = None) -> str:
        """Generate PDF from HTML via weasyprint/pdfkit, return path."""
        path = self._resolve_output_path(output_path, "pdf")
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        html_content = self._render_html()

        try:
            import weasyprint  # type: ignore
            weasyprint.HTML(string=html_content).write_pdf(path)
            self.logger.info("PDF report written to %s (weasyprint)", path)
            return path
        except ImportError:
            pass
        except Exception as exc:  # pragma: no cover - runtime failure path
            self.logger.warning("weasyprint failed to render PDF: %s", exc)

        try:
            import pdfkit  # type: ignore
            pdfkit.from_string(html_content, path)
            self.logger.info("PDF report written to %s (pdfkit)", path)
            return path
        except ImportError:
            pass
        except Exception as exc:  # pragma: no cover - runtime failure path
            self.logger.warning("pdfkit failed to render PDF: %s", exc)

        self.logger.warning(
            "No PDF backend available (weasyprint/pdfkit not installed); "
            "falling back to HTML-only output."
        )
        fallback_path = self._resolve_output_path(
            output_path.replace(".pdf", ".html") if output_path else None, "html"
        )
        with open(fallback_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return fallback_path

    def generate_json(self, output_path: Optional[str] = None) -> str:
        """Generate machine-readable JSON report."""
        path = self._resolve_output_path(output_path, "json")
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        report = {
            "title": self.title,
            "author": self.author,
            "template": self.template,
            "generated": _now_iso(),
            "summary": self.get_summary(),
            "sections": self.sections,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        self.logger.info("JSON report written to %s", path)
        return path

    # -- Loading existing results -----------------------------------------

    def load_results(self, result_files: list[str]) -> None:
        """Load results from JSON/pcap files produced by other tools."""
        for filepath in result_files:
            if not filepath.lower().endswith(".json"):
                self.logger.warning("Skipping non-JSON result file: %s", filepath)
                continue
            try:
                with open(filepath, encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError) as exc:
                self.logger.error("Failed to load %s: %s", filepath, exc)
                continue

            if not isinstance(data, dict):
                self.logger.warning("Skipping non-object result file: %s", filepath)
                continue

            if "access_points" in data or "aps" in data:
                self.add_scan_results(data)
            elif "handshakes" in data:
                self.add_handshake_results(data)
            elif "clients" in data:
                self.add_client_data(data)
            elif "findings" in data:
                self.add_vulnerability_findings(data["findings"])
            else:
                self.add_attack_results(
                    data.get("attack_name", os.path.basename(filepath)), data
                )

    def get_summary(self) -> dict:
        """Return summary statistics."""
        findings = self._all_findings()
        counts = dict.fromkeys(SEVERITY_ORDER, 0)
        for finding in findings:
            severity = finding.get("severity", "Info")
            counts[severity] = counts.get(severity, 0) + 1
        return {
            "section_count": len(self.sections),
            "finding_count": len(findings),
            "severity_counts": counts,
            "title": self.title,
            "author": self.author,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Hoover Report Generator - generate HTML/PDF/JSON security "
            "assessment reports from scan and attack module results. "
            "For authorized security testing and research only."
        )
    )
    parser.add_argument("--title", default="WiFi Security Assessment",
                         help="Report title")
    parser.add_argument("--author", default="Hoover Toolkit", help="Author name")
    parser.add_argument("-o", "--output-dir", default="reports",
                         help="Output directory for generated reports")
    parser.add_argument("-f", "--format", choices=SUPPORTED_FORMATS,
                         default="html", help="Report output format")
    parser.add_argument("--template", choices=SUPPORTED_TEMPLATES,
                         default="default", help="Report template")
    parser.add_argument("--load", nargs="*", default=[],
                         help="Paths to result files to include (glob patterns supported)")
    parser.add_argument("--scan-results", default=None,
                         help="Path to AP scan JSON")
    parser.add_argument("--handshake-data", default=None,
                         help="Path to handshake capture data")
    parser.add_argument("--client-data", default=None,
                         help="Path to client fingerprint JSON")
    parser.add_argument("--findings", default=None,
                         help="Path to vulnerability findings JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    generator = ReportGenerator(
        title=args.title,
        author=args.author,
        output_dir=args.output_dir,
        template=args.template,
    )
    generator.logger = setup_logging("reporting", verbose=args.verbose)

    load_files: list[str] = []
    for pattern in args.load:
        matches = glob.glob(pattern)
        load_files.extend(matches if matches else [pattern])
    if load_files:
        generator.load_results(load_files)

    if args.scan_results:
        with open(args.scan_results, encoding="utf-8") as f:
            generator.add_scan_results(json.load(f))
    if args.handshake_data:
        with open(args.handshake_data, encoding="utf-8") as f:
            generator.add_handshake_results(json.load(f))
    if args.client_data:
        with open(args.client_data, encoding="utf-8") as f:
            generator.add_client_data(json.load(f))
    if args.findings:
        with open(args.findings, encoding="utf-8") as f:
            findings_data = json.load(f)
        findings_list = (
            findings_data.get("findings", [])
            if isinstance(findings_data, dict) else findings_data
        )
        generator.add_vulnerability_findings(findings_list)

    if args.format in ("html", "all"):
        path = generator.generate_html()
        print(f"HTML report: {path}")
    if args.format in ("pdf", "all"):
        path = generator.generate_pdf()
        print(f"PDF report: {path}")
    if args.format in ("json", "all"):
        path = generator.generate_json()
        print(f"JSON report: {path}")


if __name__ == "__main__":
    main()
