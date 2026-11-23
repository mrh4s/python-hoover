"""Tests for reporting.py — Report Generation module."""

import builtins
import json
import os
import sys
from unittest.mock import patch

import pytest

from reporting import SUPPORTED_FORMATS, ReportGenerator, main  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def generator(tmp_path):
    return ReportGenerator(
        title="Test Assessment",
        author="Tester",
        output_dir=str(tmp_path / "reports"),
    )


@pytest.fixture
def sample_findings():
    return [
        {
            "id": "CVE-2017-13077",
            "name": "KRACK - Key Reinstallation",
            "severity": "High",
            "affected_target": "AA:BB:CC:DD:EE:FF",
            "description": "Key reinstallation vulnerability",
            "evidence": "4-way handshake replay observed",
            "recommendation": "Patch client/AP firmware",
        },
        {
            "id": "DRAGONBLOOD-1",
            "name": "Dragonblood - Side Channel",
            "severity": "Critical",
            "affected_target": "11:22:33:44:55:66",
            "description": "WPA3 side-channel leak",
            "evidence": "Timing variance detected",
            "recommendation": "Upgrade to patched hostapd",
        },
    ]


class TestInitialization:
    def test_init_defaults(self):
        gen = ReportGenerator()
        assert gen.title == "WiFi Security Assessment"
        assert gen.author == "Hoover Toolkit"
        assert gen.output_dir == "reports"
        assert gen.template == "default"
        assert gen.sections == []


class TestSectionBuilders:
    def test_add_section(self, generator):
        generator.add_section("Intro", "Narrative text", {"key": "value"})
        assert len(generator.sections) == 1
        section = generator.sections[0]
        assert section["title"] == "Intro"
        assert section["content"] == "Narrative text"
        assert section["data"] == {"key": "value"}
        assert "timestamp" in section

    def test_add_scan_results(self, generator):
        ap_data = {
            "access_points": [
                {"ssid": "TestNet", "bssid": "aa:bb:cc:dd:ee:ff",
                 "channel": 6, "signal": -40, "encryption": "WPA2"}
            ]
        }
        generator.add_scan_results(ap_data)
        assert len(generator.sections) == 1
        section = generator.sections[0]
        assert section["type"] == "scan_results"
        assert section["data"]["access_points"] == ap_data["access_points"]

    def test_add_vulnerability_findings(self, generator, sample_findings):
        generator.add_vulnerability_findings(sample_findings)
        assert len(generator.sections) == 1
        section = generator.sections[0]
        assert section["type"] == "vulnerability_findings"
        assert section["data"]["severity_counts"]["High"] == 1
        assert section["data"]["severity_counts"]["Critical"] == 1


class TestRendering:
    def test_render_html_basic(self, generator):
        generator.add_section("Intro", "Some narrative")
        rendered = generator._render_html()
        assert generator.title in rendered
        assert "Intro" in rendered
        assert "Some narrative" in rendered

    def test_render_html_escapes_input(self, generator):
        generator.add_section("<script>alert(1)</script>", "<img src=x onerror=alert(2)>")
        rendered = generator._render_html()
        assert "<script>alert(1)</script>" not in rendered
        assert "<img src=x onerror=alert(2)>" not in rendered
        assert "&lt;script&gt;" in rendered

    def test_render_executive_summary(self, generator, sample_findings):
        generator.add_vulnerability_findings(sample_findings)
        summary_html = generator._render_executive_summary()
        assert "Total findings: 2" in summary_html
        assert "High" in summary_html
        assert "Critical" in summary_html


class TestFileGeneration:
    def test_generate_html_file(self, generator, tmp_path):
        generator.add_section("Intro", "Narrative")
        output_path = str(tmp_path / "out.html")
        result_path = generator.generate_html(output_path)
        assert result_path == output_path
        assert os.path.exists(output_path)
        with open(output_path, encoding="utf-8") as f:
            content = f.read()
        assert "Narrative" in content

    def test_generate_json_file(self, generator, tmp_path):
        generator.add_section("Intro", "Narrative", {"foo": "bar"})
        output_path = str(tmp_path / "out.json")
        result_path = generator.generate_json(output_path)
        assert result_path == output_path
        with open(output_path, encoding="utf-8") as f:
            data = json.load(f)
        assert data["title"] == generator.title
        assert data["author"] == generator.author
        assert len(data["sections"]) == 1
        assert data["sections"][0]["title"] == "Intro"
        assert "summary" in data

    def test_generate_pdf_missing_dep(self, generator, tmp_path):
        output_path = str(tmp_path / "out.pdf")

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name in ("weasyprint", "pdfkit"):
                raise ImportError(f"No module named '{name}'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            result_path = generator.generate_pdf(output_path)

        # Falls back to HTML when no PDF backend is available.
        assert result_path.endswith(".html")
        assert os.path.exists(result_path)


class TestLoadResults:
    def test_load_results_from_json(self, generator, tmp_path):
        scan_file = tmp_path / "scan.json"
        scan_file.write_text(json.dumps({
            "access_points": [
                {"ssid": "Net1", "bssid": "aa:bb:cc:dd:ee:ff",
                 "channel": 1, "signal": -50, "encryption": "WPA2"}
            ]
        }))

        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps({
            "findings": [
                {"id": "X-1", "name": "Issue", "severity": "Medium",
                 "affected_target": "aa:bb:cc:dd:ee:ff", "description": "desc"}
            ]
        }))

        generator.load_results([str(scan_file), str(findings_file)])

        types = [s["type"] for s in generator.sections]
        assert "scan_results" in types
        assert "vulnerability_findings" in types

    def test_load_results_skips_non_json(self, generator, tmp_path):
        pcap_file = tmp_path / "capture.pcap"
        pcap_file.write_bytes(b"\x00\x00")
        generator.load_results([str(pcap_file)])
        assert generator.sections == []


class TestSummary:
    def test_get_summary(self, generator, sample_findings):
        generator.add_section("Intro", "Narrative")
        generator.add_vulnerability_findings(sample_findings)
        summary = generator.get_summary()
        assert summary["section_count"] == 2
        assert summary["finding_count"] == 2
        assert summary["severity_counts"]["High"] == 1
        assert summary["severity_counts"]["Critical"] == 1
        assert summary["title"] == generator.title
        assert summary["author"] == generator.author


class TestCLI:
    def test_cli_format_choices(self):
        assert set(SUPPORTED_FORMATS) == {"html", "pdf", "json", "all"}
        with pytest.raises(SystemExit):
            with patch.object(sys, "argv", ["reporting.py", "-f", "bogus"]):
                main()

    def test_cli_load_glob(self, tmp_path, monkeypatch):
        reports_dir = tmp_path / "reports"
        file1 = tmp_path / "scan1.json"
        file1.write_text(json.dumps({"access_points": []}))
        file2 = tmp_path / "scan2.json"
        file2.write_text(json.dumps({"access_points": []}))

        monkeypatch.chdir(tmp_path)

        test_args = [
            "reporting.py",
            "-o", str(reports_dir),
            "-f", "json",
            "--load", "scan*.json",
        ]
        with patch.object(sys, "argv", test_args):
            with patch("reporting.ReportGenerator.load_results") as mock_load:
                main()
        called_files = mock_load.call_args[0][0]
        assert str(file1) in called_files or file1.name in [os.path.basename(p) for p in called_files]
        assert len(called_files) == 2
