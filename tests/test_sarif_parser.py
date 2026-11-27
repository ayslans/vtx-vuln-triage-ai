import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vtx_vuln_triage.main import app
from vtx_vuln_triage.models import Priority, Severity
from vtx_vuln_triage.parsers.auto_parser import (
    InputFormat,
    detect_report_format,
    parse_security_report,
)
from vtx_vuln_triage.parsers.sarif_parser import parse_sarif_payload
from vtx_vuln_triage.reporting.json_exporter import TriageJsonReport

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_TRIVY = REPO_ROOT / "tests" / "fixtures" / "sample_trivy.json"
EXAMPLES_ASSETS = REPO_ROOT / "examples" / "assets.yaml"
POLICY_FILE = REPO_ROOT / "config" / "pci_policy.yaml"

runner = CliRunner()


def _trivy_sarif_fixture() -> dict:
    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Trivy",
                        "rules": [
                            {
                                "id": "CVE-2025-4321",
                                "shortDescription": {"text": "Critical RCE in openssl"},
                                "properties": {"security-severity": "9.8", "tags": ["vulnerability"]},
                            },
                            {
                                "id": "AVD-DS-0002",
                                "shortDescription": {"text": "Container running as root"},
                                "properties": {"security-severity": "7.5", "tags": ["misconfiguration"]},
                            },
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "CVE-2025-4321",
                        "level": "error",
                        "message": {
                            "text": "Package: openssl\nInstalled Version: 3.0.1\nFixed Version: 3.0.9"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "requirements.txt"}
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "AVD-DS-0002",
                        "level": "error",
                        "message": {"text": "Specify at least 1 USER command in Dockerfile"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "Dockerfile"},
                                    "region": {"startLine": 12},
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    }


def _bandit_sarif_fixture() -> dict:
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Bandit",
                        "rules": [
                            {
                                "id": "B602",
                                "name": "subprocess_popen_with_shell_equals_true",
                                "shortDescription": {"text": "subprocess call with shell=True"},
                                "properties": {"issue_severity": "HIGH"},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "B602",
                        "level": "error",
                        "message": {"text": "subprocess call with shell=True identified."},
                        "properties": {"issue_severity": "HIGH"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/runner.py"},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def _semgrep_sarif_fixture() -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep OSS",
                        "rules": [
                            {
                                "id": "python.lang.security.audit.formatted-sql-query",
                                "shortDescription": {"text": "Possible SQL injection via f-string"},
                                "properties": {"security-severity": "8.6", "tags": ["security"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "python.lang.security.audit.formatted-sql-query",
                        "level": "error",
                        "message": {"text": "Detected possible formatted SQL query."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/db/queries.py"},
                                    "region": {"startLine": 19},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_parse_trivy_sarif_cve_and_iac() -> None:
    findings = parse_sarif_payload(_trivy_sarif_fixture())
    assert len(findings) == 2

    cve_item, iac_item = findings
    assert cve_item.source_scanner == "trivy"
    assert cve_item.finding_type == "cve"
    assert cve_item.cve_id == "CVE-2025-4321"
    assert cve_item.package_name == "openssl"
    assert cve_item.installed_version == "3.0.1"
    assert cve_item.fixed_version == "3.0.9"
    assert cve_item.severity == Severity.CRITICAL
    assert cve_item.cvss_score == 9.8

    assert iac_item.source_scanner == "trivy"
    assert iac_item.finding_type == "iac"
    assert iac_item.cve_id == "AVD-DS-0002"
    assert iac_item.target == "Dockerfile:12"
    assert iac_item.severity == Severity.HIGH
    assert iac_item.cvss_score == 7.5


def test_parse_bandit_sarif_maps_sast_finding() -> None:
    findings = parse_sarif_payload(_bandit_sarif_fixture())
    assert len(findings) == 1

    item = findings[0]
    assert item.source_scanner == "bandit"
    assert item.finding_type == "sast"
    assert item.cve_id == "B602"
    assert item.severity == Severity.HIGH
    assert item.cvss_score == 7.5
    assert item.target == "src/runner.py:42"
    assert item.package_name == "src/runner.py"


def test_parse_semgrep_sarif_maps_sast_finding() -> None:
    findings = parse_sarif_payload(_semgrep_sarif_fixture())
    assert len(findings) == 1

    item = findings[0]
    assert item.source_scanner == "semgrep"
    assert item.finding_type == "sast"
    assert item.cve_id == "python.lang.security.audit.formatted-sql-query"
    assert item.severity == Severity.HIGH
    assert item.cvss_score == 8.6
    assert item.target == "src/db/queries.py:19"


def test_parse_empty_sarif_returns_empty_list() -> None:
    empty_sarif = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Trivy", "rules": []}}, "results": []}],
    }
    assert parse_sarif_payload(empty_sarif) == []


def test_auto_format_detection_handles_trivy_sarif_and_invalid(tmp_path: Path) -> None:
    trivy_data = json.loads(SAMPLE_TRIVY.read_text(encoding="utf-8"))
    assert detect_report_format(trivy_data) == InputFormat.TRIVY
    assert detect_report_format(_semgrep_sarif_fixture()) == InputFormat.SARIF

    with pytest.raises(ValueError, match="Formato de relatório não reconhecido"):
        detect_report_format({"unexpected": True})

    sarif_file = tmp_path / "bandit.sarif"
    sarif_file.write_text(json.dumps(_bandit_sarif_fixture()), encoding="utf-8")
    parsed = parse_security_report(sarif_file, input_format=InputFormat.AUTO)
    assert len(parsed) == 1
    assert parsed[0].source_scanner == "bandit"


def test_cli_e2e_sarif_with_asset_weighting_and_json_contract(tmp_path: Path) -> None:
    sarif_in = tmp_path / "multi.sarif"
    combined = {
        "version": "2.1.0",
        "runs": [
            _bandit_sarif_fixture()["runs"][0],
            _semgrep_sarif_fixture()["runs"][0],
        ],
    }
    sarif_in.write_text(json.dumps(combined), encoding="utf-8")

    md_out = tmp_path / "sarif_report.md"
    json_out = tmp_path / "sarif_cases.json"

    result = runner.invoke(
        app,
        [
            "--input",
            str(sarif_in),
            "--output",
            str(md_out),
            "--json-output",
            str(json_out),
            "--policy",
            str(POLICY_FILE),
            "--criticality",
            "STANDARD",
            "--assets",
            str(EXAMPLES_ASSETS),
            "--asset-id",
            "api-pagamentos-prod",
            "--offline",
        ],
    )

    assert result.exit_code == 0, result.output
    report = TriageJsonReport.model_validate_json(json_out.read_text(encoding="utf-8"))
    assert report.summary.total == 2
    assert {f.source_scanner for f in report.findings} == {"bandit", "semgrep"}
    assert all(f.finding_type == "sast" for f in report.findings)
    # Ambos HIGH (base P2) sobem para P1 em prod/internet/critical
    assert all(f.priority == Priority.P1 for f in report.findings)
    assert all(f.sla_days == 7 for f in report.findings)
