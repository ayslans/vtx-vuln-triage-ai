import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from typer.testing import CliRunner

from vtx_vuln_triage.assets import UNKNOWN_ASSET_ID
from vtx_vuln_triage.main import app
from vtx_vuln_triage.models import (
    AssetCriticality,
    EnrichedVulnerability,
    Priority,
    Severity,
    TriageDecision,
)
from vtx_vuln_triage.reporting.json_exporter import (
    CONTRACT_SCHEMA_VERSION,
    TriageJsonReport,
    compute_finding_id,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_TRIVY = REPO_ROOT / "tests" / "fixtures" / "sample_trivy.json"
EXAMPLES_ASSETS = REPO_ROOT / "examples" / "assets.yaml"
POLICY_FILE = REPO_ROOT / "config" / "pci_policy.yaml"

runner = CliRunner()


def test_triage_decision_auto_computes_sla_due_at_in_utc() -> None:
    fixed_ts = datetime(2026, 11, 27, 12, 0, 0, tzinfo=timezone.utc)
    vuln = EnrichedVulnerability(
        cve_id="CVE-2025-9999",
        package_name="openssl",
        installed_version="3.0.1",
        severity=Severity.HIGH,
        cvss_score=7.5,
        target="api:1.0.0",
    )
    decision = TriageDecision(
        vulnerability=vuln,
        asset_criticality=AssetCriticality.CDE,
        priority=Priority.P1,
        sla_days=7,
        triaged_at=fixed_ts,
    )

    assert decision.sla_due_at == fixed_ts + timedelta(days=7)
    dumped = decision.model_dump(mode="json")
    assert dumped["sla_due_at"].startswith("2026-12-04T12:00:00")


def test_finding_id_is_deterministic_for_case_deduplication() -> None:
    vuln = EnrichedVulnerability(
        cve_id="CVE-2025-2000",
        package_name="requests",
        installed_version="2.31.0",
        severity=Severity.MEDIUM,
        target="app:1.0",
    )
    d1 = TriageDecision(
        vulnerability=vuln,
        asset_criticality=AssetCriticality.STANDARD,
        priority=Priority.P3,
        sla_days=90,
        asset_id="api-pagamentos-prod",
    )
    d2 = TriageDecision(
        vulnerability=vuln,
        asset_criticality=AssetCriticality.STANDARD,
        priority=Priority.P2,
        sla_days=30,
        asset_id="api-pagamentos-prod",
    )

    id1 = compute_finding_id(d1)
    id2 = compute_finding_id(d2)
    assert id1 == id2
    assert id1.startswith("vtx-vuln-")
    assert len(id1) == len("vtx-vuln-") + 16


def test_cli_json_output_matches_case_manager_contract(tmp_path: Path) -> None:
    md_out = tmp_path / "report.md"
    json_out = tmp_path / "triage_cases.json"

    result = runner.invoke(
        app,
        [
            "--input",
            str(SAMPLE_TRIVY),
            "--output",
            str(md_out),
            "--json-output",
            str(json_out),
            "--policy",
            str(POLICY_FILE),
            "--criticality",
            "CDE",
            "--assets",
            str(EXAMPLES_ASSETS),
            "--asset-id",
            "api-pagamentos-prod",
            "--offline",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json_out.exists()

    raw_payload = json.loads(json_out.read_text(encoding="utf-8"))
    validated = TriageJsonReport.model_validate(raw_payload)

    assert validated.schema_version == CONTRACT_SCHEMA_VERSION
    assert validated.source == "vtx-vuln-triage-ai"
    assert validated.asset is not None
    assert validated.asset.asset_id == "api-pagamentos-prod"
    assert validated.asset_warning is None
    assert validated.summary.total == len(validated.findings)
    assert validated.summary.total > 0

    for finding in validated.findings:
        assert finding.asset_id == "api-pagamentos-prod"
        assert finding.owner == "squad-pagamentos@empresa.local"
        assert finding.sla_due_at == finding.triaged_at + timedelta(days=finding.sla_days)
        assert finding.finding_id.startswith("vtx-vuln-")

    # Garante formato ISO-8601 parseável no JSON bruto
    first_raw = raw_payload["findings"][0]
    parsed_triaged = datetime.fromisoformat(first_raw["triaged_at"].replace("Z", "+00:00"))
    parsed_due = datetime.fromisoformat(first_raw["sla_due_at"].replace("Z", "+00:00"))
    assert parsed_due - parsed_triaged == timedelta(days=first_raw["sla_days"])


def test_cli_json_output_records_fallback_warning_when_asset_missing(tmp_path: Path) -> None:
    md_out = tmp_path / "fallback.md"
    json_out = tmp_path / "fallback.json"

    result = runner.invoke(
        app,
        [
            "--input",
            str(SAMPLE_TRIVY),
            "--output",
            str(md_out),
            "--json-output",
            str(json_out),
            "--policy",
            str(POLICY_FILE),
            "--assets",
            str(EXAMPLES_ASSETS),
            "--asset-id",
            "ativo-nao-existe",
            "--offline",
        ],
    )

    assert result.exit_code == 0, result.output
    validated = TriageJsonReport.model_validate_json(json_out.read_text(encoding="utf-8"))
    assert validated.asset is not None
    assert validated.asset.asset_id == UNKNOWN_ASSET_ID
    assert validated.asset_warning is not None
    assert all(f.asset_id == UNKNOWN_ASSET_ID for f in validated.findings)
