import json
from pathlib import Path

from typer.testing import CliRunner

from vtx_vuln_triage.assets import UNKNOWN_ASSET_ID
from vtx_vuln_triage.main import app, run_pipeline
from vtx_vuln_triage.models import AssetCriticality, Priority

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_TRIVY = REPO_ROOT / "tests" / "fixtures" / "sample_trivy.json"
EXAMPLES_ASSETS = REPO_ROOT / "examples" / "assets.yaml"
POLICY_FILE = REPO_ROOT / "config" / "pci_policy.yaml"

runner = CliRunner()


def _write_single_high_trivy_report(path: Path) -> Path:
    payload = {
        "SchemaVersion": 2,
        "ArtifactName": "service:1.0.0",
        "Results": [
            {
                "Target": "service:1.0.0 (alpine 3.19)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2025-1000",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.1",
                        "FixedVersion": "3.0.2",
                        "Severity": "HIGH",
                        "Title": "OpenSSL high severity issue",
                        "Description": "Synthetic fixture for asset weighting E2E test",
                        "CVSS": {"nvd": {"V3Score": 7.8}},
                    }
                ],
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_cli_legacy_mode_without_assets_flags(tmp_path: Path) -> None:
    out_file = tmp_path / "legacy_report.md"
    result = runner.invoke(
        app,
        [
            "--input",
            str(SAMPLE_TRIVY),
            "--output",
            str(out_file),
            "--policy",
            str(POLICY_FILE),
            "--offline",
        ],
    )

    assert result.exit_code == 0, result.output
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "## Contexto do Ativo" not in content


def test_cli_with_catalog_and_known_asset_id(tmp_path: Path) -> None:
    out_file = tmp_path / "prod_report.md"
    result = runner.invoke(
        app,
        [
            "--input",
            str(SAMPLE_TRIVY),
            "--output",
            str(out_file),
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
    content = out_file.read_text(encoding="utf-8")
    assert "## Contexto do Ativo" in content
    assert "api-pagamentos-prod" in content
    assert "squad-pagamentos@empresa.local" in content
    assert "Aviso de Inventário" not in content


def test_cli_unknown_asset_id_applies_safe_fallback(tmp_path: Path) -> None:
    out_file = tmp_path / "unknown_asset_report.md"
    result = runner.invoke(
        app,
        [
            "--input",
            str(SAMPLE_TRIVY),
            "--output",
            str(out_file),
            "--policy",
            str(POLICY_FILE),
            "--assets",
            str(EXAMPLES_ASSETS),
            "--asset-id",
            "servico-inexistente",
            "--offline",
        ],
    )

    assert result.exit_code == 0, result.output
    assert UNKNOWN_ASSET_ID in result.output
    content = out_file.read_text(encoding="utf-8")
    assert "Aviso de Inventário" in content
    assert UNKNOWN_ASSET_ID in content


def test_cli_missing_assets_file_applies_safe_fallback(tmp_path: Path) -> None:
    out_file = tmp_path / "missing_catalog_report.md"
    missing_catalog = tmp_path / "does_not_exist.yaml"
    result = runner.invoke(
        app,
        [
            "--input",
            str(SAMPLE_TRIVY),
            "--output",
            str(out_file),
            "--policy",
            str(POLICY_FILE),
            "--assets",
            str(missing_catalog),
            "--asset-id",
            "api-pagamentos-prod",
            "--offline",
        ],
    )

    assert result.exit_code == 0, result.output
    content = out_file.read_text(encoding="utf-8")
    assert "Aviso de Inventário" in content
    assert UNKNOWN_ASSET_ID in content


def test_e2e_run_pipeline_shifts_priority_and_preserves_fallback(tmp_path: Path) -> None:
    trivy_file = _write_single_high_trivy_report(tmp_path / "trivy.json")

    prod_decisions = run_pipeline(
        input_path=trivy_file,
        output_path=tmp_path / "prod.md",
        criticality=AssetCriticality.STANDARD,
        policy_path=POLICY_FILE,
        offline=True,
        assets_path=EXAMPLES_ASSETS,
        asset_id="api-pagamentos-prod",
    )
    dev_decisions = run_pipeline(
        input_path=trivy_file,
        output_path=tmp_path / "dev.md",
        criticality=AssetCriticality.STANDARD,
        policy_path=POLICY_FILE,
        offline=True,
        assets_path=EXAMPLES_ASSETS,
        asset_id="lab-sandbox-dev",
    )
    fallback_decisions = run_pipeline(
        input_path=trivy_file,
        output_path=tmp_path / "fallback.md",
        criticality=AssetCriticality.STANDARD,
        policy_path=POLICY_FILE,
        offline=True,
        assets_path=EXAMPLES_ASSETS,
        asset_id="nao-cadastrado",
    )

    assert prod_decisions[0].priority == Priority.P1
    assert prod_decisions[0].sla_days == 7
    assert prod_decisions[0].asset_id == "api-pagamentos-prod"

    assert dev_decisions[0].priority == Priority.P3
    assert dev_decisions[0].sla_days == 90
    assert dev_decisions[0].asset_id == "lab-sandbox-dev"

    assert fallback_decisions[0].priority == Priority.P2
    assert fallback_decisions[0].sla_days == 30
    assert fallback_decisions[0].asset_id == UNKNOWN_ASSET_ID
    assert fallback_decisions[0].asset_adjustment == 0
