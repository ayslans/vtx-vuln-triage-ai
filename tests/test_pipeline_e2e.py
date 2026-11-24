from pathlib import Path

from vtx_vuln_triage.main import run_pipeline
from vtx_vuln_triage.models import AssetCriticality, Priority

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_trivy.json"


def test_run_pipeline_offline_generates_markdown_report(tmp_path):
    output_file = tmp_path / "report.md"

    decisions = run_pipeline(
        input_path=FIXTURE_PATH,
        output_path=output_file,
        criticality=AssetCriticality.CDE,
        policy_path="config/pci_policy.yaml",
        offline=True,
    )

    assert len(decisions) == 2
    assert decisions[0].vulnerability.cve_id == "CVE-2024-3094"
    assert decisions[0].priority == Priority.P1
    assert output_file.exists()

    content = output_file.read_text(encoding="utf-8")
    assert "# Boletim de Triagem de Vulnerabilidades" in content
    assert "CVE-2024-3094" in content
    assert "CVE-2023-44487" in content
    assert "PCI_DSS" in content
