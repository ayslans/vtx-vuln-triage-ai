from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from vtx_vuln_triage.enrichers.cisa_kev import CisaKevClient
from vtx_vuln_triage.enrichers.epss_client import EpssClient
from vtx_vuln_triage.models import AssetCriticality, EnrichedVulnerability, TriageDecision
from vtx_vuln_triage.parsers.trivy_parser import parse_trivy_report
from vtx_vuln_triage.policy.pci_engine import PciPolicyEngine
from vtx_vuln_triage.reporting.llm_advisor import LlmAdvisor
from vtx_vuln_triage.reporting.markdown_renderer import render_markdown_report

app = typer.Typer(help="CLI de triagem de vulnerabilidades (Trivy + KEV + EPSS + PCI-DSS + IA).")
console = Console()


def run_pipeline(
    input_path: str | Path,
    output_path: str | Path,
    criticality: AssetCriticality = AssetCriticality.CDE,
    policy_path: str | Path = "config/pci_policy.yaml",
    offline: bool = False,
    use_llm: bool = True,
) -> list[TriageDecision]:
    raw_vulns = parse_trivy_report(input_path)
    cve_ids = [v.cve_id for v in raw_vulns]

    if offline:
        kev_map = {}
        epss_map = {}
    else:
        kev_map = CisaKevClient().lookup(cve_ids)
        epss_map = EpssClient().lookup(cve_ids)

    enriched: list[EnrichedVulnerability] = []
    for vuln in raw_vulns:
        kev_info = kev_map.get(vuln.cve_id)
        epss_info = epss_map.get(vuln.cve_id)
        enriched.append(
            EnrichedVulnerability(
                **vuln.model_dump(),
                in_cisa_kev=kev_info is not None,
                kev_date_added=kev_info.get("date_added") if kev_info else None,
                kev_due_date=kev_info.get("due_date") if kev_info else None,
                epss_score=epss_info.get("epss") if epss_info else None,
                epss_percentile=epss_info.get("percentile") if epss_info else None,
            )
        )

    engine = PciPolicyEngine(policy_path=policy_path)
    decisions = engine.evaluate_batch(enriched, asset_criticality=criticality)

    advisor = LlmAdvisor()
    summary = advisor.summarize(decisions, use_llm=(use_llm and not offline))

    markdown = render_markdown_report(
        decisions=decisions,
        summary=summary,
        compliance_references=engine.compliance_references,
    )

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(markdown, encoding="utf-8")
    return decisions


@app.command()
def triage(
    input_file: Path = typer.Option(..., "--input", "-i", help="Caminho do JSON gerado pelo Trivy"),
    output_file: Path = typer.Option(
        Path("data/reports/triage_report.md"),
        "--output",
        "-o",
        help="Caminho do relatório Markdown de saída",
    ),
    criticality: AssetCriticality = typer.Option(
        AssetCriticality.CDE,
        "--criticality",
        "-c",
        help="Criticidade do ativo (CDE, CONNECTED, STANDARD)",
    ),
    policy: Path = typer.Option(
        Path("config/pci_policy.yaml"),
        "--policy",
        "-p",
        help="Caminho do arquivo YAML de política",
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Executa sem consultar APIs externas (CISA KEV, EPSS e LLM)",
    ),
) -> None:
    decisions = run_pipeline(
        input_path=input_file,
        output_path=output_file,
        criticality=criticality,
        policy_path=policy,
        offline=offline,
    )
    console.print(f"[green]Triagem concluída:[/green] {len(decisions)} achados salvos em {output_file}")


if __name__ == "__main__":
    app()
