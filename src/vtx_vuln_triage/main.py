from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from vtx_vuln_triage.assets import AssetContext, resolve_asset_context
from vtx_vuln_triage.enrichers.cisa_kev import CisaKevClient
from vtx_vuln_triage.enrichers.epss_client import EpssClient
from vtx_vuln_triage.models import AssetCriticality, EnrichedVulnerability, TriageDecision
from vtx_vuln_triage.parsers.trivy_parser import parse_trivy_report
from vtx_vuln_triage.policy.pci_engine import PciPolicyEngine
from vtx_vuln_triage.reporting.llm_advisor import LlmAdvisor
from vtx_vuln_triage.reporting.markdown_renderer import render_markdown_report

app = typer.Typer(help="CLI de triagem de vulnerabilidades (Trivy + KEV + EPSS + PCI-DSS + IA).")
console = Console()


def _append_asset_context_section(
    markdown: str,
    asset_context: Optional[AssetContext],
    asset_warning: Optional[str],
) -> str:
    if asset_context is None and asset_warning is None:
        return markdown

    lines = ["", "---", "", "## Contexto do Ativo", ""]
    if asset_warning:
        lines.append(f"> **Aviso de Inventário:** {asset_warning}")
        lines.append("")
    if asset_context is not None:
        tags_str = ", ".join(asset_context.tags) if asset_context.tags else "N/A"
        lines.extend(
            [
                f"- **Asset ID:** `{asset_context.asset_id}`",
                f"- **Nome:** {asset_context.name}",
                f"- **Responsável:** `{asset_context.owner}`",
                f"- **Ambiente / Exposição / Criticidade:** "
                f"`{asset_context.environment}` / `{asset_context.exposure}` / `{asset_context.criticality}`",
                f"- **Tags:** {tags_str}",
            ]
        )
    return markdown.rstrip() + "\n" + "\n".join(lines) + "\n"


def run_pipeline(
    input_path: str | Path,
    output_path: str | Path,
    criticality: AssetCriticality = AssetCriticality.CDE,
    policy_path: str | Path = "config/pci_policy.yaml",
    offline: bool = False,
    use_llm: bool = True,
    assets_path: Optional[str | Path] = None,
    asset_id: Optional[str] = None,
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

    asset_context, asset_warning = resolve_asset_context(
        assets_path=assets_path,
        asset_id=asset_id,
    )
    if asset_warning:
        console.print(f"[yellow]Aviso:[/yellow] {asset_warning}")

    engine = PciPolicyEngine(policy_path=policy_path)
    decisions = engine.evaluate_batch(
        enriched,
        asset_criticality=criticality,
        asset_context=asset_context,
    )

    advisor = LlmAdvisor()
    summary = advisor.summarize(decisions, use_llm=(use_llm and not offline))

    markdown = render_markdown_report(
        decisions=decisions,
        summary=summary,
        compliance_references=engine.compliance_references,
    )
    markdown = _append_asset_context_section(
        markdown=markdown,
        asset_context=asset_context,
        asset_warning=asset_warning,
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
    assets: Optional[Path] = typer.Option(
        None,
        "--assets",
        "-a",
        help="Caminho do catálogo YAML de ativos (ex: examples/assets.yaml)",
    ),
    asset_id: Optional[str] = typer.Option(
        None,
        "--asset-id",
        help="Identificador do ativo no catálogo para ajuste contextual de prioridade",
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
        assets_path=assets,
        asset_id=asset_id,
    )
    console.print(f"[green]Triagem concluída:[/green] {len(decisions)} achados salvos em {output_file}")


if __name__ == "__main__":
    app()
