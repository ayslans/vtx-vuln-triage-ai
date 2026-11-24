from __future__ import annotations

from datetime import datetime, timezone

from vtx_vuln_triage.models import Priority, TriageDecision
from vtx_vuln_triage.reporting.llm_advisor import ExecutiveSummary


def render_markdown_report(
    decisions: list[TriageDecision],
    summary: ExecutiveSummary,
    compliance_references: dict[str, str] | None = None,
) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = {p: sum(1 for d in decisions if d.priority == p) for p in Priority}

    lines: list[str] = [
        "# Boletim de Triagem de Vulnerabilidades — vtx-vuln-triage-ai",
        "",
        f"- **Gerado em:** {generated_at}",
        f"- **Total de achados:** {len(decisions)}",
        f"- **Motor de síntese:** `{summary.generated_by}`",
        "",
        "## 1. Resumo Executivo",
        "",
        summary.overview,
        "",
        "### Ações Imediatas Recomendadas",
        "",
    ]

    for action in summary.immediate_actions:
        lines.append(f"- {action}")

    lines.extend(
        [
            "",
            "## 2. Distribuição por Prioridade",
            "",
            "| Prioridade | Quantidade |",
            "| :--- | :---: |",
            f"| **P0 (Crítico / KEV em PCI)** | {counts[Priority.P0]} |",
            f"| **P1 (Alto Risco)** | {counts[Priority.P1]} |",
            f"| **P2 (Moderado/Alto)** | {counts[Priority.P2]} |",
            f"| **P3 (Baixo/Moderado)** | {counts[Priority.P3]} |",
            "",
            "## 3. Achados Priorizados",
            "",
            "| Prioridade | SLA | CVE | Pacote | Instalada -> Correção | CVSS | EPSS | CISA KEV | Escopo PCI |",
            "| :---: | :---: | :--- | :--- | :--- | :---: | :---: | :---: | :---: |",
        ]
    )

    for d in decisions:
        v = d.vulnerability
        cvss_str = f"{v.cvss_score:.1f}" if v.cvss_score is not None else "N/A"
        epss_str = f"{v.epss_score * 100:.1f}%" if v.epss_score is not None else "N/A"
        kev_str = "SIM" if v.in_cisa_kev else "Não"
        pci_str = "SIM" if d.pci_dss_in_scope else "Não"
        fix_str = v.fixed_version or "Sem patch"
        lines.append(
            f"| **{d.priority.value}** | {d.sla_days}d | `{v.cve_id}` | `{v.package_name}` | "
            f"`{v.installed_version}` -> `{fix_str}` | {cvss_str} | {epss_str} | {kev_str} | {pci_str} |"
        )

    if compliance_references:
        lines.extend(
            [
                "",
                "## 4. Mapeamento de Governança e Compliance",
                "",
            ]
        )
        for framework, ref in compliance_references.items():
            lines.append(f"- **{framework.upper()}:** {ref}")

    lines.append("")
    return "\n".join(lines)
