from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from vtx_vuln_triage.models import (
    AssetCriticality,
    EnrichedVulnerability,
    Priority,
    TriageDecision,
)

PRIORITY_ORDER = {
    Priority.P0: 0,
    Priority.P1: 1,
    Priority.P2: 2,
    Priority.P3: 3,
}


class PciPolicyEngine:
    """Motor determinístico de priorização de vulnerabilidades alinhado a PCI-DSS."""

    def __init__(self, policy_path: str | Path = "config/pci_policy.yaml") -> None:
        self.policy_path = Path(policy_path)
        if not self.policy_path.exists():
            raise FileNotFoundError(f"Arquivo de política não encontrado: {self.policy_path}")

        with self.policy_path.open("r", encoding="utf-8") as file:
            self.policy: dict[str, Any] = yaml.safe_load(file)

        self.sla_days: dict[str, int] = self.policy["sla_days"]
        self.thresholds: dict[str, float] = self.policy["thresholds"]
        self.compliance_references: dict[str, str] = self.policy.get("compliance_references", {})

    def evaluate(
        self,
        vuln: EnrichedVulnerability,
        asset_criticality: AssetCriticality = AssetCriticality.STANDARD,
    ) -> TriageDecision:
        pci_in_scope = asset_criticality in (AssetCriticality.CDE, AssetCriticality.CONNECTED)
        cvss = vuln.cvss_score or 0.0
        epss = vuln.epss_score or 0.0
        rationale: list[str] = []

        if vuln.in_cisa_kev:
            rationale.append("Exploração ativa confirmada na base CISA KEV.")
        if pci_in_scope:
            rationale.append(f"Ativo em escopo PCI-DSS ({asset_criticality.value}).")
        if vuln.cvss_score is not None:
            rationale.append(f"CVSS base: {vuln.cvss_score:.1f}.")
        if vuln.epss_score is not None:
            rationale.append(f"Probabilidade de exploração (EPSS): {vuln.epss_score * 100:.1f}%.")

        # Regras determinísticas de classificação (P0 -> P3)
        if vuln.in_cisa_kev and pci_in_scope:
            priority = Priority.P0
            rationale.append("Classificado como P0: vulnerabilidade explorada ativamente em escopo PCI-DSS.")
        elif (
            vuln.in_cisa_kev
            or cvss >= self.thresholds["critical_cvss"]
            or epss >= self.thresholds["high_epss"]
        ):
            priority = Priority.P1
            rationale.append("Classificado como P1: alto risco de exploração ou severidade crítica.")
        elif cvss >= self.thresholds["high_cvss"] or epss >= self.thresholds["medium_epss"]:
            priority = Priority.P2
            rationale.append("Classificado como P2: risco elevado dentro da janela padrão PCI-DSS Req. 6.3.3.")
        else:
            priority = Priority.P3
            rationale.append("Classificado como P3: risco baixo/moderado sem evidência de exploração ativa.")

        return TriageDecision(
            vulnerability=vuln,
            asset_criticality=asset_criticality,
            priority=priority,
            sla_days=int(self.sla_days[priority.value]),
            rationale=rationale,
            pci_dss_in_scope=pci_in_scope,
        )

    def evaluate_batch(
        self,
        vulns: list[EnrichedVulnerability],
        asset_criticality: AssetCriticality = AssetCriticality.STANDARD,
    ) -> list[TriageDecision]:
        decisions = [self.evaluate(v, asset_criticality=asset_criticality) for v in vulns]
        return sorted(
            decisions,
            key=lambda d: (
                PRIORITY_ORDER[d.priority],
                not d.vulnerability.in_cisa_kev,
                -(d.vulnerability.epss_score or 0.0),
                -(d.vulnerability.cvss_score or 0.0),
            ),
        )
