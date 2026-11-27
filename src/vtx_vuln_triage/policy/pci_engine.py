from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import yaml

from vtx_vuln_triage.assets import AssetContext
from vtx_vuln_triage.models import (
    AssetCriticality,
    EnrichedVulnerability,
    Priority,
    TriageDecision,
)

PRIORITY_LEVELS = (Priority.P0, Priority.P1, Priority.P2, Priority.P3)

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

    @staticmethod
    def _apply_asset_context(
        base_priority: Priority,
        asset_context: AssetContext,
        pci_in_scope: bool,
        in_cisa_kev: bool,
    ) -> tuple[Priority, int, str]:
        base_index = PRIORITY_ORDER[base_priority]

        is_high_exposure_prod = (
            asset_context.environment == "prod"
            and asset_context.exposure == "internet"
            and asset_context.criticality in ("critical", "high")
        )
        is_isolated_dev = (
            asset_context.environment == "dev"
            and asset_context.exposure == "internal"
            and asset_context.criticality in ("low", "medium")
        )

        if is_high_exposure_prod:
            new_index = max(0, base_index - 1)
            new_priority = PRIORITY_LEVELS[new_index]
            delta = new_index - base_index
            if delta < 0:
                note = (
                    f"Prioridade elevada ({base_priority.value} -> {new_priority.value}) "
                    f"pelo ativo '{asset_context.asset_id}' "
                    f"({asset_context.environment}/{asset_context.exposure}/{asset_context.criticality})."
                )
            else:
                note = (
                    f"Ativo '{asset_context.asset_id}' em produção exposta à internet "
                    f"reforça prioridade máxima {new_priority.value}."
                )
            return new_priority, delta, note

        if is_isolated_dev:
            if base_priority == Priority.P0 and in_cisa_kev and pci_in_scope:
                return (
                    base_priority,
                    0,
                    f"Guardrail ativo: KEV em escopo PCI-DSS mantém {base_priority.value} "
                    f"mesmo em '{asset_context.asset_id}' (dev/internal).",
                )
            new_index = min(len(PRIORITY_LEVELS) - 1, base_index + 1)
            new_priority = PRIORITY_LEVELS[new_index]
            delta = new_index - base_index
            if delta > 0:
                note = (
                    f"Prioridade reduzida ({base_priority.value} -> {new_priority.value}) "
                    f"pelo ativo '{asset_context.asset_id}' "
                    f"({asset_context.environment}/{asset_context.exposure}/{asset_context.criticality})."
                )
            else:
                note = (
                    f"Ativo '{asset_context.asset_id}' isolado em dev mantém piso {new_priority.value}."
                )
            return new_priority, delta, note

        return (
            base_priority,
            0,
            f"Contexto do ativo '{asset_context.asset_id}' "
            f"({asset_context.environment}/{asset_context.exposure}/{asset_context.criticality}) "
            f"manteve prioridade {base_priority.value}.",
        )

    def evaluate(
        self,
        vuln: EnrichedVulnerability,
        asset_criticality: AssetCriticality = AssetCriticality.STANDARD,
        asset_context: Optional[AssetContext] = None,
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

        # Regras determinísticas base (P0 -> P3)
        if vuln.in_cisa_kev and pci_in_scope:
            base_priority = Priority.P0
            rationale.append("Classificado como P0: vulnerabilidade explorada ativamente em escopo PCI-DSS.")
        elif (
            vuln.in_cisa_kev
            or cvss >= self.thresholds["critical_cvss"]
            or epss >= self.thresholds["high_epss"]
        ):
            base_priority = Priority.P1
            rationale.append("Classificado como P1: alto risco de exploração ou severidade crítica.")
        elif cvss >= self.thresholds["high_cvss"] or epss >= self.thresholds["medium_epss"]:
            base_priority = Priority.P2
            rationale.append("Classificado como P2: risco elevado dentro da janela padrão PCI-DSS Req. 6.3.3.")
        else:
            base_priority = Priority.P3
            rationale.append("Classificado como P3: risco baixo/moderado sem evidência de exploração ativa.")

        priority = base_priority
        asset_adjustment = 0
        asset_id: Optional[str] = None
        asset_owner: Optional[str] = None

        if asset_context is not None:
            asset_id = asset_context.asset_id
            asset_owner = asset_context.owner
            priority, asset_adjustment, note = self._apply_asset_context(
                base_priority=base_priority,
                asset_context=asset_context,
                pci_in_scope=pci_in_scope,
                in_cisa_kev=vuln.in_cisa_kev,
            )
            rationale.append(note)

        return TriageDecision(
            vulnerability=vuln,
            asset_criticality=asset_criticality,
            priority=priority,
            sla_days=int(self.sla_days[priority.value]),
            rationale=rationale,
            pci_dss_in_scope=pci_in_scope,
            asset_id=asset_id,
            asset_owner=asset_owner,
            base_priority=base_priority,
            asset_adjustment=asset_adjustment,
        )

    def evaluate_batch(
        self,
        vulns: list[EnrichedVulnerability],
        asset_criticality: AssetCriticality = AssetCriticality.STANDARD,
        asset_context: Optional[AssetContext] = None,
    ) -> list[TriageDecision]:
        decisions = [
            self.evaluate(
                v,
                asset_criticality=asset_criticality,
                asset_context=asset_context,
            )
            for v in vulns
        ]
        return sorted(
            decisions,
            key=lambda d: (
                PRIORITY_ORDER[d.priority],
                not d.vulnerability.in_cisa_kev,
                -(d.vulnerability.epss_score or 0.0),
                -(d.vulnerability.cvss_score or 0.0),
            ),
        )
