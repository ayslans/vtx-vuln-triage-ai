from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from vtx_vuln_triage.assets import AssetContext
from vtx_vuln_triage.models import AssetCriticality, Priority, Severity, TriageDecision

CONTRACT_SCHEMA_VERSION = "1.0"


class CaseFindingContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    cve_id: str
    package_name: str
    installed_version: str
    fixed_version: Optional[str] = None
    severity: Severity
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    in_cisa_kev: bool = False
    target: str
    asset_id: Optional[str] = None
    owner: Optional[str] = None
    asset_criticality: AssetCriticality
    pci_dss_in_scope: bool
    priority: Priority
    base_priority: Optional[Priority] = None
    asset_adjustment: int = 0
    sla_days: int = Field(..., gt=0)
    triaged_at: datetime
    sla_due_at: datetime
    rationale: list[str] = Field(default_factory=list)


class TriageSummaryCounts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int = Field(..., ge=0)
    P0: int = Field(..., ge=0)
    P1: int = Field(..., ge=0)
    P2: int = Field(..., ge=0)
    P3: int = Field(..., ge=0)
    pci_in_scope_count: int = Field(..., ge=0)


class TriageJsonReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = CONTRACT_SCHEMA_VERSION
    source: Literal["vtx-vuln-triage-ai"] = "vtx-vuln-triage-ai"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    asset: Optional[AssetContext] = None
    asset_warning: Optional[str] = None
    summary: TriageSummaryCounts
    findings: list[CaseFindingContract] = Field(default_factory=list)


def compute_finding_id(decision: TriageDecision) -> str:
    """Gera identificador determinístico para deduplicação no Gestor de Casos."""
    v = decision.vulnerability
    raw_key = "|".join(
        [
            decision.asset_id or "unassigned",
            v.cve_id,
            v.package_name,
            v.installed_version,
            v.target,
        ]
    )
    digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]
    return f"vtx-vuln-{digest}"


def build_triage_json_report(
    decisions: list[TriageDecision],
    asset_context: Optional[AssetContext] = None,
    asset_warning: Optional[str] = None,
) -> TriageJsonReport:
    counts = {p: sum(1 for d in decisions if d.priority == p) for p in Priority}
    findings: list[CaseFindingContract] = []

    for d in decisions:
        v = d.vulnerability
        sla_due_at = d.sla_due_at or (d.triaged_at + timedelta(days=d.sla_days))
        findings.append(
            CaseFindingContract(
                finding_id=compute_finding_id(d),
                cve_id=v.cve_id,
                package_name=v.package_name,
                installed_version=v.installed_version,
                fixed_version=v.fixed_version,
                severity=v.severity,
                cvss_score=v.cvss_score,
                epss_score=v.epss_score,
                in_cisa_kev=v.in_cisa_kev,
                target=v.target,
                asset_id=d.asset_id,
                owner=d.asset_owner,
                asset_criticality=d.asset_criticality,
                pci_dss_in_scope=d.pci_dss_in_scope,
                priority=d.priority,
                base_priority=d.base_priority,
                asset_adjustment=d.asset_adjustment,
                sla_days=d.sla_days,
                triaged_at=d.triaged_at,
                sla_due_at=sla_due_at,
                rationale=list(d.rationale),
            )
        )

    summary = TriageSummaryCounts(
        total=len(decisions),
        P0=counts[Priority.P0],
        P1=counts[Priority.P1],
        P2=counts[Priority.P2],
        P3=counts[Priority.P3],
        pci_in_scope_count=sum(1 for d in decisions if d.pci_dss_in_scope),
    )

    return TriageJsonReport(
        asset=asset_context,
        asset_warning=asset_warning,
        summary=summary,
        findings=findings,
    )


def export_triage_json(
    output_path: str | Path,
    decisions: list[TriageDecision],
    asset_context: Optional[AssetContext] = None,
    asset_warning: Optional[str] = None,
) -> TriageJsonReport:
    report = build_triage_json_report(
        decisions=decisions,
        asset_context=asset_context,
        asset_warning=asset_warning,
    )
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return report
