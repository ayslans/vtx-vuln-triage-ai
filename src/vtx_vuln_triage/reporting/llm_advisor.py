from __future__ import annotations

import json
import os
from typing import Optional

import httpx
from pydantic import BaseModel, Field, ValidationError

from vtx_vuln_triage.models import Priority, TriageDecision


class ExecutiveSummary(BaseModel):
    overview: str = Field(..., description="Resumo executivo da postura de risco do ativo")
    immediate_actions: list[str] = Field(default_factory=list)
    generated_by: str = Field(default="deterministic-fallback")


class LlmAdvisor:
    """Gera síntese executiva e plano de ação com saída estruturada e fallback determinístico."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4o-mini",
        api_url: str = "https://api.openai.com/v1/chat/completions",
        timeout: float = 20.0,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.getenv("OPENAI_API_KEY")
        self.model = model
        self.api_url = api_url
        self.timeout = timeout

    def summarize(self, decisions: list[TriageDecision], use_llm: bool = True) -> ExecutiveSummary:
        if not decisions:
            return ExecutiveSummary(
                overview="Nenhuma vulnerabilidade CVE válida foi identificada no relatório analisado.",
                immediate_actions=["Manter monitoramento contínuo conforme CIS Control 7."],
                generated_by="deterministic-fallback",
            )

        if use_llm and self.api_key:
            llm_result = self._call_llm(decisions)
            if llm_result is not None:
                return llm_result

        return self._build_fallback(decisions)

    def _call_llm(self, decisions: list[TriageDecision]) -> Optional[ExecutiveSummary]:
        top_items = [
            {
                "cve_id": d.vulnerability.cve_id,
                "package": d.vulnerability.package_name,
                "priority": d.priority.value,
                "sla_days": d.sla_days,
                "in_cisa_kev": d.vulnerability.in_cisa_kev,
                "cvss": d.vulnerability.cvss_score,
                "epss": d.vulnerability.epss_score,
                "fixed_version": d.vulnerability.fixed_version,
                "pci_in_scope": d.pci_dss_in_scope,
            }
            for d in decisions[:10]
        ]

        prompt = (
            "Você é um analista Blue Team sênior em uma instituição de pagamento (PCI-DSS). "
            "Com base nos achados abaixo, responda EXCLUSIVAMENTE em JSON válido com as chaves: "
            '{"overview": "texto curto objetivo", "immediate_actions": ["ação 1", "ação 2"]}.\n'
            f"Achados: {json.dumps(top_items, ensure_ascii=False)}"
        )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.model,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": "Responda apenas JSON estrito sem markdown."},
                {"role": "user", "content": prompt},
            ],
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(self.api_url, headers=headers, json=body)
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"]
                parsed = json.loads(content)
                return ExecutiveSummary(
                    overview=parsed["overview"],
                    immediate_actions=parsed.get("immediate_actions", []),
                    generated_by=f"llm:{self.model}",
                )
        except (httpx.HTTPError, KeyError, ValueError, ValidationError):
            return None

    def _build_fallback(self, decisions: list[TriageDecision]) -> ExecutiveSummary:
        counts = {p: 0 for p in Priority}
        kev_count = 0
        for d in decisions:
            counts[d.priority] += 1
            if d.vulnerability.in_cisa_kev:
                kev_count += 1

        overview = (
            f"Foram triadas {len(decisions)} vulnerabilidades "
            f"(P0: {counts[Priority.P0]}, P1: {counts[Priority.P1]}, "
            f"P2: {counts[Priority.P2]}, P3: {counts[Priority.P3]}), "
            f"sendo {kev_count} com exploração ativa confirmada na base CISA KEV."
        )

        actions: list[str] = []
        for d in decisions[:3]:
            fix = d.vulnerability.fixed_version or "aplicar mitigação/controle compensatório"
            actions.append(
                f"[{d.priority.value} | SLA {d.sla_days}d] Tratar {d.vulnerability.cve_id} "
                f"no pacote `{d.vulnerability.package_name}` (versão corrigida: {fix})."
            )

        return ExecutiveSummary(
            overview=overview,
            immediate_actions=actions,
            generated_by="deterministic-fallback",
        )
