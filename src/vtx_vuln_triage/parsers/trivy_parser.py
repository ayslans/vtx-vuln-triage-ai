from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from pydantic import ValidationError

from vtx_vuln_triage.models import RawVulnerability, Severity


def _extract_cvss_score(vuln_data: dict[str, Any]) -> Optional[float]:
    """Extrai o score CVSS v3 (ou v2 como fallback), priorizando a fonte NVD."""
    cvss_map = vuln_data.get("CVSS")
    if not isinstance(cvss_map, dict) or not cvss_map:
        return None

    # Prioridade: nvd -> qualquer outra fonte disponível
    ordered_sources = ["nvd"] + [k for k in cvss_map.keys() if k != "nvd"]

    for source in ordered_sources:
        metrics = cvss_map.get(source)
        if not isinstance(metrics, dict):
            continue
        for key in ("V3Score", "V2Score"):
            score = metrics.get(key)
            if isinstance(score, (int, float)):
                return float(score)

    return None


def _parse_severity(raw_severity: Optional[str]) -> Severity:
    if not raw_severity:
        return Severity.UNKNOWN
    try:
        return Severity(raw_severity.strip().upper())
    except ValueError:
        return Severity.UNKNOWN


def parse_trivy_report(report_path: str | Path) -> list[RawVulnerability]:
    """Lê um relatório JSON do Trivy e retorna vulnerabilidades normalizadas e deduplicadas."""
    path = Path(report_path)
    if not path.exists():
        raise FileNotFoundError(f"Relatório Trivy não encontrado: {path}")

    with path.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    results = payload.get("Results", [])
    if not isinstance(results, list):
        return []

    vulnerabilities: list[RawVulnerability] = []
    seen_keys: set[tuple[str, str, str, str]] = set()

    for result in results:
        target = result.get("Target") or payload.get("ArtifactName") or "unknown-target"
        raw_vulns = result.get("Vulnerabilities") or []

        for item in raw_vulns:
            cve_id = item.get("VulnerabilityID", "")
            package_name = item.get("PkgName", "unknown-package")
            installed_version = item.get("InstalledVersion", "unknown")
            fixed_version = item.get("FixedVersion") or None

            try:
                vuln = RawVulnerability(
                    cve_id=cve_id,
                    package_name=package_name,
                    installed_version=installed_version,
                    fixed_version=fixed_version,
                    severity=_parse_severity(item.get("Severity")),
                    cvss_score=_extract_cvss_score(item),
                    title=item.get("Title"),
                    description=item.get("Description"),
                    target=target,
                )
            except ValidationError:
                # Ignora entradas que não são CVEs válidos (ex: GHSA sem mapeamento CVE)
                continue

            dedup_key = (vuln.cve_id, vuln.package_name, vuln.installed_version, vuln.target)
            if dedup_key in seen_keys:
                continue

            seen_keys.add(dedup_key)
            vulnerabilities.append(vuln)

    return vulnerabilities
