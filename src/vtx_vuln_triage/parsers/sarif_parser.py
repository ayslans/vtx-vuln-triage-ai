from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from vtx_vuln_triage.models import FindingType, RawVulnerability, Severity

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
TRIVY_PKG_REGEX = re.compile(r"Package:\s*([^\n\r]+)", re.IGNORECASE)
TRIVY_INSTALLED_REGEX = re.compile(r"Installed Version:\s*([^\n\r]+)", re.IGNORECASE)
TRIVY_FIXED_REGEX = re.compile(r"Fixed Version:\s*([^\n\r]+)", re.IGNORECASE)

LEVEL_TO_SEVERITY: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.LOW,
}

SEVERITY_FALLBACK_CVSS: dict[Severity, Optional[float]] = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.UNKNOWN: None,
}


def _detect_scanner(driver_name: str) -> str:
    lowered = driver_name.strip().lower()
    if "trivy" in lowered:
        return "trivy"
    if "bandit" in lowered:
        return "bandit"
    if "semgrep" in lowered:
        return "semgrep"
    cleaned = re.sub(r"[^a-z0-9._-]+", "-", lowered).strip("-")
    return cleaned or "sarif"


def _parse_float(value: Any) -> Optional[float]:
    if isinstance(value, (int, float)):
        score = float(value)
    elif isinstance(value, str):
        try:
            score = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    return score if 0.0 <= score <= 10.0 else None


def _severity_from_string(raw: Any) -> Optional[Severity]:
    if not isinstance(raw, str):
        return None
    normalized = raw.strip().upper()
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "ERROR": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "MODERATE": Severity.MEDIUM,
        "WARNING": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.LOW,
        "NOTE": Severity.LOW,
    }
    return mapping.get(normalized)


def _severity_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.UNKNOWN


def _extract_severity_and_cvss(
    result: dict[str, Any],
    rule: dict[str, Any],
) -> tuple[Severity, Optional[float]]:
    result_props = result.get("properties") or {}
    rule_props = rule.get("properties") or {}

    cvss_score = _parse_float(result_props.get("security-severity"))
    if cvss_score is None:
        cvss_score = _parse_float(rule_props.get("security-severity"))

    severity: Optional[Severity] = None
    for candidate in (
        result_props.get("issue_severity"),
        result_props.get("severity"),
        rule_props.get("issue_severity"),
        rule_props.get("problem.severity"),
        rule_props.get("severity"),
        rule_props.get("impact"),
    ):
        severity = _severity_from_string(candidate)
        if severity is not None:
            break

    if severity is None and cvss_score is not None:
        severity = _severity_from_score(cvss_score)

    if severity is None:
        level = str(
            result.get("level")
            or (rule.get("defaultConfiguration") or {}).get("level")
            or ""
        ).lower()
        severity = LEVEL_TO_SEVERITY.get(level, Severity.UNKNOWN)

    if cvss_score is None:
        cvss_score = SEVERITY_FALLBACK_CVSS.get(severity)

    return severity, cvss_score


def _extract_location(result: dict[str, Any], fallback_target: str) -> tuple[str, str]:
    locations = result.get("locations") or []
    if locations and isinstance(locations[0], dict):
        phys = locations[0].get("physicalLocation") or {}
        artifact = phys.get("artifactLocation") or {}
        uri = str(artifact.get("uri") or "").strip()
        region = phys.get("region") or {}
        start_line = region.get("startLine")
        if uri:
            target = f"{uri}:{start_line}" if isinstance(start_line, int) else uri
            return uri, target
    return fallback_target, fallback_target


def _classify_identifier(
    rule_id: str,
    scanner: str,
    tags: list[str],
) -> tuple[str, FindingType]:
    cve_match = CVE_REGEX.search(rule_id)
    if cve_match:
        return cve_match.group(0).upper(), "cve"

    lowered_tags = {t.lower() for t in tags}
    if scanner in ("bandit", "semgrep"):
        return rule_id, "sast"
    if scanner == "trivy":
        if "secret" in lowered_tags or "secret" in rule_id.lower():
            return rule_id, "secret"
        return rule_id, "iac"
    return rule_id, "sarif"


def _extract_package_metadata(
    scanner: str,
    finding_type: FindingType,
    message_text: str,
    uri: str,
    rule_id: str,
) -> tuple[str, str, Optional[str]]:
    if scanner == "trivy" and finding_type == "cve":
        pkg_match = TRIVY_PKG_REGEX.search(message_text)
        inst_match = TRIVY_INSTALLED_REGEX.search(message_text)
        fix_match = TRIVY_FIXED_REGEX.search(message_text)
        pkg = pkg_match.group(1).strip() if pkg_match else (uri or rule_id)
        installed = inst_match.group(1).strip() if inst_match else "N/A"
        fixed = fix_match.group(1).strip() if fix_match else None
        if fixed in ("", "N/A", "none", "None"):
            fixed = None
        return pkg, installed, fixed

    return (uri or rule_id), "N/A", None


def parse_sarif_payload(data: dict[str, Any]) -> list[RawVulnerability]:
    runs = data.get("runs")
    if not isinstance(runs, list):
        raise ValueError("Payload SARIF inválido: campo 'runs' ausente ou não é uma lista.")

    findings: list[RawVulnerability] = []

    for run in runs:
        if not isinstance(run, dict):
            continue
        tool = run.get("tool") or {}
        driver = tool.get("driver") or {}
        driver_name = str(driver.get("name") or "sarif")
        scanner = _detect_scanner(driver_name)

        rules_by_id: dict[str, dict[str, Any]] = {}
        for rule in driver.get("rules") or []:
            if isinstance(rule, dict) and rule.get("id"):
                rules_by_id[str(rule["id"])] = rule
        for ext in tool.get("extensions") or []:
            if isinstance(ext, dict):
                for rule in ext.get("rules") or []:
                    if isinstance(rule, dict) and rule.get("id"):
                        rules_by_id.setdefault(str(rule["id"]), rule)

        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue

            rule_id = str(
                result.get("ruleId")
                or (result.get("rule") or {}).get("id")
                or ""
            ).strip()
            if not rule_id:
                continue

            rule = rules_by_id.get(rule_id, {})
            tags = [
                str(t)
                for t in ((rule.get("properties") or {}).get("tags") or [])
                if isinstance(t, str)
            ]

            identifier, finding_type = _classify_identifier(
                rule_id=rule_id,
                scanner=scanner,
                tags=tags,
            )
            severity, cvss_score = _extract_severity_and_cvss(result=result, rule=rule)
            uri, target = _extract_location(result=result, fallback_target=driver_name)

            message_text = str((result.get("message") or {}).get("text") or "").strip()
            short_desc = str((rule.get("shortDescription") or {}).get("text") or "").strip()
            full_desc = str((rule.get("fullDescription") or {}).get("text") or "").strip()

            package_name, installed_version, fixed_version = _extract_package_metadata(
                scanner=scanner,
                finding_type=finding_type,
                message_text=message_text,
                uri=uri,
                rule_id=rule_id,
            )

            findings.append(
                RawVulnerability(
                    cve_id=identifier,
                    package_name=package_name,
                    installed_version=installed_version,
                    fixed_version=fixed_version,
                    severity=severity,
                    cvss_score=cvss_score,
                    title=short_desc or str(rule.get("name") or rule_id),
                    description=message_text or full_desc or None,
                    target=target,
                    source_scanner=scanner,
                    finding_type=finding_type,
                )
            )

    return findings


def parse_sarif_report(report_path: str | Path) -> list[RawVulnerability]:
    path = Path(report_path)
    if not path.exists():
        raise FileNotFoundError(f"Relatório SARIF não encontrado: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Relatório SARIF em '{path}' deve ser um objeto JSON.")
    return parse_sarif_payload(data)
