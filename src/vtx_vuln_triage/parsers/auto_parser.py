from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Any

from vtx_vuln_triage.models import RawVulnerability
from vtx_vuln_triage.parsers.sarif_parser import parse_sarif_payload
from vtx_vuln_triage.parsers.trivy_parser import parse_trivy_report


class InputFormat(str, Enum):
    AUTO = "auto"
    TRIVY = "trivy"
    SARIF = "sarif"


def detect_report_format(data: dict[str, Any]) -> InputFormat:
    schema_uri = str(data.get("$schema") or "").lower()
    version = str(data.get("version") or "")
    if isinstance(data.get("runs"), list) and (
        "sarif" in schema_uri or version.startswith("2.1")
    ):
        return InputFormat.SARIF

    if "Results" in data or "SchemaVersion" in data:
        return InputFormat.TRIVY

    raise ValueError(
        "Formato de relatório não reconhecido. Esperado Trivy JSON ou SARIF 2.1.0."
    )


def parse_security_report(
    report_path: str | Path,
    input_format: InputFormat | str = InputFormat.AUTO,
) -> list[RawVulnerability]:
    path = Path(report_path)
    if not path.exists():
        raise FileNotFoundError(f"Relatório não encontrado: {path}")

    resolved_format = (
        input_format
        if isinstance(input_format, InputFormat)
        else InputFormat(str(input_format).strip().lower())
    )

    if resolved_format == InputFormat.TRIVY:
        return parse_trivy_report(path)

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Relatório em '{path}' deve conter um objeto JSON na raiz.")

    if resolved_format == InputFormat.AUTO:
        resolved_format = detect_report_format(data)

    if resolved_format == InputFormat.SARIF:
        return parse_sarif_payload(data)

    return parse_trivy_report(path)
