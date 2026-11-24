from pathlib import Path

import pytest

from vtx_vuln_triage.models import Severity
from vtx_vuln_triage.parsers.trivy_parser import parse_trivy_report

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_trivy.json"


def test_parse_trivy_report_extracts_and_deduplicates():
    vulns = parse_trivy_report(FIXTURE_PATH)

    # Deve ignorar a duplicata de CVE-2023-44487 e o registro GHSA-9999-xxxx-yyyy
    assert len(vulns) == 2

    cve_ids = {v.cve_id for v in vulns}
    assert cve_ids == {"CVE-2023-44487", "CVE-2024-3094"}


def test_parse_trivy_report_prioritizes_nvd_cvss():
    vulns = parse_trivy_report(FIXTURE_PATH)
    by_cve = {v.cve_id: v for v in vulns}

    # NVD (7.5) deve prevalecer sobre RedHat (8.2)
    assert by_cve["CVE-2023-44487"].cvss_score == 7.5
    assert by_cve["CVE-2023-44487"].severity == Severity.HIGH

    # Sem NVD, usa fallback da fonte disponível (ghsa = 10.0)
    assert by_cve["CVE-2024-3094"].cvss_score == 10.0
    assert by_cve["CVE-2024-3094"].severity == Severity.CRITICAL


def test_parse_trivy_report_raises_for_missing_file():
    with pytest.raises(FileNotFoundError):
        parse_trivy_report("tests/fixtures/nao_existe.json")
