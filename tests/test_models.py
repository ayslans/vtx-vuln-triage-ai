import pytest
from pydantic import ValidationError

from vtx_vuln_triage.models import (
    AssetCriticality,
    EnrichedVulnerability,
    Priority,
    RawVulnerability,
    Severity,
    TriageDecision,
)


def test_raw_vulnerability_normalizes_cve_id():
    vuln = RawVulnerability(
        cve_id="  cve-2024-3094 ",
        package_name="xz-utils",
        installed_version="5.6.0",
        fixed_version="5.6.1",
        severity=Severity.CRITICAL,
        cvss_score=10.0,
        target="payment-api:1.2.0",
    )
    assert vuln.cve_id == "CVE-2024-3094"


def test_raw_vulnerability_rejects_invalid_cve_id():
    with pytest.raises(ValidationError):
        RawVulnerability(
            cve_id="GHSA-1234-5678",
            package_name="openssl",
            installed_version="3.0.1",
            target="payment-api:1.2.0",
        )


def test_enriched_vulnerability_rejects_invalid_epss():
    with pytest.raises(ValidationError):
        EnrichedVulnerability(
            cve_id="CVE-2023-44487",
            package_name="nghttp2",
            installed_version="1.55.0",
            target="gateway:latest",
            epss_score=1.5,
        )


def test_triage_decision_creation():
    enriched = EnrichedVulnerability(
        cve_id="CVE-2023-44487",
        package_name="nghttp2",
        installed_version="1.55.0",
        fixed_version="1.57.0",
        severity=Severity.HIGH,
        cvss_score=7.5,
        target="gateway:latest",
        in_cisa_kev=True,
        epss_score=0.94,
    )
    decision = TriageDecision(
        vulnerability=enriched,
        asset_criticality=AssetCriticality.CDE,
        priority=Priority.P0,
        sla_days=2,
        rationale=["Listada na CISA KEV", "Ativo em escopo CDE (PCI-DSS)"],
        pci_dss_in_scope=True,
    )
    assert decision.priority == Priority.P0
    assert decision.sla_days == 2
    assert decision.pci_dss_in_scope is True
