from vtx_vuln_triage.models import AssetCriticality, EnrichedVulnerability, Priority, Severity
from vtx_vuln_triage.policy.pci_engine import PciPolicyEngine


def _make_vuln(**overrides) -> EnrichedVulnerability:
    base = {
        "cve_id": "CVE-2024-0001",
        "package_name": "openssl",
        "installed_version": "3.0.1",
        "fixed_version": "3.0.2",
        "severity": Severity.MEDIUM,
        "cvss_score": 5.3,
        "target": "payment-api:1.0.0",
        "in_cisa_kev": False,
        "epss_score": 0.05,
    }
    base.update(overrides)
    return EnrichedVulnerability(**base)


def test_kev_in_cde_is_p0_with_2_day_sla():
    engine = PciPolicyEngine("config/pci_policy.yaml")
    vuln = _make_vuln(cve_id="CVE-2023-44487", cvss_score=7.5, in_cisa_kev=True, epss_score=0.94)

    decision = engine.evaluate(vuln, asset_criticality=AssetCriticality.CDE)

    assert decision.priority == Priority.P0
    assert decision.sla_days == 2
    assert decision.pci_dss_in_scope is True


def test_kev_in_standard_asset_is_p1():
    engine = PciPolicyEngine("config/pci_policy.yaml")
    vuln = _make_vuln(cvss_score=6.5, in_cisa_kev=True, epss_score=0.20)

    decision = engine.evaluate(vuln, asset_criticality=AssetCriticality.STANDARD)

    assert decision.priority == Priority.P1
    assert decision.sla_days == 7
    assert decision.pci_dss_in_scope is False


def test_critical_cvss_or_high_epss_is_p1():
    engine = PciPolicyEngine("config/pci_policy.yaml")

    by_cvss = engine.evaluate(_make_vuln(cvss_score=9.8, epss_score=0.10))
    by_epss = engine.evaluate(_make_vuln(cvss_score=5.0, epss_score=0.75))

    assert by_cvss.priority == Priority.P1
    assert by_epss.priority == Priority.P1


def test_high_cvss_is_p2_and_low_risk_is_p3():
    engine = PciPolicyEngine("config/pci_policy.yaml")

    p2 = engine.evaluate(_make_vuln(cvss_score=7.8, epss_score=0.10))
    p3 = engine.evaluate(_make_vuln(cvss_score=4.3, epss_score=0.02))

    assert p2.priority == Priority.P2
    assert p2.sla_days == 30
    assert p3.priority == Priority.P3
    assert p3.sla_days == 90


def test_evaluate_batch_sorts_by_priority_and_risk():
    engine = PciPolicyEngine("config/pci_policy.yaml")
    vulns = [
        _make_vuln(cve_id="CVE-2024-0003", cvss_score=4.0, epss_score=0.01),
        _make_vuln(cve_id="CVE-2024-0001", cvss_score=7.5, in_cisa_kev=True, epss_score=0.90),
        _make_vuln(cve_id="CVE-2024-0002", cvss_score=9.8, epss_score=0.20),
    ]

    decisions = engine.evaluate_batch(vulns, asset_criticality=AssetCriticality.CDE)

    assert [d.vulnerability.cve_id for d in decisions] == [
        "CVE-2024-0001",  # P0
        "CVE-2024-0002",  # P1
        "CVE-2024-0003",  # P3
    ]
