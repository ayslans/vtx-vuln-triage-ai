from pathlib import Path

import pytest

from vtx_vuln_triage.assets import load_asset_catalog
from vtx_vuln_triage.models import AssetCriticality, EnrichedVulnerability, Priority, Severity
from vtx_vuln_triage.policy.pci_engine import PciPolicyEngine

EXAMPLES_FILE = Path(__file__).resolve().parents[1] / "examples" / "assets.yaml"


def _make_vuln(**overrides) -> EnrichedVulnerability:
    base = {
        "cve_id": "CVE-2025-1000",
        "package_name": "openssl",
        "installed_version": "3.0.1",
        "fixed_version": "3.0.2",
        "severity": Severity.HIGH,
        "cvss_score": 7.8,
        "target": "service:1.0.0",
        "in_cisa_kev": False,
        "epss_score": 0.10,
    }
    base.update(overrides)
    return EnrichedVulnerability(**base)


@pytest.mark.parametrize(
    ("asset_id", "expected_priority", "expected_sla", "expected_delta"),
    [
        ("api-pagamentos-prod", Priority.P1, 7, -1),
        ("portal-clientes-prod", Priority.P1, 7, -1),
        ("worker-etl-staging", Priority.P2, 30, 0),
        ("lab-sandbox-dev", Priority.P3, 90, 1),
    ],
)
def test_high_cvss_priority_shifts_by_asset_context(
    asset_id: str,
    expected_priority: Priority,
    expected_sla: int,
    expected_delta: int,
) -> None:
    catalog = load_asset_catalog(EXAMPLES_FILE)
    asset = catalog.get(asset_id)
    assert asset is not None

    engine = PciPolicyEngine("config/pci_policy.yaml")
    decision = engine.evaluate(
        _make_vuln(cvss_score=7.8, epss_score=0.10),
        asset_criticality=AssetCriticality.STANDARD,
        asset_context=asset,
    )

    assert decision.base_priority == Priority.P2
    assert decision.priority == expected_priority
    assert decision.sla_days == expected_sla
    assert decision.asset_adjustment == expected_delta
    assert decision.asset_id == asset.asset_id
    assert decision.asset_owner == asset.owner


def test_critical_cvss_escalates_to_p0_on_internet_prod() -> None:
    catalog = load_asset_catalog(EXAMPLES_FILE)
    prod_api = catalog.get("api-pagamentos-prod")
    dev_lab = catalog.get("lab-sandbox-dev")
    assert prod_api is not None and dev_lab is not None

    engine = PciPolicyEngine("config/pci_policy.yaml")
    vuln = _make_vuln(cvss_score=9.8, severity=Severity.CRITICAL, epss_score=0.15)

    prod_decision = engine.evaluate(vuln, asset_context=prod_api)
    dev_decision = engine.evaluate(vuln, asset_context=dev_lab)

    assert prod_decision.priority == Priority.P0
    assert prod_decision.sla_days == 2
    assert dev_decision.priority == Priority.P2
    assert dev_decision.sla_days == 30


def test_guardrail_prevents_downgrading_kev_in_pci_scope() -> None:
    catalog = load_asset_catalog(EXAMPLES_FILE)
    dev_lab = catalog.get("lab-sandbox-dev")
    assert dev_lab is not None

    engine = PciPolicyEngine("config/pci_policy.yaml")
    vuln = _make_vuln(cvss_score=7.5, in_cisa_kev=True, epss_score=0.90)

    decision = engine.evaluate(
        vuln,
        asset_criticality=AssetCriticality.CDE,
        asset_context=dev_lab,
    )

    assert decision.base_priority == Priority.P0
    assert decision.priority == Priority.P0
    assert decision.sla_days == 2
    assert decision.asset_adjustment == 0
    assert any("Guardrail" in line for line in decision.rationale)


def test_evaluate_batch_propagates_asset_context() -> None:
    catalog = load_asset_catalog(EXAMPLES_FILE)
    prod_api = catalog.get("api-pagamentos-prod")
    assert prod_api is not None

    engine = PciPolicyEngine("config/pci_policy.yaml")
    vulns = [
        _make_vuln(cve_id="CVE-2025-0001", cvss_score=4.5, epss_score=0.01),
        _make_vuln(cve_id="CVE-2025-0002", cvss_score=9.8, epss_score=0.20),
    ]

    decisions = engine.evaluate_batch(vulns, asset_context=prod_api)

    assert [d.vulnerability.cve_id for d in decisions] == ["CVE-2025-0002", "CVE-2025-0001"]
    assert decisions[0].priority == Priority.P0
    assert decisions[1].priority == Priority.P2
    assert all(d.asset_id == "api-pagamentos-prod" for d in decisions)
