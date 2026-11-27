from pathlib import Path

import pytest
from pydantic import ValidationError

from vtx_vuln_triage.assets import AssetCatalog, AssetContext, load_asset_catalog

EXAMPLES_FILE = Path(__file__).resolve().parents[1] / "examples" / "assets.yaml"


def test_load_example_assets_catalog() -> None:
    catalog = load_asset_catalog(EXAMPLES_FILE)
    assert catalog.version == "1"
    assert len(catalog.assets) == 4

    payments = catalog.get("api-pagamentos-prod")
    assert payments is not None
    assert payments.environment == "prod"
    assert payments.exposure == "internet"
    assert payments.criticality == "critical"
    assert catalog.get("ativo-inexistente") is None


def test_reject_invalid_enum_values() -> None:
    with pytest.raises(ValidationError):
        AssetContext(
            asset_id="app-teste",
            name="App Teste",
            owner="sec@empresa.local",
            environment="production",  # type: ignore[arg-type]
            exposure="internet",
            criticality="high",
        )


def test_reject_invalid_asset_id_pattern() -> None:
    with pytest.raises(ValidationError):
        AssetContext(
            asset_id="API Pagamentos",
            name="API",
            owner="sec@empresa.local",
            environment="prod",
            exposure="internet",
            criticality="critical",
        )


def test_reject_duplicate_asset_ids() -> None:
    base = {
        "asset_id": "dup-service",
        "name": "Service",
        "owner": "sec@empresa.local",
        "environment": "prod",
        "exposure": "internal",
        "criticality": "medium",
    }
    with pytest.raises(ValidationError, match="Duplicate asset_id"):
        AssetCatalog.model_validate({"version": "1", "assets": [base, base]})


def test_reject_extra_fields() -> None:
    with pytest.raises(ValidationError):
        AssetContext.model_validate(
            {
                "asset_id": "svc-extra",
                "name": "Service",
                "owner": "sec@empresa.local",
                "environment": "dev",
                "exposure": "internal",
                "criticality": "low",
                "unexpected": "value",
            }
        )


def test_load_invalid_yaml_root_raises_value_error(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad_assets.yaml"
    bad_file.write_text("- item1\n- item2\n", encoding="utf-8")

    with pytest.raises(ValueError, match="YAML mapping"):
        load_asset_catalog(bad_file)
