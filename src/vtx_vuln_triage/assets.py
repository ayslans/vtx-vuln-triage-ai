from __future__ import annotations

from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

AssetEnvironment = Literal["prod", "staging", "dev"]
AssetExposure = Literal["internet", "internal"]
AssetBusinessCriticality = Literal["critical", "high", "medium", "low"]

UNKNOWN_ASSET_ID = "unknown-asset"


class AssetContext(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    asset_id: str = Field(
        ...,
        min_length=2,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
        description="Identificador único do ativo (kebab/snake case minúsculo).",
    )
    name: str = Field(..., min_length=1, max_length=120)
    owner: str = Field(..., min_length=1, max_length=120)
    environment: AssetEnvironment
    exposure: AssetExposure
    criticality: AssetBusinessCriticality
    tags: list[str] = Field(default_factory=list)


class AssetCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal["1"] = "1"
    assets: list[AssetContext] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_unique_asset_ids(self) -> AssetCatalog:
        seen: set[str] = set()
        duplicates: list[str] = []
        for asset in self.assets:
            if asset.asset_id in seen:
                duplicates.append(asset.asset_id)
            seen.add(asset.asset_id)
        if duplicates:
            dup_list = ", ".join(sorted(set(duplicates)))
            raise ValueError(f"Duplicate asset_id entries found: {dup_list}")
        return self

    def by_id(self) -> dict[str, AssetContext]:
        return {asset.asset_id: asset for asset in self.assets}

    def get(self, asset_id: str) -> Optional[AssetContext]:
        return self.by_id().get(asset_id)


def load_asset_catalog(path: str | Path) -> AssetCatalog:
    catalog_path = Path(path)
    raw_content = catalog_path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw_content)
    if not isinstance(data, dict):
        raise ValueError(
            f"Asset catalog at '{catalog_path}' must be a YAML mapping."
        )
    return AssetCatalog.model_validate(data)


def build_unknown_asset_context(requested_asset_id: Optional[str] = None) -> AssetContext:
    """Retorna perfil conservador (delta 0) para ativos ausentes ou não catalogados."""
    suffix = f" ({requested_asset_id.strip()})" if requested_asset_id and requested_asset_id.strip() else ""
    return AssetContext(
        asset_id=UNKNOWN_ASSET_ID,
        name=f"Ativo não catalogado{suffix}",
        owner="unassigned@unknown.local",
        environment="prod",
        exposure="internal",
        criticality="high",
        tags=["unknown-asset", "fallback"],
    )


def resolve_asset_context(
    assets_path: Optional[str | Path] = None,
    asset_id: Optional[str] = None,
) -> tuple[Optional[AssetContext], Optional[str]]:
    """Resolve AssetContext do catálogo YAML com fallback seguro sem interromper o pipeline."""
    if assets_path is None and asset_id is None:
        return None, None

    if assets_path is None:
        return (
            build_unknown_asset_context(asset_id),
            f"Asset ID '{asset_id}' informado sem catálogo (--assets); "
            f"aplicando perfil conservador '{UNKNOWN_ASSET_ID}'.",
        )

    try:
        catalog = load_asset_catalog(assets_path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return (
            build_unknown_asset_context(asset_id),
            f"Falha ao carregar catálogo '{assets_path}' ({exc}); "
            f"aplicando perfil conservador '{UNKNOWN_ASSET_ID}'.",
        )

    if not asset_id or not asset_id.strip():
        return (
            build_unknown_asset_context(),
            f"Catálogo '{assets_path}' informado sem --asset-id; "
            f"aplicando perfil conservador '{UNKNOWN_ASSET_ID}'.",
        )

    normalized_id = asset_id.strip()
    found = catalog.get(normalized_id)
    if found is None:
        return (
            build_unknown_asset_context(normalized_id),
            f"Asset ID '{normalized_id}' não encontrado em '{assets_path}'; "
            f"aplicando perfil conservador '{UNKNOWN_ASSET_ID}'.",
        )

    return found, None
