from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

AssetEnvironment = Literal["prod", "staging", "dev"]
AssetExposure = Literal["internet", "internal"]
AssetCriticality = Literal["critical", "high", "medium", "low"]


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
    criticality: AssetCriticality
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

    def get(self, asset_id: str) -> AssetContext | None:
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
