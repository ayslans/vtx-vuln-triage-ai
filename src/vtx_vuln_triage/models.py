from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Priority(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class AssetCriticality(str, Enum):
    CDE = "CDE"  # Cardholder Data Environment (escopo crítico PCI-DSS)
    CONNECTED = "CONNECTED"  # Sistemas conectados ao CDE
    STANDARD = "STANDARD"  # Demais ambientes


class RawVulnerability(BaseModel):
    cve_id: str = Field(..., description="Identificador CVE (ex: CVE-2024-3094)")
    package_name: str
    installed_version: str
    fixed_version: Optional[str] = None
    severity: Severity = Severity.UNKNOWN
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    title: Optional[str] = None
    description: Optional[str] = None
    target: str = Field(..., description="Imagem, container ou manifesto analisado")

    @field_validator("cve_id")
    @classmethod
    def normalize_cve_id(cls, value: str) -> str:
        cleaned = value.strip().upper()
        if not cleaned.startswith("CVE-"):
            raise ValueError(f"cve_id inválido: {value}")
        return cleaned


class EnrichedVulnerability(RawVulnerability):
    in_cisa_kev: bool = False
    kev_date_added: Optional[str] = None
    kev_due_date: Optional[str] = None
    epss_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class TriageDecision(BaseModel):
    vulnerability: EnrichedVulnerability
    asset_criticality: AssetCriticality
    priority: Priority
    sla_days: int = Field(..., gt=0)
    rationale: list[str] = Field(default_factory=list)
    pci_dss_in_scope: bool = False
    asset_id: Optional[str] = None
    asset_owner: Optional[str] = None
    base_priority: Optional[Priority] = None
    asset_adjustment: int = 0
    triaged_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sla_due_at: Optional[datetime] = None

    @model_validator(mode="after")
    def populate_sla_due_at(self) -> TriageDecision:
        if self.triaged_at.tzinfo is None:
            self.triaged_at = self.triaged_at.replace(tzinfo=timezone.utc)
        if self.sla_due_at is None:
            self.sla_due_at = self.triaged_at + timedelta(days=self.sla_days)
        elif self.sla_due_at.tzinfo is None:
            self.sla_due_at = self.sla_due_at.replace(tzinfo=timezone.utc)
        return self
