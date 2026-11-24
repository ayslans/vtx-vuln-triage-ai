from __future__ import annotations

from typing import Any, Optional

import httpx

from vtx_vuln_triage.utils.cache import FileCache

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKevClient:
    """Consulta e faz cache do catálogo CISA Known Exploited Vulnerabilities (KEV)."""

    def __init__(
        self,
        cache: Optional[FileCache] = None,
        http_client: Optional[httpx.Client] = None,
        timeout: float = 15.0,
    ) -> None:
        self.cache = cache or FileCache()
        self.http_client = http_client
        self.timeout = timeout

    def _fetch_catalog(self) -> dict[str, dict[str, Any]]:
        cached = self.cache.get("cisa_kev_catalog")
        if isinstance(cached, dict):
            return cached

        try:
            if self.http_client is not None:
                response = self.http_client.get(CISA_KEV_URL, timeout=self.timeout)
            else:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.get(CISA_KEV_URL)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError):
            # Modo degradado: não derruba o pipeline se o feed externo estiver indisponível
            return {}

        catalog: dict[str, dict[str, Any]] = {}
        for item in data.get("vulnerabilities", []):
            cve_id = str(item.get("cveID", "")).strip().upper()
            if cve_id:
                catalog[cve_id] = {
                    "date_added": item.get("dateAdded"),
                    "due_date": item.get("dueDate"),
                }

        if catalog:
            self.cache.set("cisa_kev_catalog", catalog)
        return catalog

    def lookup(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Retorna um mapa {cve_id: {date_added, due_date}} apenas para CVEs presentes no KEV."""
        catalog = self._fetch_catalog()
        return {
            cve.upper(): catalog[cve.upper()]
            for cve in cve_ids
            if cve.upper() in catalog
        }
