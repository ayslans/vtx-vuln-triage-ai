from __future__ import annotations

from typing import Optional

import httpx

from vtx_vuln_triage.utils.cache import FileCache

EPSS_API_URL = "https://api.first.org/data/v1/epss"


class EpssClient:
    """Consulta em lote a API pública FIRST EPSS com cache local por CVE."""

    def __init__(
        self,
        cache: Optional[FileCache] = None,
        http_client: Optional[httpx.Client] = None,
        batch_size: int = 50,
        timeout: float = 15.0,
    ) -> None:
        self.cache = cache or FileCache()
        self.http_client = http_client
        self.batch_size = batch_size
        self.timeout = timeout

    def lookup(self, cve_ids: list[str]) -> dict[str, dict[str, float]]:
        """Retorna {cve_id: {'epss': float, 'percentile': float}} para os CVEs consultados."""
        unique_cves = sorted({cve.strip().upper() for cve in cve_ids if cve.strip()})
        results: dict[str, dict[str, float]] = {}
        missing: list[str] = []

        for cve in unique_cves:
            cached = self.cache.get(f"epss_{cve}")
            if isinstance(cached, dict) and "epss" in cached:
                results[cve] = cached
            else:
                missing.append(cve)

        if not missing:
            return results

        for idx in range(0, len(missing), self.batch_size):
            batch = missing[idx : idx + self.batch_size]
            fetched = self._fetch_batch(batch)
            for cve, metrics in fetched.items():
                results[cve] = metrics
                self.cache.set(f"epss_{cve}", metrics)

        return results

    def _fetch_batch(self, cve_batch: list[str]) -> dict[str, dict[str, float]]:
        params = {"cve": ",".join(cve_batch)}
        try:
            if self.http_client is not None:
                response = self.http_client.get(EPSS_API_URL, params=params, timeout=self.timeout)
            else:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.get(EPSS_API_URL, params=params)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError):
            return {}

        parsed: dict[str, dict[str, float]] = {}
        for item in payload.get("data", []):
            cve_id = str(item.get("cve", "")).strip().upper()
            if not cve_id:
                continue
            try:
                parsed[cve_id] = {
                    "epss": float(item["epss"]),
                    "percentile": float(item["percentile"]),
                }
            except (KeyError, TypeError, ValueError):
                continue

        return parsed
