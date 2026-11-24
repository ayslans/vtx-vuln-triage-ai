import httpx

from vtx_vuln_triage.enrichers.cisa_kev import CisaKevClient
from vtx_vuln_triage.enrichers.epss_client import EpssClient
from vtx_vuln_triage.utils.cache import FileCache


def test_cisa_kev_client_fetches_and_caches(tmp_path):
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2023-44487",
                        "dateAdded": "2023-10-10",
                        "dueDate": "2023-10-31",
                    }
                ]
            },
        )

    transport = httpx.MockTransport(handler)
    cache = FileCache(cache_dir=tmp_path)

    with httpx.Client(transport=transport) as http_client:
        client = CisaKevClient(cache=cache, http_client=http_client)

        first = client.lookup(["CVE-2023-44487", "CVE-2024-3094"])
        second = client.lookup(["CVE-2023-44487"])

    assert calls["count"] == 1  # Segunda chamada veio do cache
    assert "CVE-2023-44487" in first
    assert "CVE-2024-3094" not in first
    assert second["CVE-2023-44487"]["date_added"] == "2023-10-10"


def test_cisa_kev_client_degrades_gracefully_on_http_error(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    transport = httpx.MockTransport(handler)
    cache = FileCache(cache_dir=tmp_path)

    with httpx.Client(transport=transport) as http_client:
        client = CisaKevClient(cache=cache, http_client=http_client)
        result = client.lookup(["CVE-2023-44487"])

    assert result == {}


def test_epss_client_batches_and_caches(tmp_path):
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        cves = request.url.params.get("cve", "").split(",")
        data = [
            {"cve": cve, "epss": "0.94210", "percentile": "0.99120"}
            for cve in cves
            if cve
        ]
        return httpx.Response(200, json={"status": "OK", "data": data})

    transport = httpx.MockTransport(handler)
    cache = FileCache(cache_dir=tmp_path)

    with httpx.Client(transport=transport) as http_client:
        client = EpssClient(cache=cache, http_client=http_client, batch_size=1)

        first = client.lookup(["CVE-2023-44487", "CVE-2024-3094"])
        second = client.lookup(["CVE-2023-44487"])

    # batch_size=1 com 2 CVEs => 2 chamadas na primeira vez; 0 na segunda (cache)
    assert calls["count"] == 2
    assert first["CVE-2023-44487"]["epss"] == 0.9421
    assert second["CVE-2023-44487"]["percentile"] == 0.9912
