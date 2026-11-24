# Boletim de Triagem de Vulnerabilidades — vtx-vuln-triage-ai

- **Gerado em:** 2026-11-24 05:15 UTC
- **Total de achados:** 1115
- **Motor de síntese:** `deterministic-fallback`

## 1. Resumo Executivo

Foram triadas 1115 vulnerabilidades (P0: 7, P1: 55, P2: 374, P3: 679), sendo 7 com exploração ativa confirmada na base CISA KEV.

### Ações Imediatas Recomendadas

- [P0 | SLA 2d] Tratar CVE-2023-44487 no pacote `libnghttp2-14` (versão corrigida: 1.43.0-1+deb11u1).
- [P0 | SLA 2d] Tratar CVE-2023-44487 no pacote `nginx` (versão corrigida: aplicar mitigação/controle compensatório).
- [P0 | SLA 2d] Tratar CVE-2023-4863 no pacote `libwebp6` (versão corrigida: 0.6.1-2.1+deb11u2).

## 2. Distribuição por Prioridade

| Prioridade | Quantidade |
| :--- | :---: |
| **P0 (Crítico / KEV em PCI)** | 7 |
| **P1 (Alto Risco)** | 55 |
| **P2 (Moderado/Alto)** | 374 |
| **P3 (Baixo/Moderado)** | 679 |

## 3. Achados Priorizados

| Prioridade | SLA | CVE | Pacote | Instalada -> Correção | CVSS | EPSS | CISA KEV | Escopo PCI |
| :---: | :---: | :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **P0** | 2d | `CVE-2023-44487` | `libnghttp2-14` | `1.43.0-1` -> `1.43.0-1+deb11u1` | 7.5 | 100.0% | SIM | SIM |
| **P0** | 2d | `CVE-2023-44487` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 7.5 | 100.0% | SIM | SIM |
| **P0** | 2d | `CVE-2023-4863` | `libwebp6` | `0.6.1-2.1` -> `0.6.1-2.1+deb11u2` | 8.8 | 100.0% | SIM | SIM |
| **P0** | 2d | `CVE-2026-111497` | `libbrotli1` | `1.0.9-2+b2` -> `Sem patch` | 9.8 | 99.9% | SIM | SIM |
| **P0** | 2d | `CVE-2023-4911` | `libc-bin` | `2.31-13+deb11u3` -> `2.31-13+deb11u7` | 7.8 | 63.8% | SIM | SIM |
| **P0** | 2d | `CVE-2023-4911` | `libc6` | `2.31-13+deb11u3` -> `2.31-13+deb11u7` | 7.8 | 63.8% | SIM | SIM |
| **P0** | 2d | `CVE-2025-27363` | `libfreetype6` | `2.10.4+dfsg-1+deb11u1` -> `2.10.4+dfsg-1+deb11u2` | 8.1 | 27.8% | SIM | SIM |
| **P1** | 7d | `CVE-2023-50387` | `libsystemd0` | `247.3-7` -> `247.3-7+deb11u6` | 7.5 | 100.0% | Não | SIM |
| **P1** | 7d | `CVE-2023-50387` | `libudev1` | `247.3-7` -> `247.3-7+deb11u6` | 7.5 | 100.0% | Não | SIM |
| **P1** | 7d | `CVE-2024-2961` | `libc-bin` | `2.31-13+deb11u3` -> `2.31-13+deb11u9` | 8.8 | 88.3% | Não | SIM |
| **P1** | 7d | `CVE-2024-2961` | `libc6` | `2.31-13+deb11u3` -> `2.31-13+deb11u9` | 8.8 | 88.3% | Não | SIM |
| **P1** | 7d | `CVE-2024-28182` | `libnghttp2-14` | `1.43.0-1` -> `1.43.0-1+deb11u2` | 5.3 | 82.0% | Não | SIM |
| **P1** | 7d | `CVE-2023-38545` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u10` | 9.8 | 78.3% | Não | SIM |
| **P1** | 7d | `CVE-2023-38545` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u10` | 9.8 | 78.3% | Não | SIM |
| **P1** | 7d | `CVE-2023-2650` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u5` | 6.5 | 75.4% | Não | SIM |
| **P1** | 7d | `CVE-2023-2650` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u5` | 6.5 | 75.4% | Não | SIM |
| **P1** | 7d | `CVE-2023-50868` | `libsystemd0` | `247.3-7` -> `247.3-7+deb11u6` | 7.5 | 74.3% | Não | SIM |
| **P1** | 7d | `CVE-2023-50868` | `libudev1` | `247.3-7` -> `247.3-7+deb11u6` | 7.5 | 74.3% | Não | SIM |
| **P1** | 7d | `CVE-2011-3389` | `libgnutls30` | `3.7.1-5+deb11u1` -> `Sem patch` | 4.3 | 73.3% | Não | SIM |
| **P1** | 7d | `CVE-2019-8457` | `libdb5.3` | `5.3.28+dfsg1-0.8` -> `Sem patch` | 9.8 | 45.4% | Não | SIM |
| **P1** | 7d | `CVE-2022-37434` | `zlib1g` | `1:1.2.11.dfsg-2+deb11u1` -> `1:1.2.11.dfsg-2+deb11u2` | 9.8 | 19.2% | Não | SIM |
| **P1** | 7d | `CVE-2022-32207` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 9.8 | 12.3% | Não | SIM |
| **P1** | 7d | `CVE-2022-32207` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 9.8 | 12.3% | Não | SIM |
| **P1** | 7d | `CVE-2021-22945` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 9.1 | 6.7% | Não | SIM |
| **P1** | 7d | `CVE-2021-22945` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 9.1 | 6.7% | Não | SIM |
| **P1** | 7d | `CVE-2024-5535` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u2` | 9.1 | 6.1% | Não | SIM |
| **P1** | 7d | `CVE-2024-5535` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u2` | 9.1 | 6.1% | Não | SIM |
| **P1** | 7d | `CVE-2022-32221` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u5` | 9.8 | 5.1% | Não | SIM |
| **P1** | 7d | `CVE-2022-32221` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u5` | 9.8 | 5.1% | Não | SIM |
| **P1** | 7d | `CVE-2005-2541` | `tar` | `1.34+dfsg-1` -> `Sem patch` | 10.0 | 4.0% | Não | SIM |
| **P1** | 7d | `CVE-2023-45853` | `zlib1g` | `1:1.2.11.dfsg-2+deb11u1` -> `Sem patch` | 9.8 | 3.4% | Não | SIM |
| **P1** | 7d | `CVE-2022-1586` | `libpcre2-8-0` | `10.36-2` -> `10.36-2+deb11u1` | 9.1 | 3.4% | Não | SIM |
| **P1** | 7d | `CVE-2019-1010022` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 9.8 | 3.2% | Não | SIM |
| **P1** | 7d | `CVE-2019-1010022` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 9.8 | 3.2% | Não | SIM |
| **P1** | 7d | `CVE-2021-46848` | `libtasn1-6` | `4.16.0-2` -> `4.16.0-2+deb11u1` | 9.1 | 2.8% | Não | SIM |
| **P1** | 7d | `CVE-2022-1587` | `libpcre2-8-0` | `10.36-2` -> `10.36-2+deb11u1` | 9.1 | 2.8% | Não | SIM |
| **P1** | 7d | `CVE-2026-33845` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u10` | 9.1 | 2.1% | Não | SIM |
| **P1** | 7d | `CVE-2024-37371` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u5` | 9.1 | 1.9% | Não | SIM |
| **P1** | 7d | `CVE-2024-37371` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u5` | 9.1 | 1.9% | Não | SIM |
| **P1** | 7d | `CVE-2024-37371` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u5` | 9.1 | 1.9% | Não | SIM |
| **P1** | 7d | `CVE-2024-37371` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u5` | 9.1 | 1.9% | Não | SIM |
| **P1** | 7d | `CVE-2025-49796` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u8` | 9.1 | 1.6% | Não | SIM |
| **P1** | 7d | `CVE-2024-45492` | `libexpat1` | `2.2.10-2+deb11u3` -> `2.2.10-2+deb11u6` | 9.8 | 1.4% | Não | SIM |
| **P1** | 7d | `CVE-2024-56171` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u6` | 9.8 | 1.2% | Não | SIM |
| **P1** | 7d | `CVE-2024-45491` | `libexpat1` | `2.2.10-2+deb11u3` -> `2.2.10-2+deb11u6` | 9.8 | 1.1% | Não | SIM |
| **P1** | 7d | `CVE-2026-42010` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u10` | 9.8 | 1.1% | Não | SIM |
| **P1** | 7d | `CVE-2023-23914` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 9.1 | 0.9% | Não | SIM |
| **P1** | 7d | `CVE-2023-23914` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 9.1 | 0.9% | Não | SIM |
| **P1** | 7d | `CVE-2025-49794` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u8` | 9.1 | 0.9% | Não | SIM |
| **P1** | 7d | `CVE-2026-11856` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 9.8 | 0.7% | Não | SIM |
| **P1** | 7d | `CVE-2026-11856` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 9.8 | 0.7% | Não | SIM |
| **P1** | 7d | `CVE-2026-8924` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 9.1 | 0.7% | Não | SIM |
| **P1** | 7d | `CVE-2026-8924` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 9.1 | 0.7% | Não | SIM |
| **P1** | 7d | `CVE-2026-8376` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 9.8 | 0.6% | Não | SIM |
| **P1** | 7d | `CVE-2026-97205` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 9.8 | 0.6% | Não | SIM |
| **P1** | 7d | `CVE-2026-13221` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 9.1 | 0.5% | Não | SIM |
| **P1** | 7d | `CVE-2026-42496` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 9.1 | 0.5% | Não | SIM |
| **P1** | 7d | `CVE-2026-8927` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 9.1 | 0.5% | Não | SIM |
| **P1** | 7d | `CVE-2026-8927` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 9.1 | 0.5% | Não | SIM |
| **P1** | 7d | `CVE-2026-129483` | `libsasl2-2` | `2.1.27+dfsg-2.1+deb11u1` -> `Sem patch` | 9.1 | 0.4% | Não | SIM |
| **P1** | 7d | `CVE-2026-129483` | `libsasl2-modules-db` | `2.1.27+dfsg-2.1+deb11u1` -> `Sem patch` | 9.1 | 0.4% | Não | SIM |
| **P1** | 7d | `CVE-2026-6653` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `Sem patch` | 9.8 | 0.3% | Não | SIM |
| **P2** | 30d | `CVE-2023-0286` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u4` | 7.4 | 61.8% | Não | SIM |
| **P2** | 30d | `CVE-2023-0286` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u4` | 7.4 | 61.8% | Não | SIM |
| **P2** | 30d | `CVE-2024-2511` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u2` | 5.9 | 59.3% | Não | SIM |
| **P2** | 30d | `CVE-2024-2511` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u2` | 5.9 | 59.3% | Não | SIM |
| **P2** | 30d | `CVE-2022-40303` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u3` | 7.5 | 41.4% | Não | SIM |
| **P2** | 30d | `CVE-2022-32206` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 6.5 | 36.3% | Não | SIM |
| **P2** | 30d | `CVE-2022-32206` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 6.5 | 36.3% | Não | SIM |
| **P2** | 30d | `CVE-2024-2398` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u12` | 8.6 | 36.1% | Não | SIM |
| **P2** | 30d | `CVE-2024-2398` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u12` | 8.6 | 36.1% | Não | SIM |
| **P2** | 30d | `CVE-2022-32205` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 4.3 | 31.5% | Não | SIM |
| **P2** | 30d | `CVE-2022-32205` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 4.3 | 31.5% | Não | SIM |
| **P2** | 30d | `CVE-2022-4450` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u4` | 7.5 | 28.6% | Não | SIM |
| **P2** | 30d | `CVE-2022-4450` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u4` | 7.5 | 28.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-123007` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 8.1 | 27.8% | Não | SIM |
| **P2** | 30d | `CVE-2021-30560` | `libxslt1.1` | `1.1.34-4` -> `1.1.34-4+deb11u1` | 8.8 | 20.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-123633` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 8.1 | 17.5% | Não | SIM |
| **P2** | 30d | `CVE-2026-123634` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 8.1 | 17.1% | Não | SIM |
| **P2** | 30d | `CVE-2022-43551` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 7.5 | 16.6% | Não | SIM |
| **P2** | 30d | `CVE-2022-43551` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 7.5 | 16.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-121810` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 8.1 | 16.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-113425` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 8.1 | 13.9% | Não | SIM |
| **P2** | 30d | `CVE-2017-17740` | `libldap-2.4-2` | `2.4.57+dfsg-3+deb11u1` -> `Sem patch` | 7.5 | 7.0% | Não | SIM |
| **P2** | 30d | `CVE-2022-42898` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u3` | 8.8 | 6.9% | Não | SIM |
| **P2** | 30d | `CVE-2022-42898` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u3` | 8.8 | 6.9% | Não | SIM |
| **P2** | 30d | `CVE-2022-42898` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u3` | 8.8 | 6.9% | Não | SIM |
| **P2** | 30d | `CVE-2022-42898` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u3` | 8.8 | 6.9% | Não | SIM |
| **P2** | 30d | `CVE-2026-42533` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 7.0 | 6.5% | Não | SIM |
| **P2** | 30d | `CVE-2022-40304` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u3` | 7.8 | 5.8% | Não | SIM |
| **P2** | 30d | `CVE-2018-20796` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 7.5 | 5.8% | Não | SIM |
| **P2** | 30d | `CVE-2018-20796` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 7.5 | 5.8% | Não | SIM |
| **P2** | 30d | `CVE-2017-16232` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 7.5 | 5.4% | Não | SIM |
| **P2** | 30d | `CVE-2015-3276` | `libldap-2.4-2` | `2.4.57+dfsg-3+deb11u1` -> `Sem patch` | 7.5 | 5.3% | Não | SIM |
| **P2** | 30d | `CVE-2023-0215` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u4` | 7.5 | 5.3% | Não | SIM |
| **P2** | 30d | `CVE-2023-0215` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u4` | 7.5 | 5.3% | Não | SIM |
| **P2** | 30d | `CVE-2021-22946` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 7.5 | 4.5% | Não | SIM |
| **P2** | 30d | `CVE-2021-22946` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 7.5 | 4.5% | Não | SIM |
| **P2** | 30d | `CVE-2026-45447` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u8` | 8.8 | 4.0% | Não | SIM |
| **P2** | 30d | `CVE-2026-45447` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u8` | 8.8 | 4.0% | Não | SIM |
| **P2** | 30d | `CVE-2023-0464` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u5` | 7.5 | 4.0% | Não | SIM |
| **P2** | 30d | `CVE-2023-0464` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u5` | 7.5 | 4.0% | Não | SIM |
| **P2** | 30d | `CVE-2026-118899` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 7.5 | 3.8% | Não | SIM |
| **P2** | 30d | `CVE-2022-27775` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 7.5 | 3.3% | Não | SIM |
| **P2** | 30d | `CVE-2022-27775` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 7.5 | 3.3% | Não | SIM |
| **P2** | 30d | `CVE-2024-4741` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u2` | 7.5 | 3.3% | Não | SIM |
| **P2** | 30d | `CVE-2024-4741` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u2` | 7.5 | 3.3% | Não | SIM |
| **P2** | 30d | `CVE-2021-46828` | `libtirpc-common` | `1.3.1-1` -> `1.3.1-1+deb11u1` | 7.5 | 3.2% | Não | SIM |
| **P2** | 30d | `CVE-2021-46828` | `libtirpc3` | `1.3.1-1` -> `1.3.1-1+deb11u1` | 7.5 | 3.2% | Não | SIM |
| **P2** | 30d | `CVE-2022-43680` | `libexpat1` | `2.2.10-2+deb11u3` -> `2.2.10-2+deb11u5` | 7.5 | 3.2% | Não | SIM |
| **P2** | 30d | `CVE-2022-27782` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 7.5 | 3.1% | Não | SIM |
| **P2** | 30d | `CVE-2022-27782` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 7.5 | 3.1% | Não | SIM |
| **P2** | 30d | `CVE-2017-11164` | `libpcre3` | `2:8.39-13` -> `Sem patch` | 7.5 | 3.1% | Não | SIM |
| **P2** | 30d | `CVE-2019-1010023` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 8.8 | 3.1% | Não | SIM |
| **P2** | 30d | `CVE-2019-1010023` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 8.8 | 3.1% | Não | SIM |
| **P2** | 30d | `CVE-2022-27781` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 7.5 | 2.9% | Não | SIM |
| **P2** | 30d | `CVE-2022-27781` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 7.5 | 2.9% | Não | SIM |
| **P2** | 30d | `CVE-2019-20838` | `libpcre3` | `2:8.39-13` -> `Sem patch` | 7.5 | 2.8% | Não | SIM |
| **P2** | 30d | `CVE-2023-52356` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u6` | 7.5 | 2.7% | Não | SIM |
| **P2** | 30d | `CVE-2017-7246` | `libpcre3` | `2:8.39-13` -> `Sem patch` | 7.8 | 2.6% | Não | SIM |
| **P2** | 30d | `CVE-2022-22576` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 8.1 | 2.5% | Não | SIM |
| **P2** | 30d | `CVE-2022-22576` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 8.1 | 2.5% | Não | SIM |
| **P2** | 30d | `CVE-2022-42916` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 7.5 | 2.5% | Não | SIM |
| **P2** | 30d | `CVE-2022-42916` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 7.5 | 2.5% | Não | SIM |
| **P2** | 30d | `CVE-2022-2309` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u5` | 7.5 | 2.4% | Não | SIM |
| **P2** | 30d | `CVE-2019-9192` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 7.5 | 2.4% | Não | SIM |
| **P2** | 30d | `CVE-2019-9192` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 7.5 | 2.4% | Não | SIM |
| **P2** | 30d | `CVE-2023-27534` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u8` | 8.8 | 2.4% | Não | SIM |
| **P2** | 30d | `CVE-2023-27534` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u8` | 8.8 | 2.4% | Não | SIM |
| **P2** | 30d | `CVE-2022-40674` | `libexpat1` | `2.2.10-2+deb11u3` -> `2.2.10-2+deb11u4` | 8.1 | 2.4% | Não | SIM |
| **P2** | 30d | `CVE-2017-7245` | `libpcre3` | `2:8.39-13` -> `Sem patch` | 7.8 | 2.4% | Não | SIM |
| **P2** | 30d | `CVE-2021-33560` | `libgcrypt20` | `1.8.7-6` -> `Sem patch` | 7.5 | 2.4% | Não | SIM |
| **P2** | 30d | `CVE-2022-2509` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u2` | 7.5 | 2.3% | Não | SIM |
| **P2** | 30d | `CVE-2013-0337` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 7.5 | 2.2% | Não | SIM |
| **P2** | 30d | `CVE-2023-27533` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u8` | 8.8 | 2.2% | Não | SIM |
| **P2** | 30d | `CVE-2023-27533` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u8` | 8.8 | 2.2% | Não | SIM |
| **P2** | 30d | `CVE-2023-52425` | `libexpat1` | `2.2.10-2+deb11u3` -> `2.2.10-2+deb11u6` | 7.5 | 2.1% | Não | SIM |
| **P2** | 30d | `CVE-2021-40145` | `libgd3` | `2.3.0-2` -> `2.3.0-2+deb11u1` | 7.5 | 2.1% | Não | SIM |
| **P2** | 30d | `CVE-2018-5709` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 2.0% | Não | SIM |
| **P2** | 30d | `CVE-2018-5709` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 2.0% | Não | SIM |
| **P2** | 30d | `CVE-2018-5709` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 2.0% | Não | SIM |
| **P2** | 30d | `CVE-2018-5709` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 2.0% | Não | SIM |
| **P2** | 30d | `CVE-2024-28757` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 7.5 | 2.0% | Não | SIM |
| **P2** | 30d | `CVE-2023-2953` | `libldap-2.4-2` | `2.4.57+dfsg-3+deb11u1` -> `Sem patch` | 7.5 | 2.0% | Não | SIM |
| **P2** | 30d | `CVE-2023-52355` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 7.5 | 1.8% | Não | SIM |
| **P2** | 30d | `CVE-2024-34459` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u8` | 7.5 | 1.8% | Não | SIM |
| **P2** | 30d | `CVE-2025-0725` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 7.3 | 1.8% | Não | SIM |
| **P2** | 30d | `CVE-2025-0725` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 7.3 | 1.8% | Não | SIM |
| **P2** | 30d | `CVE-2025-9230` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u4` | 7.5 | 1.8% | Não | SIM |
| **P2** | 30d | `CVE-2025-9230` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u4` | 7.5 | 1.8% | Não | SIM |
| **P2** | 30d | `CVE-2018-6829` | `libgcrypt20` | `1.8.7-6` -> `Sem patch` | 7.5 | 1.8% | Não | SIM |
| **P2** | 30d | `CVE-2023-31486` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 8.1 | 1.7% | Não | SIM |
| **P2** | 30d | `CVE-2022-3970` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 8.8 | 1.7% | Não | SIM |
| **P2** | 30d | `CVE-2024-45490` | `libexpat1` | `2.2.10-2+deb11u3` -> `2.2.10-2+deb11u6` | 7.5 | 1.7% | Não | SIM |
| **P2** | 30d | `CVE-2023-3138` | `libx11-6` | `2:1.7.2-1` -> `2:1.7.2-1+deb11u1` | 7.5 | 1.7% | Não | SIM |
| **P2** | 30d | `CVE-2023-3138` | `libx11-data` | `2:1.7.2-1` -> `2:1.7.2-1+deb11u1` | 7.5 | 1.7% | Não | SIM |
| **P2** | 30d | `CVE-2026-63076` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 7.5 | 1.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-63076` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 7.5 | 1.6% | Não | SIM |
| **P2** | 30d | `CVE-2024-0553` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u5` | 7.5 | 1.6% | Não | SIM |
| **P2** | 30d | `CVE-2022-4899` | `libzstd1` | `1.4.8+dfsg-2.1` -> `Sem patch` | 7.5 | 1.6% | Não | SIM |
| **P2** | 30d | `CVE-2023-31484` | `perl-base` | `5.32.1-4+deb11u2` -> `5.32.1-4+deb11u4` | 8.1 | 1.5% | Não | SIM |
| **P2** | 30d | `CVE-2024-7006` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u6` | 7.5 | 1.5% | Não | SIM |
| **P2** | 30d | `CVE-2025-32988` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u8` | 8.2 | 1.5% | Não | SIM |
| **P2** | 30d | `CVE-2025-59375` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 7.5 | 1.5% | Não | SIM |
| **P2** | 30d | `CVE-2025-6021` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u8` | 7.5 | 1.5% | Não | SIM |
| **P2** | 30d | `CVE-2022-1304` | `e2fsprogs` | `1.46.2-2` -> `1.46.2-2+deb11u1` | 7.8 | 1.5% | Não | SIM |
| **P2** | 30d | `CVE-2022-1304` | `libcom-err2` | `1.46.2-2` -> `1.46.2-2+deb11u1` | 7.8 | 1.5% | Não | SIM |
| **P2** | 30d | `CVE-2022-1304` | `libext2fs2` | `1.46.2-2` -> `1.46.2-2+deb11u1` | 7.8 | 1.5% | Não | SIM |
| **P2** | 30d | `CVE-2022-1304` | `libss2` | `1.46.2-2` -> `1.46.2-2+deb11u1` | 7.8 | 1.5% | Não | SIM |
| **P2** | 30d | `CVE-2022-1304` | `logsave` | `1.46.2-2` -> `1.46.2-2+deb11u1` | 7.8 | 1.5% | Não | SIM |
| **P2** | 30d | `CVE-2023-0361` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u3` | 7.4 | 1.5% | Não | SIM |
| **P2** | 30d | `CVE-2026-42009` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u10` | 7.5 | 1.4% | Não | SIM |
| **P2** | 30d | `CVE-2024-0567` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u5` | 7.5 | 1.4% | Não | SIM |
| **P2** | 30d | `CVE-2024-8176` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 7.5 | 1.4% | Não | SIM |
| **P2** | 30d | `CVE-2022-29458` | `libtinfo6` | `6.2+20201114-2` -> `6.2+20201114-2+deb11u1` | 7.1 | 1.3% | Não | SIM |
| **P2** | 30d | `CVE-2022-29458` | `ncurses-base` | `6.2+20201114-2` -> `6.2+20201114-2+deb11u1` | 7.1 | 1.3% | Não | SIM |
| **P2** | 30d | `CVE-2022-29458` | `ncurses-bin` | `6.2+20201114-2` -> `6.2+20201114-2+deb11u1` | 7.1 | 1.3% | Não | SIM |
| **P2** | 30d | `CVE-2022-46285` | `libxpm4` | `1:3.5.12-1` -> `1:3.5.12-1.1~deb11u1` | 7.5 | 1.3% | Não | SIM |
| **P2** | 30d | `CVE-2024-25062` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u6` | 7.5 | 1.3% | Não | SIM |
| **P2** | 30d | `CVE-2024-33599` | `libc-bin` | `2.31-13+deb11u3` -> `2.31-13+deb11u10` | 7.6 | 1.3% | Não | SIM |
| **P2** | 30d | `CVE-2024-33599` | `libc6` | `2.31-13+deb11u3` -> `2.31-13+deb11u10` | 7.6 | 1.3% | Não | SIM |
| **P2** | 30d | `CVE-2025-7424` | `libxslt1.1` | `1.1.34-4` -> `1.1.34-4+deb11u3` | 7.5 | 1.3% | Não | SIM |
| **P2** | 30d | `CVE-2026-92392` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 8.1 | 1.3% | Não | SIM |
| **P2** | 30d | `CVE-2026-92392` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 8.1 | 1.3% | Não | SIM |
| **P2** | 30d | `CVE-2022-44617` | `libxpm4` | `1:3.5.12-1` -> `1:3.5.12-1.1~deb11u1` | 7.5 | 1.3% | Não | SIM |
| **P2** | 30d | `CVE-2026-33846` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u10` | 7.5 | 1.3% | Não | SIM |
| **P2** | 30d | `CVE-2022-4883` | `libxpm4` | `1:3.5.12-1` -> `1:3.5.12-1.1~deb11u1` | 8.8 | 1.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-112314` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-112314` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-112314` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-112314` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-93479` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 7.0 | 1.2% | Não | SIM |
| **P2** | 30d | `CVE-2020-22218` | `libssh2-1` | `1.9.0-2` -> `1.9.0-2+deb11u1` | 7.5 | 1.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-109518` | `apt` | `2.2.4` -> `Sem patch` | 8.1 | 1.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-109518` | `libapt-pkg6.0` | `2.2.4` -> `Sem patch` | 8.1 | 1.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-112321` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-112321` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-112321` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-112321` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-112320` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-112320` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-112320` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-112320` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.1% | Não | SIM |
| **P2** | 30d | `CVE-2022-41409` | `libpcre2-8-0` | `10.36-2` -> `Sem patch` | 7.5 | 1.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-25646` | `libpng16-16` | `1.6.37-3` -> `1.6.37-3+deb11u2` | 8.1 | 1.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-119079` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-119079` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-119079` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-119079` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.1% | Não | SIM |
| **P2** | 30d | `CVE-2025-27113` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u6` | 7.5 | 1.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-33416` | `libpng16-16` | `1.6.37-3` -> `1.6.37-3+deb11u3` | 7.5 | 1.1% | Não | SIM |
| **P2** | 30d | `CVE-2025-9900` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u7` | 8.8 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2026-34180` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u8` | 7.5 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2026-34180` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u8` | 7.5 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2026-66046` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 7.5 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2026-112322` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2026-112323` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2026-112322` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2026-112323` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2026-112322` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2026-112323` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2026-112322` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2026-112323` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2026-15176` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 8.1 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2023-29491` | `libtinfo6` | `6.2+20201114-2` -> `6.2+20201114-2+deb11u2` | 7.8 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2023-29491` | `ncurses-base` | `6.2+20201114-2` -> `6.2+20201114-2+deb11u2` | 7.8 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2023-29491` | `ncurses-bin` | `6.2+20201114-2` -> `6.2+20201114-2+deb11u2` | 7.8 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2023-1999` | `libwebp6` | `0.6.1-2.1` -> `0.6.1-2.1+deb11u1` | 7.5 | 1.0% | Não | SIM |
| **P2** | 30d | `CVE-2025-69421` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u5` | 7.5 | 0.9% | Não | SIM |
| **P2** | 30d | `CVE-2025-69421` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u5` | 7.5 | 0.9% | Não | SIM |
| **P2** | 30d | `CVE-2026-63072` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 7.5 | 0.9% | Não | SIM |
| **P2** | 30d | `CVE-2026-63072` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 7.5 | 0.9% | Não | SIM |
| **P2** | 30d | `CVE-2025-69420` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u5` | 7.5 | 0.9% | Não | SIM |
| **P2** | 30d | `CVE-2025-69420` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u5` | 7.5 | 0.9% | Não | SIM |
| **P2** | 30d | `CVE-2026-28388` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u7` | 7.5 | 0.9% | Não | SIM |
| **P2** | 30d | `CVE-2026-28388` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u7` | 7.5 | 0.9% | Não | SIM |
| **P2** | 30d | `CVE-2025-32990` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u8` | 8.2 | 0.9% | Não | SIM |
| **P2** | 30d | `CVE-2026-84782` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 7.4 | 0.9% | Não | SIM |
| **P2** | 30d | `CVE-2026-84782` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 7.4 | 0.9% | Não | SIM |
| **P2** | 30d | `CVE-2026-27135` | `libnghttp2-14` | `1.43.0-1` -> `1.43.0-1+deb11u3` | 7.5 | 0.9% | Não | SIM |
| **P2** | 30d | `CVE-2020-16156` | `perl-base` | `5.32.1-4+deb11u2` -> `5.32.1-4+deb11u4` | 7.8 | 0.9% | Não | SIM |
| **P2** | 30d | `CVE-2026-28390` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u7` | 7.5 | 0.9% | Não | SIM |
| **P2** | 30d | `CVE-2026-28390` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u7` | 7.5 | 0.9% | Não | SIM |
| **P2** | 30d | `CVE-2023-25434` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u4` | 8.8 | 0.8% | Não | SIM |
| **P2** | 30d | `CVE-2026-28389` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u7` | 7.5 | 0.8% | Não | SIM |
| **P2** | 30d | `CVE-2026-28389` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u7` | 7.5 | 0.8% | Não | SIM |
| **P2** | 30d | `CVE-2023-47038` | `perl-base` | `5.32.1-4+deb11u2` -> `5.32.1-4+deb11u3` | 7.8 | 0.8% | Não | SIM |
| **P2** | 30d | `CVE-2021-3999` | `libc-bin` | `2.31-13+deb11u3` -> `2.31-13+deb11u4` | 7.8 | 0.8% | Não | SIM |
| **P2** | 30d | `CVE-2021-3999` | `libc6` | `2.31-13+deb11u3` -> `2.31-13+deb11u4` | 7.8 | 0.8% | Não | SIM |
| **P2** | 30d | `CVE-2026-7383` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u8` | 8.1 | 0.8% | Não | SIM |
| **P2** | 30d | `CVE-2026-7383` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u8` | 8.1 | 0.8% | Não | SIM |
| **P2** | 30d | `CVE-2026-33636` | `libpng16-16` | `1.6.37-3` -> `1.6.37-3+deb11u3` | 7.6 | 0.8% | Não | SIM |
| **P2** | 30d | `CVE-2026-5260` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u10` | 8.2 | 0.8% | Não | SIM |
| **P2** | 30d | `CVE-2022-31782` | `libfreetype6` | `2.10.4+dfsg-1+deb11u1` -> `Sem patch` | 7.8 | 0.8% | Não | SIM |
| **P2** | 30d | `CVE-2024-37370` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u5` | 7.5 | 0.7% | Não | SIM |
| **P2** | 30d | `CVE-2024-37370` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u5` | 7.5 | 0.7% | Não | SIM |
| **P2** | 30d | `CVE-2024-37370` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u5` | 7.5 | 0.7% | Não | SIM |
| **P2** | 30d | `CVE-2024-37370` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u5` | 7.5 | 0.7% | Não | SIM |
| **P2** | 30d | `CVE-2026-60005` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 8.2 | 0.7% | Não | SIM |
| **P2** | 30d | `CVE-2026-9076` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u8` | 7.5 | 0.7% | Não | SIM |
| **P2** | 30d | `CVE-2026-9076` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u8` | 7.5 | 0.7% | Não | SIM |
| **P2** | 30d | `CVE-2026-28387` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u7` | 8.1 | 0.7% | Não | SIM |
| **P2** | 30d | `CVE-2026-28387` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u7` | 8.1 | 0.7% | Não | SIM |
| **P2** | 30d | `CVE-2026-124709` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 7.5 | 0.7% | Não | SIM |
| **P2** | 30d | `CVE-2026-124709` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 7.5 | 0.7% | Não | SIM |
| **P2** | 30d | `CVE-2026-74860` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `Sem patch` | 8.5 | 0.7% | Não | SIM |
| **P2** | 30d | `CVE-2026-40355` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u8` | 7.5 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-40355` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u8` | 7.5 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-40355` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u8` | 7.5 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-40355` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u8` | 7.5 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-4775` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u8` | 7.8 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-41992` | `gzip` | `1.10-4+deb11u1` -> `Sem patch` | 7.5 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-5773` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 7.5 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-5773` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 7.5 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-54874` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 7.5 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-54874` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 7.5 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2025-69419` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u5` | 7.4 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2025-69419` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u5` | 7.4 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-7598` | `libssh2-1` | `1.9.0-2` -> `Sem patch` | 7.3 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-40356` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u8` | 7.5 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-40356` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u8` | 7.5 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-40356` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u8` | 7.5 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-40356` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u8` | 7.5 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2025-32415` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u7` | 7.5 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-63074` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 7.5 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-63074` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 7.5 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2025-4802` | `libc-bin` | `2.31-13+deb11u3` -> `2.31-13+deb11u13` | 7.0 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2025-4802` | `libc6` | `2.31-13+deb11u3` -> `2.31-13+deb11u13` | 7.0 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-66032` | `libssh2-1` | `1.9.0-2` -> `Sem patch` | 8.8 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-3833` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u10` | 7.4 | 0.6% | Não | SIM |
| **P2** | 30d | `CVE-2026-117610` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 7.5 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2026-57433` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 7.5 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2025-69720` | `libtinfo6` | `6.2+20201114-2` -> `Sem patch` | 7.8 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2025-69720` | `ncurses-base` | `6.2+20201114-2` -> `Sem patch` | 7.8 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2025-69720` | `ncurses-bin` | `6.2+20201114-2` -> `Sem patch` | 7.8 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2026-9538` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 7.5 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2026-52490` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 7.3 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2026-118370` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 8.2 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2026-113351` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 7.5 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2025-6020` | `libpam-modules` | `1.4.0-9+deb11u1` -> `1.4.0-9+deb11u2` | 7.8 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2025-6020` | `libpam-modules-bin` | `1.4.0-9+deb11u1` -> `1.4.0-9+deb11u2` | 7.8 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2025-6020` | `libpam-runtime` | `1.4.0-9+deb11u1` -> `1.4.0-9+deb11u2` | 7.8 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2025-6020` | `libpam0g` | `1.4.0-9+deb11u1` -> `1.4.0-9+deb11u2` | 7.8 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2026-45186` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 7.5 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2023-43787` | `libx11-6` | `2:1.7.2-1` -> `2:1.7.2-1+deb11u2` | 7.8 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2023-43787` | `libx11-data` | `2:1.7.2-1` -> `2:1.7.2-1+deb11u2` | 7.8 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2026-42011` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u10` | 7.4 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2026-115506` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 7.5 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2026-42497` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 7.5 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2026-85091` | `zlib1g` | `1:1.2.11.dfsg-2+deb11u1` -> `Sem patch` | 8.1 | 0.5% | Não | SIM |
| **P2** | 30d | `CVE-2025-64720` | `libpng16-16` | `1.6.37-3` -> `1.6.37-3+deb11u1` | 7.1 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-58050` | `libssh2-1` | `1.9.0-2` -> `Sem patch` | 7.5 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-48962` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 7.8 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2025-5222` | `libicu67` | `67.1-7` -> `67.1-7+deb11u1` | 7.0 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-77214` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 8.2 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-12912` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 7.3 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-86145` | `libpcre2-8-0` | `10.36-2` -> `Sem patch` | 8.2 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-42013` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u10` | 8.2 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-66034` | `libssh2-1` | `1.9.0-2` -> `Sem patch` | 7.5 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-93990` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 7.5 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-8932` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 7.5 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-8932` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 7.5 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-107494` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 7.5 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-107494` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 7.5 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-0861` | `libc-bin` | `2.31-13+deb11u3` -> `2.31-13+deb11u14` | 8.1 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-0861` | `libc6` | `2.31-13+deb11u3` -> `2.31-13+deb11u14` | 8.1 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2025-24928` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u6` | 7.7 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2022-3715` | `bash` | `5.1-2+deb11u1` -> `Sem patch` | 7.8 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2025-32414` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u7` | 7.5 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2025-66293` | `libpng16-16` | `1.6.37-3` -> `1.6.37-3+deb11u1` | 7.1 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-107161` | `libsasl2-2` | `2.1.27+dfsg-2.1+deb11u1` -> `Sem patch` | 7.5 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-107161` | `libsasl2-modules-db` | `2.1.27+dfsg-2.1+deb11u1` -> `Sem patch` | 7.5 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-42012` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u10` | 7.1 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-9547` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 7.4 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-9547` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 7.4 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2024-55549` | `libxslt1.1` | `1.1.34-4` -> `1.1.34-4+deb11u2` | 7.8 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2025-24855` | `libxslt1.1` | `1.1.34-4` -> `1.1.34-4+deb11u2` | 7.8 | 0.4% | Não | SIM |
| **P2** | 30d | `CVE-2026-89157` | `libpcre2-8-0` | `10.36-2` -> `Sem patch` | 7.4 | 0.3% | Não | SIM |
| **P2** | 30d | `CVE-2025-8177` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 7.8 | 0.3% | Não | SIM |
| **P2** | 30d | `CVE-2025-61144` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 7.3 | 0.3% | Não | SIM |
| **P2** | 30d | `CVE-2026-84243` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 7.0 | 0.3% | Não | SIM |
| **P2** | 30d | `CVE-2026-84243` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 7.0 | 0.3% | Não | SIM |
| **P2** | 30d | `CVE-2026-6276` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 7.5 | 0.3% | Não | SIM |
| **P2** | 30d | `CVE-2026-6276` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 7.5 | 0.3% | Não | SIM |
| **P2** | 30d | `CVE-2026-8286` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 8.1 | 0.3% | Não | SIM |
| **P2** | 30d | `CVE-2026-8286` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 8.1 | 0.3% | Não | SIM |
| **P2** | 30d | `CVE-2025-8176` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 7.8 | 0.3% | Não | SIM |
| **P2** | 30d | `CVE-2025-65018` | `libpng16-16` | `1.6.37-3` -> `1.6.37-3+deb11u1` | 7.1 | 0.3% | Não | SIM |
| **P2** | 30d | `CVE-2026-103111` | `libpcre2-8-0` | `10.36-2` -> `Sem patch` | 7.6 | 0.3% | Não | SIM |
| **P2** | 30d | `CVE-2022-49043` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u6` | 7.8 | 0.3% | Não | SIM |
| **P2** | 30d | `CVE-2026-78408` | `bsdutils` | `1:2.36.1-8+deb11u1` -> `Sem patch` | 7.9 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78408` | `libblkid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.9 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78408` | `libmount1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.9 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78408` | `libsmartcols1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.9 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78408` | `libuuid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.9 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78408` | `mount` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.9 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78408` | `util-linux` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.9 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78409` | `bsdutils` | `1:2.36.1-8+deb11u1` -> `Sem patch` | 7.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78409` | `libblkid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78409` | `libmount1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78409` | `libsmartcols1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78409` | `libuuid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78409` | `mount` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78409` | `util-linux` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-22695` | `libpng16-16` | `1.6.37-3` -> `1.6.37-3+deb11u2` | 7.1 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-76642` | `bsdutils` | `1:2.36.1-8+deb11u1` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-76642` | `libblkid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-76642` | `libmount1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-76642` | `libsmartcols1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-76642` | `libuuid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-76642` | `mount` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-76642` | `util-linux` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-57432` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 8.4 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-25210` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-86143` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `Sem patch` | 7.3 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-88806` | `libx11-6` | `2:1.7.2-1` -> `Sem patch` | 7.5 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-88806` | `libx11-data` | `2:1.7.2-1` -> `Sem patch` | 7.5 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78410` | `bsdutils` | `1:2.36.1-8+deb11u1` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78410` | `libblkid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78410` | `libmount1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78410` | `libsmartcols1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78410` | `libuuid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78410` | `mount` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-78410` | `util-linux` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-52492` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 7.3 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-86144` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-53615` | `bsdutils` | `1:2.36.1-8+deb11u1` -> `Sem patch` | 8.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-53615` | `libblkid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 8.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-53615` | `libmount1` | `2.36.1-8+deb11u1` -> `Sem patch` | 8.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-53615` | `libsmartcols1` | `2.36.1-8+deb11u1` -> `Sem patch` | 8.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-53615` | `libuuid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 8.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-53615` | `mount` | `2.36.1-8+deb11u1` -> `Sem patch` | 8.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-53615` | `util-linux` | `2.36.1-8+deb11u1` -> `Sem patch` | 8.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-53613` | `bsdutils` | `1:2.36.1-8+deb11u1` -> `Sem patch` | 7.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-53613` | `libblkid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-53613` | `libmount1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-53613` | `libsmartcols1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-53613` | `libuuid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-53613` | `mount` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-53613` | `util-linux` | `2.36.1-8+deb11u1` -> `Sem patch` | 7.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-86140` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-86142` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `Sem patch` | 7.8 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-54369` | `libacl1` | `2.2.53-10` -> `Sem patch` | 7.1 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2025-68973` | `gpgv` | `2.2.27-2+deb11u2` -> `2.2.27-2+deb11u3` | 7.0 | 0.2% | Não | SIM |
| **P2** | 30d | `CVE-2026-76957` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 7.8 | 0.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-11979` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `Sem patch` | 7.8 | 0.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-29111` | `libsystemd0` | `247.3-7` -> `247.3-7+deb11u8` | 7.8 | 0.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-29111` | `libudev1` | `247.3-7` -> `247.3-7+deb11u8` | 7.8 | 0.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-52491` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 7.3 | 0.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-22801` | `libpng16-16` | `1.6.37-3` -> `1.6.37-3+deb11u2` | 7.8 | 0.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-86138` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `Sem patch` | 7.8 | 0.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-89161` | `libpcre2-8-0` | `10.36-2` -> `Sem patch` | 7.8 | 0.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-86139` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `Sem patch` | 7.8 | 0.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-95818` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 7.0 | 0.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-95818` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 7.0 | 0.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-86805` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 7.0 | 0.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-86805` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 7.0 | 0.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-16742` | `libsystemd0` | `247.3-7` -> `Sem patch` | 8.8 | 0.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-16742` | `libudev1` | `247.3-7` -> `Sem patch` | 8.8 | 0.1% | Não | SIM |
| **P2** | 30d | `CVE-2026-9672` | `libgd3` | `2.3.0-2` -> `2.3.0-2+deb11u2` | 8.1 | N/A | Não | SIM |
| **P2** | 30d | `CVE-2026-71199` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 8.1 | N/A | Não | SIM |
| **P2** | 30d | `CVE-2026-71199` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 8.1 | N/A | Não | SIM |
| **P2** | 30d | `CVE-2026-71199` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 8.1 | N/A | Não | SIM |
| **P2** | 30d | `CVE-2026-71199` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 8.1 | N/A | Não | SIM |
| **P2** | 30d | `CVE-2026-107364` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | N/A | Não | SIM |
| **P2** | 30d | `CVE-2026-71200` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | N/A | Não | SIM |
| **P2** | 30d | `CVE-2026-107364` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | N/A | Não | SIM |
| **P2** | 30d | `CVE-2026-71200` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | N/A | Não | SIM |
| **P2** | 30d | `CVE-2026-107364` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | N/A | Não | SIM |
| **P2** | 30d | `CVE-2026-71200` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | N/A | Não | SIM |
| **P2** | 30d | `CVE-2026-107364` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | N/A | Não | SIM |
| **P2** | 30d | `CVE-2026-71200` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.5 | N/A | Não | SIM |
| **P2** | 30d | `CVE-2026-118380` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.4 | N/A | Não | SIM |
| **P2** | 30d | `CVE-2026-118380` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.4 | N/A | Não | SIM |
| **P2** | 30d | `CVE-2026-118380` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.4 | N/A | Não | SIM |
| **P2** | 30d | `CVE-2026-118380` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 7.4 | N/A | Não | SIM |
| **P3** | 90d | `CVE-2009-4487` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 6.8 | 26.8% | Não | SIM |
| **P3** | 90d | `CVE-2022-4304` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u4` | 5.9 | 23.5% | Não | SIM |
| **P3** | 90d | `CVE-2022-4304` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u4` | 5.9 | 23.5% | Não | SIM |
| **P3** | 90d | `CVE-2024-7264` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u13` | 6.5 | 20.2% | Não | SIM |
| **P3** | 90d | `CVE-2024-7264` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u13` | 6.5 | 20.2% | Não | SIM |
| **P3** | 90d | `CVE-2013-0340` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 6.8 | 19.4% | Não | SIM |
| **P3** | 90d | `CVE-2024-9143` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u2` | 4.3 | 12.5% | Não | SIM |
| **P3** | 90d | `CVE-2024-9143` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u2` | 4.3 | 12.5% | Não | SIM |
| **P3** | 90d | `CVE-2022-32208` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 5.9 | 8.4% | Não | SIM |
| **P3** | 90d | `CVE-2022-32208` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 5.9 | 8.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-3446` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1v-0~deb11u1` | 5.3 | 6.5% | Não | SIM |
| **P3** | 90d | `CVE-2023-3446` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1v-0~deb11u1` | 5.3 | 6.5% | Não | SIM |
| **P3** | 90d | `CVE-2023-38546` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u10` | 3.7 | 6.0% | Não | SIM |
| **P3** | 90d | `CVE-2023-38546` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u10` | 3.7 | 6.0% | Não | SIM |
| **P3** | 90d | `CVE-2021-22924` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 3.7 | 5.9% | Não | SIM |
| **P3** | 90d | `CVE-2021-22924` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 3.7 | 5.9% | Não | SIM |
| **P3** | 90d | `CVE-2023-5678` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u2` | 5.3 | 5.1% | Não | SIM |
| **P3** | 90d | `CVE-2023-5678` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u2` | 5.3 | 5.1% | Não | SIM |
| **P3** | 90d | `CVE-2022-2097` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u4` | 5.3 | 4.9% | Não | SIM |
| **P3** | 90d | `CVE-2022-2097` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u4` | 5.3 | 4.9% | Não | SIM |
| **P3** | 90d | `CVE-2021-22898` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 3.1 | 4.5% | Não | SIM |
| **P3** | 90d | `CVE-2021-22898` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 3.1 | 4.5% | Não | SIM |
| **P3** | 90d | `CVE-2021-22922` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 4.3% | Não | SIM |
| **P3** | 90d | `CVE-2021-22922` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 4.3% | Não | SIM |
| **P3** | 90d | `CVE-2022-35252` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u3` | 3.7 | 4.1% | Não | SIM |
| **P3** | 90d | `CVE-2022-35252` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u3` | 3.7 | 4.1% | Não | SIM |
| **P3** | 90d | `CVE-2022-27776` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 6.5 | 4.1% | Não | SIM |
| **P3** | 90d | `CVE-2022-27776` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 6.5 | 4.1% | Não | SIM |
| **P3** | 90d | `CVE-2019-1010024` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 5.3 | 3.2% | Não | SIM |
| **P3** | 90d | `CVE-2019-1010024` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 5.3 | 3.2% | Não | SIM |
| **P3** | 90d | `CVE-2024-0727` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u2` | 5.5 | 3.2% | Não | SIM |
| **P3** | 90d | `CVE-2024-0727` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u2` | 5.5 | 3.2% | Não | SIM |
| **P3** | 90d | `CVE-2023-3817` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1v-0~deb11u1` | 5.3 | 3.0% | Não | SIM |
| **P3** | 90d | `CVE-2023-3817` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1v-0~deb11u1` | 5.3 | 3.0% | Não | SIM |
| **P3** | 90d | `CVE-2021-22947` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 5.9 | 3.0% | Não | SIM |
| **P3** | 90d | `CVE-2021-22947` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 5.9 | 3.0% | Não | SIM |
| **P3** | 90d | `CVE-2017-9937` | `libjbig0` | `2.1-3.1+b2` -> `Sem patch` | 6.5 | 2.9% | Não | SIM |
| **P3** | 90d | `CVE-2023-36054` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u4` | 6.5 | 2.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-36054` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u4` | 6.5 | 2.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-36054` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u4` | 6.5 | 2.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-36054` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u4` | 6.5 | 2.8% | Não | SIM |
| **P3** | 90d | `CVE-2022-43552` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u5` | 5.9 | 2.8% | Não | SIM |
| **P3** | 90d | `CVE-2022-43552` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u5` | 5.9 | 2.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-28320` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.9 | 2.7% | Não | SIM |
| **P3** | 90d | `CVE-2023-28320` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.9 | 2.7% | Não | SIM |
| **P3** | 90d | `CVE-2010-4756` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 4.0 | 2.6% | Não | SIM |
| **P3** | 90d | `CVE-2010-4756` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 4.0 | 2.6% | Não | SIM |
| **P3** | 90d | `CVE-2020-15719` | `libldap-2.4-2` | `2.4.57+dfsg-3+deb11u1` -> `Sem patch` | 4.2 | 2.5% | Não | SIM |
| **P3** | 90d | `CVE-2019-1010025` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 5.3 | 2.5% | Não | SIM |
| **P3** | 90d | `CVE-2019-1010025` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 5.3 | 2.5% | Não | SIM |
| **P3** | 90d | `CVE-2015-9019` | `libxslt1.1` | `1.1.34-4` -> `Sem patch` | 5.3 | 2.4% | Não | SIM |
| **P3** | 90d | `CVE-2024-28085` | `bsdutils` | `1:2.36.1-8+deb11u1` -> `2.36.1-8+deb11u2` | 3.3 | 2.2% | Não | SIM |
| **P3** | 90d | `CVE-2024-28085` | `libblkid1` | `2.36.1-8+deb11u1` -> `2.36.1-8+deb11u2` | 3.3 | 2.2% | Não | SIM |
| **P3** | 90d | `CVE-2024-28085` | `libmount1` | `2.36.1-8+deb11u1` -> `2.36.1-8+deb11u2` | 3.3 | 2.2% | Não | SIM |
| **P3** | 90d | `CVE-2024-28085` | `libsmartcols1` | `2.36.1-8+deb11u1` -> `2.36.1-8+deb11u2` | 3.3 | 2.2% | Não | SIM |
| **P3** | 90d | `CVE-2024-28085` | `libuuid1` | `2.36.1-8+deb11u1` -> `2.36.1-8+deb11u2` | 3.3 | 2.2% | Não | SIM |
| **P3** | 90d | `CVE-2024-28085` | `mount` | `2.36.1-8+deb11u1` -> `2.36.1-8+deb11u2` | 3.3 | 2.2% | Não | SIM |
| **P3** | 90d | `CVE-2024-28085` | `util-linux` | `2.36.1-8+deb11u1` -> `2.36.1-8+deb11u2` | 3.3 | 2.2% | Não | SIM |
| **P3** | 90d | `CVE-2023-28322` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u9` | 3.7 | 2.2% | Não | SIM |
| **P3** | 90d | `CVE-2023-28322` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u9` | 3.7 | 2.2% | Não | SIM |
| **P3** | 90d | `CVE-2022-27774` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 5.7 | 2.0% | Não | SIM |
| **P3** | 90d | `CVE-2022-27774` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u2` | 5.7 | 2.0% | Não | SIM |
| **P3** | 90d | `CVE-2021-22923` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 2.0% | Não | SIM |
| **P3** | 90d | `CVE-2021-22923` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 2.0% | Não | SIM |
| **P3** | 90d | `CVE-2024-9681` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 2.0% | Não | SIM |
| **P3** | 90d | `CVE-2024-9681` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 2.0% | Não | SIM |
| **P3** | 90d | `CVE-2023-4813` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 5.9 | 1.9% | Não | SIM |
| **P3** | 90d | `CVE-2023-4813` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 5.9 | 1.9% | Não | SIM |
| **P3** | 90d | `CVE-2022-34526` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 6.5 | 1.9% | Não | SIM |
| **P3** | 90d | `CVE-2021-38115` | `libgd3` | `2.3.0-2` -> `2.3.0-2+deb11u1` | 6.5 | 1.9% | Não | SIM |
| **P3** | 90d | `CVE-2024-2379` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.3 | 1.9% | Não | SIM |
| **P3** | 90d | `CVE-2024-2379` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.3 | 1.9% | Não | SIM |
| **P3** | 90d | `CVE-2022-1210` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 6.5 | 1.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-6277` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 6.5 | 1.8% | Não | SIM |
| **P3** | 90d | `CVE-2018-10126` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 6.5 | 1.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-28321` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u9` | 5.9 | 1.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-28321` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u9` | 5.9 | 1.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-27535` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u8` | 5.9 | 1.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-27535` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u8` | 5.9 | 1.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-0465` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u5` | 5.3 | 1.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-0466` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u5` | 5.3 | 1.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-0465` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u5` | 5.3 | 1.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-0466` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1n-0+deb11u5` | 5.3 | 1.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-27536` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u8` | 5.9 | 1.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-27536` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u8` | 5.9 | 1.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-23916` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u7` | 6.5 | 1.7% | Não | SIM |
| **P3** | 90d | `CVE-2023-23916` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u7` | 6.5 | 1.7% | Não | SIM |
| **P3** | 90d | `CVE-2022-1622` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 5.5 | 1.7% | Não | SIM |
| **P3** | 90d | `CVE-2023-46218` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u11` | 6.5 | 1.7% | Não | SIM |
| **P3** | 90d | `CVE-2023-46218` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u11` | 6.5 | 1.7% | Não | SIM |
| **P3** | 90d | `CVE-2021-40812` | `libgd3` | `2.3.0-2` -> `2.3.0-2+deb11u1` | 6.5 | 1.7% | Não | SIM |
| **P3** | 90d | `CVE-2023-4806` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 5.9 | 1.6% | Não | SIM |
| **P3** | 90d | `CVE-2023-4806` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 5.9 | 1.6% | Não | SIM |
| **P3** | 90d | `CVE-2019-6129` | `libpng16-16` | `1.6.37-3` -> `Sem patch` | 6.5 | 1.6% | Não | SIM |
| **P3** | 90d | `CVE-2022-48303` | `tar` | `1.34+dfsg-1` -> `1.34+dfsg-1+deb11u1` | 5.5 | 1.5% | Não | SIM |
| **P3** | 90d | `CVE-2023-27538` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u8` | 5.5 | 1.5% | Não | SIM |
| **P3** | 90d | `CVE-2023-27538` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u8` | 5.5 | 1.5% | Não | SIM |
| **P3** | 90d | `CVE-2020-13529` | `libsystemd0` | `247.3-7` -> `Sem patch` | 6.1 | 1.4% | Não | SIM |
| **P3** | 90d | `CVE-2020-13529` | `libudev1` | `247.3-7` -> `Sem patch` | 6.1 | 1.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-5981` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u4` | 5.9 | 1.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-40745` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u5` | 6.5 | 1.4% | Não | SIM |
| **P3** | 90d | `CVE-2022-2519` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 6.5 | 1.4% | Não | SIM |
| **P3** | 90d | `CVE-2022-2521` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 6.5 | 1.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-125283` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 5.3 | 1.4% | Não | SIM |
| **P3** | 90d | `CVE-2022-3627` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 6.5 | 1.4% | Não | SIM |
| **P3** | 90d | `CVE-2025-13151` | `libtasn1-6` | `4.16.0-2` -> `Sem patch` | 5.9 | 1.4% | Não | SIM |
| **P3** | 90d | `CVE-2016-3709` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u5` | 6.1 | 1.4% | Não | SIM |
| **P3** | 90d | `CVE-2022-2520` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 6.5 | 1.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-40403` | `libxslt1.1` | `1.1.34-4` -> `1.1.34-4+deb11u3` | 6.5 | 1.3% | Não | SIM |
| **P3** | 90d | `CVE-2022-2058` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 6.5 | 1.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-29469` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u4` | 6.5 | 1.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-41175` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u5` | 6.5 | 1.3% | Não | SIM |
| **P3** | 90d | `CVE-2024-12243` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u7` | 5.3 | 1.3% | Não | SIM |
| **P3** | 90d | `CVE-2025-4598` | `libsystemd0` | `247.3-7` -> `247.3-7+deb11u7` | 4.7 | 1.3% | Não | SIM |
| **P3** | 90d | `CVE-2025-4598` | `libudev1` | `247.3-7` -> `247.3-7+deb11u7` | 4.7 | 1.3% | Não | SIM |
| **P3** | 90d | `CVE-2022-3597` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 6.5 | 1.3% | Não | SIM |
| **P3** | 90d | `CVE-2022-3599` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 6.5 | 1.3% | Não | SIM |
| **P3** | 90d | `CVE-2022-2056` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 6.5 | 1.3% | Não | SIM |
| **P3** | 90d | `CVE-2022-2057` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 6.5 | 1.3% | Não | SIM |
| **P3** | 90d | `CVE-2022-3598` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 6.5 | 1.3% | Não | SIM |
| **P3** | 90d | `CVE-2022-3626` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 6.5 | 1.3% | Não | SIM |
| **P3** | 90d | `CVE-2022-1623` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 5.5 | 1.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-28484` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u4` | 6.5 | 1.2% | Não | SIM |
| **P3** | 90d | `CVE-2024-33600` | `libc-bin` | `2.31-13+deb11u3` -> `2.31-13+deb11u10` | 5.3 | 1.2% | Não | SIM |
| **P3** | 90d | `CVE-2024-33600` | `libc6` | `2.31-13+deb11u3` -> `2.31-13+deb11u10` | 5.3 | 1.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-75806` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.3 | 1.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-75806` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.3 | 1.2% | Não | SIM |
| **P3** | 90d | `CVE-2011-3374` | `apt` | `2.2.4` -> `Sem patch` | 3.7 | 1.2% | Não | SIM |
| **P3** | 90d | `CVE-2011-3374` | `libapt-pkg6.0` | `2.2.4` -> `Sem patch` | 3.7 | 1.2% | Não | SIM |
| **P3** | 90d | `CVE-2023-3618` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u6` | 6.5 | 1.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-92391` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 1.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-92391` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 1.2% | Não | SIM |
| **P3** | 90d | `CVE-2024-2236` | `libgcrypt20` | `1.8.7-6` -> `Sem patch` | 5.9 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2023-46219` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2023-46219` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2023-3316` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u6` | 6.5 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2024-26461` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.9 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2024-26461` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.9 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2024-26461` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.9 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2024-26461` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.9 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2024-50602` | `libexpat1` | `2.2.10-2+deb11u3` -> `2.2.10-2+deb11u7` | 5.9 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2024-12133` | `libtasn1-6` | `4.16.0-2` -> `4.16.0-2+deb11u2` | 5.3 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-86409` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-86409` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2022-1056` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 5.5 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2023-39615` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u6` | 6.5 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2021-46822` | `libjpeg62-turbo` | `1:2.0.6-4` -> `Sem patch` | 5.5 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2024-33601` | `libc-bin` | `2.31-13+deb11u3` -> `2.31-13+deb11u10` | 4.0 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2024-33601` | `libc6` | `2.31-13+deb11u3` -> `2.31-13+deb11u10` | 4.0 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-42766` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u8` | 5.9 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-42766` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u8` | 5.9 | 1.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-92387` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2026-92387` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2023-50495` | `libtinfo6` | `6.2+20201114-2` -> `Sem patch` | 6.5 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2023-50495` | `ncurses-base` | `6.2+20201114-2` -> `Sem patch` | 6.5 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2023-50495` | `ncurses-bin` | `6.2+20201114-2` -> `Sem patch` | 6.5 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2023-4039` | `gcc-10-base` | `10.2.1-6` -> `Sem patch` | 4.8 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2023-4039` | `gcc-9-base` | `9.3.0-22` -> `Sem patch` | 4.8 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2023-4039` | `libgcc-s1` | `10.2.1-6` -> `Sem patch` | 4.8 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2023-4039` | `libstdc++6` | `10.2.1-6` -> `Sem patch` | 4.8 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2026-112315` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.3 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2026-112315` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.3 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2026-112315` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.3 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2026-112315` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.3 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2026-112319` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.5 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2026-112319` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.5 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2026-112319` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.5 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2026-112319` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.5 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2026-87862` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2026-87862` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2023-45322` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u6` | 6.5 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2026-0990` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u10` | 5.9 | 1.0% | Não | SIM |
| **P3** | 90d | `CVE-2022-40090` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 6.5 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2007-5686` | `login` | `1:4.8.1-1` -> `Sem patch` | 4.9 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2007-5686` | `passwd` | `1:4.8.1-1` -> `Sem patch` | 4.9 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2026-112317` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.3 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2026-112317` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.3 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2026-112317` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.3 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2026-112317` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.3 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2026-112318` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.5 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2026-112318` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.5 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2026-112318` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.5 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2026-112318` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.5 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2023-23915` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2023-23915` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2026-112316` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.5 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2026-112316` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.5 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2026-112316` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.5 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2026-112316` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.5 | 0.9% | Não | SIM |
| **P3** | 90d | `CVE-2023-7008` | `libsystemd0` | `247.3-7` -> `247.3-7+deb11u6` | 5.9 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2023-7008` | `libudev1` | `247.3-7` -> `247.3-7+deb11u6` | 5.9 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2026-86412` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2026-86412` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2026-92386` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 4.3 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2026-92386` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 4.3 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2026-87863` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2026-87864` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2026-87863` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2026-87864` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2022-4415` | `libsystemd0` | `247.3-7` -> `247.3-7+deb11u2` | 5.5 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2022-4415` | `libudev1` | `247.3-7` -> `247.3-7+deb11u2` | 5.5 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2024-8096` | `curl` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u14` | 6.5 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2024-8096` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `7.74.0-1.3+deb11u14` | 6.5 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2024-26458` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.9 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2024-26458` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.9 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2024-26458` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.9 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2024-26458` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.9 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2026-94265` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.1 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2026-94265` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.1 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2025-6395` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u8` | 6.5 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2026-86410` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.8 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2026-86410` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.8 | 0.8% | Não | SIM |
| **P3** | 90d | `CVE-2024-13176` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u3` | 4.1 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2024-13176` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u3` | 4.1 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-35191` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 3.7 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-35191` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 3.7 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-86413` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-86413` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-6253` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.9 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-6253` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.9 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-42015` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u10` | 5.3 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2024-28834` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u6` | 5.3 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-92389` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-92389` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-19931` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-19931` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-54873` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.3 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-54873` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.3 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-107928` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 4.8 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-107928` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 4.8 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-92388` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-92388` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2025-14524` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2025-14524` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-86414` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-86414` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-87861` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-87861` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2023-43785` | `libx11-6` | `2:1.7.2-1` -> `2:1.7.2-1+deb11u2` | 5.5 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2023-43785` | `libx11-data` | `2:1.7.2-1` -> `2:1.7.2-1+deb11u2` | 5.5 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-107929` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2026-107929` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2025-14831` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u9` | 5.3 | 0.7% | Não | SIM |
| **P3** | 90d | `CVE-2025-15661` | `libssh2-1` | `1.9.0-2` -> `Sem patch` | 6.5 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-123640` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 5.3 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-82560` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | N/A | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-84784` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.3 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-84784` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.3 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-0915` | `libc-bin` | `2.31-13+deb11u3` -> `2.31-13+deb11u14` | 5.3 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-0915` | `libc6` | `2.31-13+deb11u3` -> `2.31-13+deb11u14` | 5.3 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-12087` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 5.3 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2021-36086` | `libsepol1` | `3.1-1` -> `3.1-1+deb11u1` | 3.3 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-92390` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-92390` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-22796` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u5` | 5.3 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-22796` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u5` | 5.3 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-19487` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 6.5 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-127040` | `libgnutls30` | `3.7.1-5+deb11u1` -> `Sem patch` | N/A | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2022-2953` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 5.5 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-132138` | `libsasl2-2` | `2.1.27+dfsg-2.1+deb11u1` -> `Sem patch` | 5.3 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-132138` | `libsasl2-modules-db` | `2.1.27+dfsg-2.1+deb11u1` -> `Sem patch` | 5.3 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-48959` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 5.0 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-18924` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-80229` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-18924` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-80229` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2022-1355` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 6.1 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2022-1354` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 5.5 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-94266` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.3 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2026-94266` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.3 | 0.6% | Não | SIM |
| **P3** | 90d | `CVE-2025-15079` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2025-15079` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-107708` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 4.9 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-107708` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 4.9 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-107708` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 4.9 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-107708` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 4.9 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-34743` | `liblzma5` | `5.2.5-2.1~deb11u1` -> `5.2.5-2.1~deb11u2` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2017-16231` | `libpcre3` | `2:8.39-13` -> `Sem patch` | 5.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2021-4214` | `libpng16-16` | `1.6.37-3` -> `Sem patch` | 5.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-75804` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-75804` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-87865` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-87865` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2022-3570` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 5.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2011-4116` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 3.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-6429` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-6429` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-5450` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 5.0 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-5450` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 5.0 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2023-30774` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 5.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-87866` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-87866` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2025-24528` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u6` | 6.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2025-24528` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u6` | 6.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2025-24528` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u6` | 6.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2025-24528` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u6` | 6.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-0989` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u10` | 3.7 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-56434` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 6.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-13608` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-13608` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2025-40909` | `perl-base` | `5.32.1-4+deb11u2` -> `5.32.1-4+deb11u5` | 5.9 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-3783` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-3783` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2025-15281` | `libc-bin` | `2.31-13+deb11u3` -> `2.31-13+deb11u14` | 5.9 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2025-15281` | `libc6` | `2.31-13+deb11u3` -> `2.31-13+deb11u14` | 5.9 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-42772` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-42772` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-54875` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 4.7 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-54875` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 4.7 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-5704` | `tar` | `1.34+dfsg-1` -> `Sem patch` | 5.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-54872` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.9 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-54872` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.9 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2025-15224` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.1 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2025-15224` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.1 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-80255` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-80255` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2025-6297` | `dpkg` | `1.20.11` -> `1.20.14` | N/A | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2023-43786` | `libx11-6` | `2:1.7.2-1` -> `2:1.7.2-1+deb11u2` | 5.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2023-43786` | `libx11-data` | `2:1.7.2-1` -> `2:1.7.2-1+deb11u2` | 5.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2021-36087` | `libsepol1` | `3.1-1` -> `3.1-1+deb11u1` | 3.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-7168` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-7168` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-126765` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 3.7 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-126765` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 3.7 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2013-4392` | `libsystemd0` | `247.3-7` -> `Sem patch` | 3.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2013-4392` | `libudev1` | `247.3-7` -> `Sem patch` | 3.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2025-27587` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | N/A | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2025-27587` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | N/A | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-120967` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 4.8 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-121481` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 3.7 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-121481` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 3.7 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2024-22365` | `libpam-modules` | `1.4.0-9+deb11u1` -> `1.4.0-9+deb11u2` | 5.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2024-22365` | `libpam-modules-bin` | `1.4.0-9+deb11u1` -> `1.4.0-9+deb11u2` | 5.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2024-22365` | `libpam-runtime` | `1.4.0-9+deb11u1` -> `1.4.0-9+deb11u2` | 5.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2024-22365` | `libpam0g` | `1.4.0-9+deb11u1` -> `1.4.0-9+deb11u2` | 5.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-0992` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u10` | 2.9 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2022-48281` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 5.5 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2021-36084` | `libsepol1` | `3.1-1` -> `3.1-1+deb11u1` | 3.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-121758` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | N/A | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-121758` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | N/A | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-3184` | `bsdutils` | `1:2.36.1-8+deb11u1` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-3184` | `libblkid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-3184` | `libmount1` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-3184` | `libsmartcols1` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-3184` | `libuuid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-3184` | `mount` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-3184` | `util-linux` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-124024` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | N/A | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-124024` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | N/A | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2021-36085` | `libsepol1` | `3.1-1` -> `3.1-1+deb11u1` | 3.3 | 0.5% | Não | SIM |
| **P3** | 90d | `CVE-2026-95692` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 4.8 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-95692` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 4.8 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-3784` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-3784` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-107778` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-107778` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-107778` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-107778` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-122054` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-122054` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-77696` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-77696` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2022-3821` | `libsystemd0` | `247.3-7` -> `247.3-7+deb11u2` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2022-3821` | `libudev1` | `247.3-7` -> `247.3-7+deb11u2` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-86411` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-86411` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2022-0563` | `bsdutils` | `1:2.36.1-8+deb11u1` -> `Sem patch` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2022-0563` | `libblkid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2022-0563` | `libmount1` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2022-0563` | `libsmartcols1` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2022-0563` | `libuuid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2022-0563` | `mount` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2022-0563` | `util-linux` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2016-2781` | `coreutils` | `8.32-4+b1` -> `Sem patch` | 6.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-0800` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u4` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-0801` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u4` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-0802` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u4` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-0803` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u4` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-0804` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u4` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2025-10966` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 4.3 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2025-10966` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 4.3 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2024-56433` | `login` | `1:4.8.1-1` -> `Sem patch` | 3.6 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2024-56433` | `passwd` | `1:4.8.1-1` -> `Sem patch` | 3.6 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-29383` | `login` | `1:4.8.1-1` -> `1:4.8.1-1+deb11u1` | 3.3 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-29383` | `passwd` | `1:4.8.1-1` -> `1:4.8.1-1+deb11u1` | 3.3 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2022-4645` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-0799` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u4` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-5545` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-5545` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-2908` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u6` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-0795` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u4` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-0796` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u4` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-0797` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u4` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-0798` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u4` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-85977` | `libtirpc-common` | `1.3.1-1` -> `Sem patch` | 5.3 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-85977` | `libtirpc3` | `1.3.1-1` -> `Sem patch` | 5.3 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-86415` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-86415` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-26966` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u6` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-25433` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u6` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-127039` | `libgnutls30` | `3.7.1-5+deb11u1` -> `Sem patch` | N/A | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-6228` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-82208` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 4.8 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-82208` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 4.8 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-134703` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | N/A | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-41080` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 2.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-97629` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 6.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2024-33602` | `libc-bin` | `2.31-13+deb11u3` -> `2.31-13+deb11u10` | 4.0 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2024-33602` | `libc6` | `2.31-13+deb11u3` -> `2.31-13+deb11u10` | 4.0 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-107496` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-107496` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-4046` | `libc-bin` | `2.31-13+deb11u3` -> `2.31-13+deb11u14` | 5.3 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-4046` | `libc6` | `2.31-13+deb11u3` -> `2.31-13+deb11u14` | 5.3 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-72897` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-72897` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-102633` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-52426` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2024-28835` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u6` | 5.0 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-43788` | `libxpm4` | `1:3.5.12-1` -> `1:3.5.12-1.1+deb11u1` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-35189` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 3.7 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-35189` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 3.7 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-5928` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 5.0 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-5928` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 5.0 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-127231` | `libgnutls30` | `3.7.1-5+deb11u1` -> `Sem patch` | N/A | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-26965` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u6` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-8458` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-8458` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-80230` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-80230` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.7 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-1916` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 6.1 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-75805` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-75805` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-43789` | `libxpm4` | `1:3.5.12-1` -> `1:3.5.12-1.1+deb11u1` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-82209` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.1 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-82209` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 3.1 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-121482` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.3 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-121482` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.3 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-6238` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 6.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-6238` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 6.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-77117` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-80489` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-77117` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-80489` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2025-3576` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u7` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2025-3576` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u7` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2025-3576` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u7` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2025-3576` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `1.18.3-6+deb11u7` | 5.9 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2026-7017` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 6.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2025-0395` | `libc-bin` | `2.31-13+deb11u3` -> `2.31-13+deb11u12` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2025-0395` | `libc6` | `2.31-13+deb11u3` -> `2.31-13+deb11u12` | 5.5 | 0.4% | Não | SIM |
| **P3** | 90d | `CVE-2023-31439` | `libsystemd0` | `247.3-7` -> `Sem patch` | 5.3 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-31439` | `libudev1` | `247.3-7` -> `Sem patch` | 5.3 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-95101` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 5.3 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2017-14159` | `libldap-2.4-2` | `2.4.57+dfsg-3+deb11u1` -> `Sem patch` | 4.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-25435` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u4` | 5.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2017-18018` | `coreutils` | `8.32-4+b1` -> `Sem patch` | 4.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-31437` | `libsystemd0` | `247.3-7` -> `Sem patch` | 5.3 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-31437` | `libudev1` | `247.3-7` -> `Sem patch` | 5.3 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2025-6170` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u8` | 2.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-100290` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 3.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-100290` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 3.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-4873` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.9 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-4873` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 5.9 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-31438` | `libsystemd0` | `247.3-7` -> `Sem patch` | 5.3 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-31438` | `libudev1` | `247.3-7` -> `Sem patch` | 5.3 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2022-2869` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 5.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2022-2867` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 5.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2022-2868` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 5.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-54411` | `libpam-modules` | `1.4.0-9+deb11u1` -> `Sem patch` | 4.8 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-54411` | `libpam-modules-bin` | `1.4.0-9+deb11u1` -> `Sem patch` | 4.8 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-54411` | `libpam-runtime` | `1.4.0-9+deb11u1` -> `Sem patch` | 4.8 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-54411` | `libpam0g` | `1.4.0-9+deb11u1` -> `Sem patch` | 4.8 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-3576` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u5` | 5.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-3164` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 5.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-8674` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 5.3 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-8674` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 5.3 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2025-5278` | `coreutils` | `8.32-4+b1` -> `Sem patch` | 4.4 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2013-4235` | `login` | `1:4.8.1-1` -> `Sem patch` | 4.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2013-4235` | `passwd` | `1:4.8.1-1` -> `Sem patch` | 4.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-30086` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u3` | 5.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-121757` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | N/A | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-121757` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | N/A | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-19499` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 6.8 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-19499` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 6.8 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-1965` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-1965` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-85231` | `libtirpc-common` | `1.3.1-1` -> `Sem patch` | 6.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-85231` | `libtirpc3` | `1.3.1-1` -> `Sem patch` | 6.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-30775` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 5.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-89156` | `libpcre2-8-0` | `10.36-2` -> `Sem patch` | 5.9 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2022-3219` | `gpgv` | `2.2.27-2+deb11u2` -> `Sem patch` | 3.3 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-53910` | `diffutils` | `1:3.7-5` -> `Sem patch` | 5.3 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-58051` | `libssh2-1` | `1.9.0-2` -> `Sem patch` | 6.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-95691` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.4 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-95691` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.4 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-39804` | `tar` | `1.34+dfsg-1` -> `1.34+dfsg-1+deb11u1` | 6.2 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2025-11731` | `libxslt1.1` | `1.1.34-4` -> `Sem patch` | 3.1 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-97399` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 3.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-97399` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 3.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-95690` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.3 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-95690` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.3 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-89160` | `libpcre2-8-0` | `10.36-2` -> `Sem patch` | 6.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-88823` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 3.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-88823` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 3.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2025-9165` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 3.3 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2024-10041` | `libpam-modules` | `1.4.0-9+deb11u1` -> `Sem patch` | 4.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2024-10041` | `libpam-modules-bin` | `1.4.0-9+deb11u1` -> `Sem patch` | 4.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2024-10041` | `libpam-runtime` | `1.4.0-9+deb11u1` -> `Sem patch` | 4.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2024-10041` | `libpam0g` | `1.4.0-9+deb11u1` -> `Sem patch` | 4.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-115819` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 4.8 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-115819` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 4.8 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-48961` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 5.0 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-11850` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.0 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-11850` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.0 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-11850` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.0 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-11850` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 5.0 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-88822` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 3.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-88822` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 3.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-90439` | `nginx` | `1.23.0-1~bullseye` -> `Sem patch` | 6.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-15534` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 5.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-4641` | `login` | `1:4.8.1-1` -> `1:4.8.1-1+deb11u1` | 5.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2023-4641` | `passwd` | `1:4.8.1-1` -> `1:4.8.1-1+deb11u1` | 5.5 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2025-8732` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u10` | 3.3 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-75803` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 3.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-75803` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 3.7 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-58055` | `libnghttp2-14` | `1.43.0-1` -> `Sem patch` | 5.4 | 0.3% | Não | SIM |
| **P3** | 90d | `CVE-2026-91094` | `dpkg` | `1.20.11` -> `Sem patch` | N/A | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-124317` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | N/A | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-89158` | `libpcre2-8-0` | `10.36-2` -> `Sem patch` | 6.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-8961` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 3.3 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-32777` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 5.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-89092` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 4.2 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-89092` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 4.2 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-88647` | `libgnutls30` | `3.7.1-5+deb11u1` -> `Sem patch` | N/A | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-5435` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 5.9 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-5435` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 5.9 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-35190` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.9 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-35190` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.9 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-7010` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | N/A | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-84786` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.9 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-84786` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 5.9 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2024-13978` | `libtiff5` | `4.2.0-1+deb11u1` -> `4.2.0-1+deb11u7` | 2.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-19542` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 4.2 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-19542` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 4.2 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-8058` | `libc-bin` | `2.31-13+deb11u3` -> `2.31-13+deb11u14` | 4.2 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-8058` | `libc6` | `2.31-13+deb11u3` -> `2.31-13+deb11u14` | 4.2 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-9820` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u9` | 4.0 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-8534` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 2.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-6791` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 5.9 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-6791` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 5.9 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-1757` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u10` | 6.2 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-66382` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 5.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-14104` | `bsdutils` | `1:2.36.1-8+deb11u1` -> `Sem patch` | 6.1 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-14104` | `libblkid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 6.1 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-14104` | `libmount1` | `2.36.1-8+deb11u1` -> `Sem patch` | 6.1 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-14104` | `libsmartcols1` | `2.36.1-8+deb11u1` -> `Sem patch` | 6.1 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-14104` | `libuuid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 6.1 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-14104` | `mount` | `2.36.1-8+deb11u1` -> `Sem patch` | 6.1 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-14104` | `util-linux` | `2.36.1-8+deb11u1` -> `Sem patch` | 6.1 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-8851` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 5.3 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-94283` | `libx11-6` | `2:1.7.2-1` -> `Sem patch` | 6.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-94283` | `libx11-data` | `2:1.7.2-1` -> `Sem patch` | 6.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-6141` | `libtinfo6` | `6.2+20201114-2` -> `Sem patch` | 3.3 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-6141` | `ncurses-base` | `6.2+20201114-2` -> `Sem patch` | 3.3 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-6141` | `ncurses-bin` | `6.2+20201114-2` -> `Sem patch` | 3.3 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-95184` | `libgnutls30` | `3.7.1-5+deb11u1` -> `Sem patch` | 5.3 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-64505` | `libpng16-16` | `1.6.37-3` -> `1.6.37-3+deb11u1` | 6.1 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-40930` | `libpng16-16` | `1.6.37-3` -> `Sem patch` | 5.4 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-88648` | `libgnutls30` | `3.7.1-5+deb11u1` -> `Sem patch` | N/A | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-104357` | `libtirpc-common` | `1.3.1-1` -> `Sem patch` | 4.8 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-104357` | `libtirpc3` | `1.3.1-1` -> `Sem patch` | 4.8 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-24515` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 2.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-95210` | `libgnutls30` | `3.7.1-5+deb11u1` -> `Sem patch` | N/A | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-34757` | `libpng16-16` | `1.6.37-3` -> `1.6.37-3+deb11u4` | 4.4 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-86137` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `Sem patch` | 6.1 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-56412` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 5.9 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-30258` | `gpgv` | `2.2.27-2+deb11u2` -> `Sem patch` | 4.7 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-72522` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 6.2 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-32778` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 5.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-32776` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 5.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-50219` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 5.9 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-68160` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u5` | 4.7 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-68160` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u5` | 4.7 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-56406` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 6.9 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-56407` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 6.9 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-56392` | `coreutils` | `8.32-4+b1` -> `Sem patch` | 6.1 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-22185` | `libldap-2.4-2` | `2.4.57+dfsg-3+deb11u1` -> `Sem patch` | 6.8 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-56131` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 4.9 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-56403` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 6.9 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-95512` | `libfreetype6` | `2.10.4+dfsg-1+deb11u1` -> `Sem patch` | 5.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-40228` | `libsystemd0` | `247.3-7` -> `Sem patch` | 3.3 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-40228` | `libudev1` | `247.3-7` -> `Sem patch` | 3.3 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-22795` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u5` | 5.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-22795` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u5` | 5.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-10911` | `libxslt1.1` | `1.1.34-4` -> `Sem patch` | 5.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-67693` | `libgnutls30` | `3.7.1-5+deb11u1` -> `Sem patch` | N/A | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-28162` | `libpng16-16` | `1.6.37-3` -> `Sem patch` | 5.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-28164` | `libpng16-16` | `1.6.37-3` -> `Sem patch` | 5.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-9714` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `2.9.10+dfsg-6.7+deb11u9` | 5.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-4105` | `libsystemd0` | `247.3-7` -> `247.3-7+deb11u8` | 6.7 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-4105` | `libudev1` | `247.3-7` -> `247.3-7+deb11u8` | 6.7 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-15059` | `libsystemd0` | `247.3-7` -> `Sem patch` | 5.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-15059` | `libudev1` | `247.3-7` -> `Sem patch` | 5.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2025-61145` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 5.0 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-27456` | `bsdutils` | `1:2.36.1-8+deb11u1` -> `Sem patch` | 4.7 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-27456` | `libblkid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 4.7 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-27456` | `libmount1` | `2.36.1-8+deb11u1` -> `Sem patch` | 4.7 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-27456` | `libsmartcols1` | `2.36.1-8+deb11u1` -> `Sem patch` | 4.7 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-27456` | `libuuid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 4.7 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-27456` | `mount` | `2.36.1-8+deb11u1` -> `Sem patch` | 4.7 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-27456` | `util-linux` | `2.36.1-8+deb11u1` -> `Sem patch` | 4.7 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-56132` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 6.9 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-76781` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `Sem patch` | 5.5 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-89162` | `libpcre2-8-0` | `10.36-2` -> `Sem patch` | 3.3 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-13757` | `libp11-kit0` | `0.23.22-1` -> `Sem patch` | 6.2 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-13595` | `bsdutils` | `1:2.36.1-8+deb11u1` -> `Sem patch` | 5.3 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-13595` | `libblkid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.3 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-13595` | `libmount1` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.3 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-13595` | `libsmartcols1` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.3 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-13595` | `libuuid1` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.3 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-13595` | `mount` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.3 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-13595` | `util-linux` | `2.36.1-8+deb11u1` -> `Sem patch` | 5.3 | 0.2% | Não | SIM |
| **P3** | 90d | `CVE-2026-42014` | `libgnutls30` | `3.7.1-5+deb11u1` -> `3.7.1-5+deb11u10` | 6.6 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-40225` | `libsystemd0` | `247.3-7` -> `247.3-7+deb11u8` | 6.4 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-40225` | `libudev1` | `247.3-7` -> `247.3-7+deb11u8` | 6.4 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2025-64506` | `libpng16-16` | `1.6.37-3` -> `1.6.37-3+deb11u1` | 6.1 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-107493` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `Sem patch` | 3.7 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-107493` | `openssl` | `1.1.1n-0+deb11u3` -> `Sem patch` | 3.7 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-5958` | `sed` | `4.7-1` -> `Sem patch` | 6.3 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-3713` | `libpng16-16` | `1.6.37-3` -> `Sem patch` | 5.3 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-94285` | `libx11-6` | `2:1.7.2-1` -> `Sem patch` | 5.1 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-94285` | `libx11-data` | `2:1.7.2-1` -> `Sem patch` | 5.1 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-56404` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 6.9 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-54371` | `libattr1` | `1:2.4.48-6` -> `Sem patch` | 6.3 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-56410` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 6.9 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-56411` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 6.9 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-18374` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 4.9 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-18374` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 4.9 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-56405` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 6.9 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-56408` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 6.9 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-18508` | `tar` | `1.34+dfsg-1` -> `Sem patch` | 4.4 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2025-61143` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 5.5 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-56409` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | 6.5 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-94284` | `libx11-6` | `2:1.7.2-1` -> `Sem patch` | 5.5 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-94284` | `libx11-data` | `2:1.7.2-1` -> `Sem patch` | 5.5 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2025-69418` | `libssl1.1` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u5` | 4.0 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2025-69418` | `openssl` | `1.1.1n-0+deb11u3` -> `1.1.1w-0+deb11u5` | 4.0 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-56391` | `coreutils` | `8.32-4+b1` -> `Sem patch` | 6.1 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-4367` | `libxpm4` | `1:3.5.12-1` -> `Sem patch` | 5.5 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-94287` | `libxpm4` | `1:3.5.12-1` -> `Sem patch` | 5.5 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-105712` | `gpgv` | `2.2.27-2+deb11u2` -> `Sem patch` | 3.6 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2025-15649` | `perl-base` | `5.32.1-4+deb11u2` -> `Sem patch` | 6.5 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-42250` | `libbz2-1.0` | `1.0.8-4` -> `Sem patch` | 5.0 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-86141` | `libxml2` | `2.9.10+dfsg-6.7+deb11u2` -> `Sem patch` | 3.3 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-18495` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | 6.1 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-41991` | `gzip` | `1.10-4+deb11u1` -> `Sem patch` | 4.7 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2025-14017` | `curl` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.3 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2025-14017` | `libcurl4` | `7.74.0-1.3+deb11u1` -> `Sem patch` | 6.3 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2025-68972` | `gpgv` | `2.2.27-2+deb11u2` -> `Sem patch` | 4.7 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-102474` | `dash` | `0.5.11+git20200708+dd9ef66-5` -> `Sem patch` | 4.0 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-128241` | `libexpat1` | `2.2.10-2+deb11u3` -> `Sem patch` | N/A | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-18938` | `libp11-kit0` | `0.23.22-1` -> `Sem patch` | 6.2 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-6368` | `libc-bin` | `2.31-13+deb11u3` -> `Sem patch` | 5.5 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-6368` | `libc6` | `2.31-13+deb11u3` -> `Sem patch` | 5.5 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-18477` | `tar` | `1.34+dfsg-1` -> `Sem patch` | 4.4 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-102473` | `dash` | `0.5.11+git20200708+dd9ef66-5` -> `Sem patch` | 5.5 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-54370` | `libacl1` | `2.2.53-10` -> `Sem patch` | 6.3 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-40226` | `libsystemd0` | `247.3-7` -> `247.3-7+deb11u8` | 6.4 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-40226` | `libudev1` | `247.3-7` -> `247.3-7+deb11u8` | 6.4 | 0.1% | Não | SIM |
| **P3** | 90d | `CVE-2026-107884` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.7 | N/A | Não | SIM |
| **P3** | 90d | `CVE-2026-107884` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.7 | N/A | Não | SIM |
| **P3** | 90d | `CVE-2026-107884` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.7 | N/A | Não | SIM |
| **P3** | 90d | `CVE-2026-107884` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 6.7 | N/A | Não | SIM |
| **P3** | 90d | `CVE-2026-46675` | `libpng16-16` | `1.6.37-3` -> `Sem patch` | 5.9 | N/A | Não | SIM |
| **P3** | 90d | `CVE-2026-111423` | `libgssapi-krb5-2` | `1.18.3-6+deb11u1` -> `Sem patch` | 4.2 | N/A | Não | SIM |
| **P3** | 90d | `CVE-2026-111423` | `libk5crypto3` | `1.18.3-6+deb11u1` -> `Sem patch` | 4.2 | N/A | Não | SIM |
| **P3** | 90d | `CVE-2026-111423` | `libkrb5-3` | `1.18.3-6+deb11u1` -> `Sem patch` | 4.2 | N/A | Não | SIM |
| **P3** | 90d | `CVE-2026-111423` | `libkrb5support0` | `1.18.3-6+deb11u1` -> `Sem patch` | 4.2 | N/A | Não | SIM |
| **P3** | 90d | `CVE-2026-36849` | `libtiff5` | `4.2.0-1+deb11u1` -> `Sem patch` | N/A | N/A | Não | SIM |

## 4. Mapeamento de Governança e Compliance

- **PCI_DSS:** Req. 6.3.1 / 6.3.3 (Identificação e remediação de vulnerabilidades)
- **NIST_CSF:** ID.RA-01 / DE.CM-09 (Avaliação de Risco e Monitoramento Contínuo)
- **CIS_CONTROLS:** CIS Control 7 (Continuous Vulnerability Management)
