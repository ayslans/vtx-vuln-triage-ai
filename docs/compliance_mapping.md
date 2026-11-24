# Mapeamento de Compliance — vtx-vuln-triage-ai

Este documento mapeia os controles implementados no pipeline aos requisitos de **PCI-DSS v4.0**, **NIST CSF 2.0** e **CIS Controls v8**.

## 1. Matriz de Rastreabilidade

| Etapa do Pipeline | PCI-DSS v4.0 | NIST CSF 2.0 | CIS Controls v8 | Evidência Gerada |
| :--- | :--- | :--- | :--- | :--- |
| Varredura automatizada de imagens (`docker-compose.yml` + Trivy) | **Req. 6.3.1** (Identificação contínua de vulnerabilidades) | **ID.RA-01** (Vulnerabilidades em ativos identificadas e registradas) | **Control 7.1 / 7.5** (Processo e varredura automatizada) | `data/raw/*.json` |
| Enriquecimento com CISA KEV e FIRST EPSS (`enrichers/`) | **Req. 6.3.1** (Uso de fontes confiáveis de inteligência) | **ID.RA-02** (Recebimento de inteligência de ameaças) | **Control 7.2** (Remediação orientada a risco) | Campos `in_cisa_kev` e `epss_score` no boletim |
| Classificação por escopo e SLA (`config/pci_policy.yaml` + `pci_engine.py`) | **Req. 6.3.3** (Priorização e remediação dentro de janelas definidas) | **ID.RA-05** (Priorização de ameaças e vulnerabilidades) | **Control 7.3 / 7.4** (Atualização contínua de SO e apps) | Prioridade `P0–P3`, SLA e `rationale` por CVE |
| Troca de imagem base e controles compensatórios (`docs/evidence/`) | **Req. 6.3.3 / Apêndice B** (Mitigação e controles compensatórios) | **PR.PS-02** (Manutenção e substituição de software) | **Control 7.7** (Remediação de vulnerabilidades detectadas) | Comparativo Antes vs. Depois em `docs/evidence/` |
| Boletim executivo e técnico (`markdown_renderer.py`) | **Req. 12.10 / Governança** (Comunicação estruturada de riscos) | **GV.RM-01** (Gestão e comunicação de riscos) | **Control 7.1** (Revisão periódica do processo) | `triage_report.md` |

## 2. Política de SLAs (`config/pci_policy.yaml`)

| Prioridade | Critério de Acionamento | SLA | Ação Operacional Esperada |
| :---: | :--- | :---: | :--- |
| **P0** | CISA KEV confirmada em ativo em escopo PCI (`CDE` ou `CONNECTED`) | **2 dias** | Patch emergencial, troca de imagem base ou controle compensatório imediato (WAF/isolamento). |
| **P1** | CISA KEV fora do CDE, `CVSS >= 9.0` ou `EPSS >= 70%` | **7 dias** | Correção prioritária na sprint atual. |
| **P2** | `CVSS >= 7.0` ou `EPSS >= 30%` | **30 dias** | Remediação dentro da janela padrão PCI-DSS Req. 6.3.3. |
| **P3** | Demais achados sem exploração ativa | **90 dias** | Tratamento em manutenção regular ou aceitação formal de risco. |

## 3. Evidências Auditáveis no Repositório

- **Antes (Imagem Legada — `nginx:1.23.0`):** `docs/evidence/legacy_nginx_1.23/triage_report.md` (1.115 achados | 7 P0 | 55 P1)
- **Depois (Imagem Remediada — `nginx:1.27-alpine`):** `docs/evidence/remediated_nginx_1.27_alpine/triage_report.md` (219 achados | 2 P0 | 13 P1 | 0 sem patch)

## 4. Limite de Escopo (Disclaimer)

Este mapeamento apoia a operação de gestão de vulnerabilidades (Blue Team / AppSec) e **não** substitui auditorias oficiais (QSA/ASV) nem garante conformidade regulatória isoladamente.
