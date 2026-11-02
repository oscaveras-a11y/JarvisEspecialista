# Analisadores offline adicionais (itens 9, 10, 11) — 2026-11-02

Comando: `cyber offline-analyze CASE KIND PATH` (arquivo dentro do escopo autorizado, até 8 MiB, nada é executado nem transmitido).

| KIND | Item | O que faz | Limite honesto |
|---|---|---|---|
| `secrets` | 9 | Regras tipo Gitleaks (AWS, GitHub, Slack, JWT, chave privada, atribuição genérica); achado sempre mascarado | Regras fixas; não valida o segredo |
| `sca` | 9 | requirements*.txt / package.json contra lista de advisories **fornecida** (`--advisories`) | Sem base própria; versão declarada ≠ instalada |
| `nmap-xml` | 9 | Interpreta XML do Nmap já produzido; recusa DOCTYPE/ENTITY | **Não executa Nmap** |
| `nvd-json` | 11 | Interpreta resposta NVD API 2.0 (CVE, CVSS, severidade) | Não consulta o NVD; use `research-fetch` com `--allow-host services.nvd.nist.gov` e salve o arquivo |
| `canfd` | 10 | candump `ID##flags dados` (até 64 bytes, DLC válidos, BRS/ESI) | CRC não verificável; `analyze-can` clássico segue inalterado |
| `uart` | 10 | Decodifica CSV `t,rx` (baud, paridade) | Só amostras; sem sondagem de hardware |
| `i2c` | 10 | CSV `t,sda,scl`: START/STOP, endereço, R/W, ACK, dados | idem |
| `spi` | 10 | CSV `t,cs,clk,mosi,miso`, modos CPOL/CPHA, 8 bits | idem |

Testes: `tests/test_extra_analyzers.py` (formas de onda e arquivos sintéticos).

## Não fechado nesta rodada (declarado)
- **Semgrep** e **Nmap** reais: não integrados como execução (exigem binário externo e política de rede); só interpretamos a saída.
- Item 8 (Autopsy/TSK/recuperação de apagados), 6 (decompilação/firmware automotivo real), 14 (sandbox de rede/privilégios), 12 (limite rígido de RAM/CPU e custo), 3 (credenciais reais de API), 13 (reconfirmar inconsistência de estados), 17 (proteção de branch — não verificada via API), 15 (painel web ainda demonstração): **não alterados**. Nada aqui os fecha.
- Ambiente (item 2): o produto roda em Linux/container GitHub; o escopo cita Windows 8 GB. Divergência existe e permanece não resolvida; deve ser decidida pelo proprietário.
