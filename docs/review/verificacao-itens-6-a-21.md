# Verificação consolidada — itens 6 a 21

Autor: **Claude Code**. Percorrendo de 6 a 21 a pedido do proprietário, no modo
"verificar + implementar lacunas". Itens pares são engenharia do Codex (já
parcialmente prontos): verifico e preencho lacunas de forma aditiva, re-mesclando
a `main` conforme ele entrega. Log atualizado por item.

> Legenda: **[FATO]** existe e verificado · **[LACUNA→feito]** faltava e implementei · **[PENDENTE]** depende de ferramenta externa/decisão/Codex.

## Item 6 — Engenharia reversa (par; Codex) — verificado + 1 lacuna preenchida
- **[FATO]** `reverse_engineering.analyze` (cópia verificada, hash, entropia, assinatura), `firmware` (Intel HEX, Motorola S-record com checksum, cabeçalhos ELF/PE com limites, `compare_firmware`), `automotive` (CAN clássico) — tudo estático, sem execução nem modificação de dispositivo.
- **[FATO]** identificação de arquitetura/máquina em ELF/PE (campo `machine`), cabeçalhos e limites de seções validados.
- **[LACUNA→feito]** **Extração de strings** não existia. Implementada em `reverse_engineering/strings.py` (`Core.extract_strings`, CLI `strings`): runs ASCII e UTF-16LE de um prefixo limitado, com `min_length`/`max_strings`; as strings vão ao operador e a auditoria registra **apenas contagens** (conteúdo de evidência não entra na auditoria).
- **[PENDENTE]** Integração de Ghidra/Capstone/Binwalk (ferramentas externas não instaladas) e desmontagem — declarado pendente (itens pares/Fase 4, com o Codex); não afirmar o que não foi executado.

## Item 8 — Perícia digital (par; Codex) — verificado + 1 lacuna preenchida
- **[FATO]** cópia verificada + SHA-256, preservação do original, auditoria encadeada (origem, data UTC, operações, hashes), relatório pericial (`reporting.write_report`), verificação de integridade (`verification/artifacts`).
- **[LACUNA→feito]** **Linha do tempo / cadeia de custódia** como artefato dedicado. `Core.custody_timeline` (CLI `custody`) monta, a partir da auditoria encadeada, uma linha cronológica por caso (sequência, UTC, evento, digest, e campos auditados como sha256/cópia/origem/ator) + lista de aquisições, confere a integridade da cadeia e declara as limitações (tamper-evident, não assinatura digital). Lê só metadados já auditados.
- **[PENDENTE]** Autopsy/Sleuth Kit/YARA e análise de imagem de disco completa — ferramentas externas, declarado pendente (Fase 5, com o Codex).

## Item 9 — Pesquisa de vulnerabilidades (ímpar; Claude) — lacuna preenchida (estático/autorizado)
- **[LACUNA→feito]** Não havia auditoria de vulnerabilidades. Implementada **estrita e estática**: `vulnerability/audit_config` (`Core.audit_config`, CLI `audit-config`) lê um prefixo limitado de um arquivo **autorizado** e sinaliza, por padrão, segredos expostos (senha/chave/token/private key/AWS id) e configurações inseguras (DEBUG on, verificação TLS desligada, PermitRootLogin yes, http://, hashes fracos). Severidades alto/médio/baixo.
- **Garantias:** sem teste ativo, sem rede, sem ferramentas externas; valores de segredos **redigidos**; auditoria registra só contagens por severidade. Correspondência é indício a verificar, não prova de falha.
- **[PENDENTE]** Nmap/Wireshark/Semgrep/OWASP ZAP/YARA e testes ativos em laboratório autorizado — ferramentas externas / escopo ativo, declarado pendente (Fase 6, com o Codex).
