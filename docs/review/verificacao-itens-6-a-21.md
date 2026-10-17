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

## Item 10 — Análise de protocolos (par; Codex) — verificado + 1 lacuna preenchida
- **[FATO]** `automotive` analisa/compara logs CAN clássicos (passivo).
- **[LACUNA→feito]** Analisador **genérico e passivo** de capturas: `protocol/analyze_capture`/`compare_captures` (`Core.analyze_capture`, CLI `analyze-capture` com `--compare-to`). Captura textual, uma mensagem por linha em hex (separadores espaço/":"/","/"-"; id opcional antes de '#'/'|'); reporta contagem, pulados, payloads únicos, histogramas de tamanho e id, e diff entre capturas. Passivo: nunca abre barramento/dispositivo/socket.
- **[PENDENTE]** USB/UART/SPI/I2C e integração python-can/cantools/SavvyCAN/Wireshark — exigem hardware/ferramentas externas, declarado pendente.

## Item 11 — Motor de pesquisa técnica (ímpar; Claude) — verificado + 1 lacuna preenchida
- **[FATO]** registro de fontes (`research` / `Workflow.add_source`): título, url, versão, proveniência, autor; sem busca web implícita (coerente com o escopo).
- **[LACUNA→feito]** diferenciação de **autoridade da fonte**: `research/classify_source` (`Core.classify_source`, CLI `classify-source`) rotula oficial/acadêmica/comunidade/desconhecida por heurística de domínio, offline; `Core.sources` (CLI `sources`) lista as fontes do caso já com a autoridade. Honesto: heurística a confirmar, nenhuma requisição de rede.
- **[PENDENTE]** Consulta automática a bases/documentação quando houver conectividade autorizada — fora do modo offline atual; declarado pendente.

## Item 13 — Verificação independente (ímpar; Claude) — lacuna preenchida
- **[FATO]** `Workflow.finalize` já exige evidência verificável, testes reproduzíveis, comparação com resultado esperado e documentação de limitações antes de "resolvido"; revisão independente obrigatória (bloqueia auto-revisão).
- **[LACUNA→feito]** O escopo lista **7 estados possíveis**; `finalize` só aceitava 4 (faltavam "Aguardando informações" e "Aguardando autorização"). Adicionados como estados **não-terminais** (não exigem portões de evidência/revisão, como já era o caso de "Aguardando recursos"); `validated` permanece `false` para eles.
- **[PENDENTE]** nada identificado; os 7 estados do escopo estão todos cobertos agora.
