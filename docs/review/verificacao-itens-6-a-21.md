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

## Item 13 — Verificação independente (ímpar; Claude) — lacuna preenchida (correção: minha 1ª tentativa estava incompleta)
- **[FATO]** `Workflow.finalize` já exige evidência verificável, testes reproduzíveis, comparação com resultado esperado e documentação de limitações antes de "resolvido"; revisão independente obrigatória (bloqueia auto-revisão).
- **[LACUNA→feito, 1ª passada]** O escopo lista **7 estados possíveis**; `finalize` só aceitava 4. Adicionei "Aguardando informações" e "Aguardando autorização" — mas isso levou a 6, não 7. **Eu afirmei erroneamente que os 7 estavam cobertos**; faltava "Falha de execução". Esse erro foi corretamente apontado pela revisão cruzada do Codex no PR #9.
- **[LACUNA→feito, correção]** Adicionado `FALHA DE EXECUCAO` como 7º estado (declara falha operacional, não conclusão científica); como os demais estados não-terminais, não passa pelos portões de evidência/revisão e `validated` permanece `false`. `reopen()` agora também volta `FALHA DE EXECUCAO` para `EM INVESTIGACAO` quando chega trabalho novo (mesmo tratamento de `RESOLVIDO`/`SEM SOLUCAO VIAVEL DEMONSTRADA`). Testes de regressão em `tests/test_verification_states.py` (inclusive que a declaração de falha não é bloqueada pela própria tarefa falha que a origina).
- **[PENDENTE]** nada identificado; os 7 estados do escopo estão todos cobertos agora — desta vez verificado contando de fato.

## Item 15 — Interface do sistema (ímpar; Claude) — lacuna preenchida
- **[FATO]** terminal funcional cobre: criar investigação (`investigate`), selecionar arquivo/definir objetivo/informar autorização e escopo (parte de `investigate`), acompanhar tarefas e progresso (`status`), visualizar hipóteses (`hypothesis list`), pausar/retomar/cancelar (`pause`/`resume`/`cancel`), consultar memória (`history`, `recall`), exportar relatórios (`report`).
- **[LACUNA→feito]** "Ver logs" não tinha comando dedicado (só `status`, que não inclui o log de auditoria). Adicionado `cyber logs <caso>` (expõe `Core.audit` + `verify_audit` — o log bruto encadeado por hash, distinto do `custody`, que é uma visão derivada para perícia).
- **[PENDENTE]** interface gráfica Windows (Fase 9) — corretamente posterior à validação do núcleo, como o escopo pede.

## Correção de honestidade documental — docs/roadmap.md
Durante a verificação, encontrada uma afirmação **desatualizada e falsa**: "Não há (...) buscas de vulnerabilidades, recuperação de senhas (...) nesta entrega" — mas os itens 7 e 9 desta sessão já implementam exatamente isso (de forma limitada/autorizada/estática). Corrigido no próprio `docs/roadmap.md` para refletir o estado real sem exagerar: recuperação de senha é só autoteste em arquivo próprio; auditoria de vulnerabilidade é só estática/autorizada, sem rede. O que permanece ausente (pesquisa web automática, extração de chaves, malware, gravação automotiva, varredura ativa) continua declarado como ausente.

## Itens 16, 17, 19, 20, 21 — verificados (sem lacuna de código a preencher)

- **Item 16 — Estrutura do repositório (par; Codex).** Decisão já registrada em `docs/roadmap.md`: raiz do repositório é a raiz do pacote (`src/cyber_core/`), sem árvore aninhada `core/agents/modules/` do escopo literal. Divergência de layout **documentada e deliberada**, não lacuna; mudar a árvore agora seria reestruturação de alto risco sobre código ativo do Codex — não feito sem decisão conjunta.
- **Item 17 — Integração GitHub (ímpar; Claude).** **Correção de atribuição:** a versão anterior deste documento atribuía por engano o item 17 ao Codex (par); 17 é **ímpar**, portanto meu — achado corretamente apontado pela revisão do Codex no PR #9. Verificado por mim: Git/branches/PRs/CI com permissões de leitura/histórico de decisões/documentação técnica — **[FATO]**, cobertos por este próprio fluxo de PRs (múltiplos commits testados e validados antes de cada push, nesta mesma branch). Git Worktrees para agentes paralelos: **[PENDENTE]**, depende de infraestrutura multiagente ainda não construída. Proteção de branch: tentei consultar via API e, como o Codex já relatou, a consulta é negada/restrita pelo plano do repositório — não dá para afirmar se proteções estão configuradas ou ausentes a partir daqui; registrado como limitação de visibilidade, não como lacuna de código.
- **Item 19 — Etapas de implementação.** É o próprio plano de fases; vive em `docs/roadmap.md`, agora corrigido para refletir o estado real (ver acima) em vez de uma lista estática desatualizada.
- **Item 20 — Critérios de entrega.** Processo (implementar → instalar deps → testar → corrigir → retestar → registrar → documentar → declarar funcional/pendente → avançar). Seguido em cada item desta sessão: toda mudança desta sessão rodou `compileall` + suíte completa + `demo.py` antes do commit, com contagem de testes registrada no commit e em `docs/validation.md`. Nenhum resultado de teste foi inventado.
- **Item 21 — Instrução final (papéis).** Já versionado como parte de `docs/escopo.md` §21 (o próprio texto de escopo fornecido pelo proprietário). Nada a implementar em código; é uma instrução de papel/processo para o Codex, já cumprida nesta colaboração (fundação e núcleo entregues antes do Claude Code, sem depender dele).

Nenhum destes itens exigiu invenção de funcionalidade para "parecer completo": onde a dependência é externa (worktrees, hardware, ferramentas profissionais) ou é decisão deliberada de layout, fica declarado como tal.

## Correções dos 5 achados do PR #9 (revisão cruzada do Codex)

O PR #9 (mergeado na main) combinou o candidato Claude (70deac2) com a main num runner do GitHub e reproduziu 5 pendências reais no código ímpar deste agente. Todas corrigidas, com regressão:

- **F1 (alta) — segredo vazava por outro achado na mesma linha.** `vulnerability._redact_line` agora redige TODOS os valores sensíveis da linha (inclusive o valor inteiro de regras sem grupo, como `aws_access_key_id`, via sentinela `group=-1`) antes de montar qualquer excerto — não apenas o da própria regra. Testes: `test_secret_not_leaked_through_another_finding_on_same_line`, `test_aws_key_itself_is_redacted`.
- **F2 (média) — pausa ignorada nas rotas novas.** `Core._ensure_not_paused` adicionado e aplicado em `audit_config`, `differentiate_content`, `extract_strings`, `analyze_capture`, `classify`, `plan`, `decompose`, `assign`, `self_test_recovery`, `make_lab_envelope` — mesmo padrão já usado em `cryptanalysis/intake.py`/`orchestrator`. Testes: `tests/test_review_fixes.py::PauseGuardTests`.
- **F3 (média) — análises novas não reconstruíveis pelo histórico normal.** Nova tabela `side_analyses` (esquema SQLite **8**, aditivo); `Core._persist_side_analysis`/`side_analyses` persistem o resultado completo (já sem segredo) de `strings`/`differentiate`/`config_audit`/`capture`; `reporting.write_report` agora inclui `side_analyses`; CLI `side-analyses`. Testes: `tests/test_review_fixes.py::SideAnalysisPersistenceTests`.
- **F4 (média) — captura truncada sem aviso.** `Core.analyze_capture` lia o arquivo inteiro antes de recortar; agora lê só `max_sample` + 1 byte de espreita (mesmo padrão de `differentiate_content`/`extract_strings`), e propaga `truncated`/`sample_truncated` corretamente mesmo quando a truncagem é só de bytes (não de contagem de mensagens), em ambos os arquivos no modo de comparação. Testes: `tests/test_review_fixes.py::CaptureTruncationTests`.
- **F5 (média) — classificação incorreta de domínios semelhantes.** `research._matches` usava `endswith` sem fronteira de domínio (`"unrelated-ietf.org".endswith("ietf.org")` → `True`, falso positivo). Corrigido para exigir igualdade exata ou subdomínio delimitado por ponto para marcadores de domínio completo; marcadores de categoria (`.gov`, `.edu`) continuam corretos como estavam (já tinham o ponto). Testes: `test_similar_domain_is_not_misclassified`, `test_real_subdomain_still_matches`.

Validação: **242 testes OK** (227 + 15 de regressão), `compileall` e `demo.py` (exit 0); confirmação ponta a ponta pela CLI dos 3 cenários exatos relatados (segredo redigido nos dois achados; pausa recusando `audit-config`; domínio semelhante → `unknown`).

Os demais pontos do PR #9 (integração plena ao pipeline de tarefas/fila do item 12/14, allowlist de 4 operações do processo filho supervisionado cobrindo as rotas novas, unificação dos 7 estados do item 13 também no lado do Codex) permanecem como trabalho conjunto futuro — não forçados aqui para não colidir com o item 12/14/18 do Codex.

## Item 15 — Interface do sistema: pendência final fechada (PR #9)

A revisão cruzada do Codex (PR #9) apontou a última pendência real do item 15: "roteiro de teste pessoal simples no GitHub com cenários sintéticos e saídas claras", pedido pelo próprio proprietário (PR #8, teste pessoal sem login).

- `scripts/try-me.py`: roteiro narrado em português, saída **PASSOU/FALHOU** legível (não JSON técnico), para o proprietário rodar e entender sem ler código. Exercita de ponta a ponta: criar investigação, analisar arquivo, classificar/planejar, auditoria de config (segredo redigido), auditoria de implementação cripto (ECB detectado), autoteste de recuperação (senha fraca própria), RSA/ECC/ChaCha20 reais, backup/restauração em diretório novo, integridade da cadeia de auditoria.
- Termina com resumo honesto: quantas verificações passaram, lista exata de falhas (se houver — nunca inventa resultado), e as limitações reais (sintético, sem ferramentas profissionais, sem hardware, `platform_complete` seria `false`).
- Adicionado ao CI (`.github/workflows/ci.yml`), rodando junto do `demo.py` em cada execução.

Execução local: **9 de 9 verificações passaram**, exit 0. Suíte completa: 290 testes OK; demo exit 0.
