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

## Item 9/7 — expansão das auditorias estáticas (regras adicionais)

A pedido do proprietário, continuei escrevendo código: ampliei as duas auditorias estáticas já existentes com padrões de segurança reais e bem conhecidos, mantendo o mesmo rigor (indício a verificar, nunca prova; segredos sempre redigidos).

**Item 9 — `vulnerability/__init__.py`** (5 regras novas):
- `insecure_deserialization` — `pickle.loads`/`pickle.load`/`Unpickler` (execução arbitrária de código sobre dado não confiável).
- `unsafe_yaml_load` — `yaml.load(...)` sem `Loader=` explícito na mesma linha (não sinaliza quando usa `SafeLoader`, testado).
- `jwt_alg_none` — `"alg": "none"` em cabeçalho JWT (falsificação de token).
- `cors_wildcard` — `Access-Control-Allow-Origin: *`.
- `sql_string_concat` — f-string com palavra-chave SQL e interpolação (indício de injeção).

**Item 7 — `cryptanalysis/implementation_audit.py`** (1 regra nova):
- `insufficient_kdf_iterations` — `PBKDF2(...iterations=N...)` com N conhecidamente baixo (1/10/100/1000/2000/4096/10000); não sinaliza valores altos (testado com 600000).

Validação: **296 testes OK** (290 + 6: 5 em `test_vulnerability.py` + 1 em `test_implementation_audit.py`), `compileall`, `demo.py` e `try-me.py` (exit 0). Confirmado ponta a ponta pela CLI num arquivo com `yaml.load`/`pickle.loads`/SQL por f-string — as três regras disparam corretamente.

## Itens 8/10 (pares do Codex) — CORE/CLI wiring de forensics/disk.py e protocols_pcap.py

Com o Codex parado, o proprietário autorizou explicitamente ("Assumo tudo, inclusive pares... sempre sem apagar o trabalho já feito pelo Codex, só completando") que eu também complete os itens pares. Os PRs de rascunho do Codex #13 (item 6, Ghidra/Binwalk), #14 (agents-broker, `ClaudeAdapter` real) e #15 (item 8/10, `forensics/disk.py` + `protocols_pcap.py`) foram integrados via merge de teste (`git merge --no-commit --no-ff`) e, após validação completa, commitados nesta branch — sem descartar nenhum código já escrito por ele. O PR #12 (candidato duplicado, mesmas correções F1-F5 que eu já havia corrigido) recebeu apenas um comentário explicativo, sem merge, para não sobrescrever a correção já testada.

Os módulos `forensics/disk.py` (`inspect_disk_image`) e `protocols_pcap.py` (`inspect_pcap`) do PR #15 são funções puras (sem I/O, sem dependência externa) que o próprio Codex deixou declaradamente como "etapa separada" a integração ao CORE/CLI. Essa etapa é o que completei agora:

- **`Core.inspect_disk_image(case, path, *, sector_size=512, max_bytes=16MiB, max_partitions=256)`** — `authorize` → `_ensure_not_paused` → limite de bytes (`min(self.max_bytes, max_bytes)`, leitura integral pois o módulo precisa da imagem completa para validar CRCs do GPT, não há "espreita" por faixa de bytes) → chama `forensics.disk.inspect_disk_image`, convertendo `ValueError` em `CoreError` → persiste resultado completo em `side_analyses` (kind `disk_inventory`) → audita apenas `format`/`sha256` (nunca a lista de partições/trilha completa no log de auditoria).
- **`Core.inspect_pcap(case, path, *, max_bytes=16MiB, max_packets=256)`** — mesmo padrão; audita apenas contagem de pacotes e `sha256`.
- CLI: novos subcomandos `inspect-disk` (`--sector-size`, `--max-bytes`, `--max-partitions`) e `inspect-pcap` (`--max-bytes`, `--max-packets`); `side-analyses --kind` passou a listar também `disk_inventory`/`pcap_inventory`.
- Testes novos: `tests/test_forensics_protocols_service.py` (arquivo novo, separado do `tests/test_forensics_protocols.py` já existente do Codex com os testes unitários dos módulos — não tocado) — caminho feliz com imagem MBR sintética mínima e PCAP clássico sintético mínimo, rejeição com investigação pausada, rejeição por limite de bytes, imagem/captura inválida convertida em `CoreError`, persistência em `side_analyses` reconstrutível, e integridade da cadeia de auditoria.

Validação: suíte completa **354 testes OK** (skipped=8), `compileall -q src scripts tests`, `demo.py` e `try-me.py` (exit 0). Confirmado ponta a ponta via CLI real num diretório `/tmp` isolado: `investigate` → `inspect-disk` → `inspect-pcap` → `side-analyses`, com os dois resultados aparecendo corretamente persistidos.

## Item 12 (par do Codex) — controle de RAM e CPU por processo de agente

A fila/execução assíncrona/checkpoints/retomada/cancelamento seguro/pausa-retomada/limite de tentativas/detecção de tarefa travada (lease) e tratamento de erros de conexão/autenticação/rate-limit do item 12 já existiam (`Core.enqueue`/`run_one`/`run_queue`/`cancel`/`pause`/`resume`/`checkpoints`, `AgentResourceError` em `agents/runner.py`). O controle de custo de API por caso também já existia (`agent_calls_per_case`, aplicado em `orchestrator/__init__.py` e `orchestrator/broker.py`). O que faltava, e foi adicionado agora: **limites de RAM e CPU por processo filho do agente**, que não existiam antes.

- `agents/runner.py::run_bounded` ganhou `max_memory_bytes` (padrão 512 MiB) e `max_cpu_seconds` (padrão `timeout + 5`, nunca mais apertado que o próprio timeout de parede), aplicados via `resource.setrlimit(RLIMIT_AS, ...)`/`RLIMIT_CPU` num `preexec_fn`, antes do `exec` do `process_child.py`. Como os limites de recurso POSIX são herdados por processos filhos, o mesmo teto cobre tanto o wrapper confiável quanto o CLI real do Codex/Claude que ele executa — sem precisar modificar `process_child.py`.
- Limitação honesta e explícita: `RLIMIT_AS`/`RLIMIT_CPU` não existem no Windows; nesse SO o novo limite simplesmente não é aplicado (sem erro, sem simulação de sucesso) — documentado no próprio código (`_resource_limits`), não escondido.
- Testes novos em `tests/test_agents.py` (pulados automaticamente em `win32`): `test_memory_limit_rejects_oversized_allocation` (processo tentando alocar 2 GiB sob limite de 100 MiB é rejeitado com `CoreError`) e `test_cpu_limit_terminates_before_wall_clock_timeout` (loop ocupado infinito sob limite de 1s de CPU é encerrado em menos de 15s mesmo com timeout de parede de 30s — prova que é o limite de CPU, não o timeout de parede, que interrompe).

Validação: suíte completa **384 testes OK** (382 + 2), `compileall`, `demo.py` e `try-me.py` exit 0. Os dois testes novos passam em ~1.8s no total, confirmando que o corte veio do `RLIMIT_CPU`/`RLIMIT_AS`, não do polling de timeout existente.

## Item 14 (par do Codex) — política de acesso à rede no processo de análise

A maior parte do item 14 já existia e foi mapeada: controle de permissões (nenhuma ferramenta/shell no prompt de revisão de agente; `--disallowedTools '*'`), auditoria (cadeia hash-linkada em todo lugar), isolamento de processos (`run_bounded`/`run_monitored`, e agora com RAM/CPU do item 12), proteção de credenciais (`_environment()` allowlist, nunca logadas), armazenamento seguro de segredos (auditorias sempre redigem), separação código/evidências e escopo por investigação (`scoped_path`/`authorize`), bloqueio fora do escopo, confirmação para ações destrutivas (`cancel` exige motivo não vazio; `restore` recusa sobrescrever store existente), validação de comando antes da execução (`_executable()` recusa scripts de shell/relativos), proteção contra instrução maliciosa em evidência (prompt do agente trata todo dado suprido como dado, nunca instrução; evidência nunca é executada, só lida).

O que faltava, documentado na própria docstring de `analysis_process/__init__.py` ("no privilege or network sandbox is implied"): **política de acesso à rede** no processo filho que efetivamente interpreta bytes de evidência não confiável (`analysis_process/child.py`, usado por `analyze-file`/`assess-recovery`/`analyze-firmware`/`analyze-can`). Diferente do processo de revisão de agente (que precisa de rede para falar com Codex/Claude de propósito), esse processo nunca deveria acessar rede — se algum bug na análise confiável (ou uma dependência) fosse explorado por um arquivo malicioso, nada impedia uma conexão de saída.

- `analysis_process/network_guard.py` (novo): `block_network()` substitui `socket.socket`/`socket.create_connection`/`socket.getaddrinfo`/`socket.gethostbyname` por uma função que levanta `NetworkBlocked` (subclasse de `OSError`). Cobre tudo que passa por `socket` (urllib, http.client, requests, ftplib, smtplib, etc.) — é um bloqueio em nível Python, não de kernel; não cobre um descritor de rede recebido por outra via. Isso está dito explicitamente no docstring do módulo, não escondido.
- `analysis_process/child.py` chama `block_network()` antes de importar `cyber_core.reverse_engineering` ou qualquer código de análise — na primeira linha executável do processo filho.
- Testes novos (`tests/test_network_guard.py`, 3 testes, todos via subprocesso isolado para não poluir o `socket` do processo de teste compartilhado): bloqueio de `socket.socket`, de `create_connection`/`getaddrinfo`/`gethostbyname`, e confirmação de que o próprio ponto de entrada do child (`network_guard` antes de `reverse_engineering.analyze`) deixa a rede bloqueada.

Validação: suíte completa **387 testes OK** (384 + 3), `compileall`, `demo.py` e `try-me.py` exit 0 — confirmando que as análises legítimas (que nunca precisaram de rede) continuam funcionando normalmente.

## Item 18 (par do Codex) — testes obrigatórios: auditoria de cobertura

Em vez de escrever testes novos sem necessidade real (o que violaria a diretriz de não adicionar trabalho sem lacuna concreta), auditei a suíte de **387 testes** já existente contra cada categoria exigida pelo item 18. Mapeamento (arquivo representativo de cada categoria; não exaustivo):

- Inicialização do CORE — `tests/test_core.py`, `cmd == 'init'` na CLI.
- Comunicação com Codex — `tests/test_agent_adapters.py`, `tests/test_agent_broker.py` (`CodexAdapter`).
- Funcionamento sem Claude Code — `tests/test_agent_broker.py::test_missing_agent_waits_for_resources_and_local_analysis_still_works`: agente `claude` indisponível vira `awaiting_resources` (nunca erro fatal) e a análise local do arquivo continua funcionando no mesmo caso.
- Persistência da memória — `tests/test_backup_restore.py`, `side_analyses` em `tests/test_forensics_protocols_service.py`/`test_implementation_audit.py`/etc.
- Retomada de tarefas — `tests/test_orchestration_beta.py` (`test_expired_lease_is_resumed_by_cli_without_duplicate_result`, `test_pause_stops_between_tasks_and_resume_preserves_queue`).
- Detecção de falhas — `test_failed_task_does_not_stop_other_authorized_work`, `test_exhausted` (lease/tentativas esgotadas).
- Controle de permissões — `scoped_path`/`authorize` em praticamente todo arquivo de teste de análise; `_executable()` em `tests/test_agents.py`.
- Análise de arquivos de exemplo — `scripts/demo.py`, `scripts/try-me.py`, `tests/test_core.py`.
- Identificação de formatos — `tests/test_binary_structure.py`, `tests/test_firmware.py`, `tests/test_forensics_protocols.py` (MBR/GPT), `tests/test_forensics_protocols.py`/`protocols_pcap` (PCAP).
- Cálculo de hashes — SHA-256 verificado em quase todo teste de análise (`result['sha256']`/`hashlib.sha256(raw).hexdigest()`).
- Execução isolada de ferramentas — `tests/test_process_isolation.py`, `tests/test_process_contracts.py`.
- Geração de relatórios — `tests/test_core.py` (relatório contém o sha256 do caso), `tests/test_cli.py::test_new_process_pause_resume_report`.
- Cancelamento seguro — `tests/test_orchestration_beta.py` (`test_cancellation_is_idempotent_and_preserves_prior_evidence`, `test_cancelled_case_cannot_resume_enqueue_recover_or_finalize`).
- Recuperação após interrupções — `test_interrupt_after_commit_preserves_committed_evidence`, `test_interruption_releases_claim_and_removes_partial_copy`.
- Proteção contra comandos fora do escopo — `scoped_path` rejeitando caminho fora do escopo em `tests/test_core.py` e outros.

**Resultado da auditoria: nenhuma lacuna real encontrada** nas categorias exigidas pelo item 18 — todas já têm teste correspondente com arquivo sintético/autorizado, sem afirmação de funcionamento de ferramenta externa sem teste real (Ghidra/Binwalk seguem declarados como não testados de ponta a ponta, item 6). Não escrevi testes redundantes só para "mostrar trabalho"; os únicos testes novos desta rodada (itens 8/10/12/14) cobrem lacunas reais que identifiquei, já documentadas nas seções correspondentes acima.

**Honestidade sobre o que NÃO foi feito agora (item 6, Ghidra/Binwalk):** o PR #13 do Codex (`reverse_engineering/external.py::analyze_external`) adiciona adaptadores opcionais para Ghidra 12.1.4 e Binwalk 3.1.0, exigindo configuração explícita com caminhos absolutos (`ghidra.home`, `java_home`, `binwalk.executable`). Esse módulo foi mergeado (código presente, testado para degradar graciosamente sem fabricar resultado quando as ferramentas não existem — confirmado via `which ghidra`/`which binwalk`, ambos vazios neste sandbox), mas a integração ao `Core`/CLI **ainda não foi feita**. Motivo: essa integração exige supervisão real de processo externo (Ghidra/Binwalk de fato instalados, com os caminhos configurados) para ser validada de ponta a ponta sem fabricar sucesso — o que este sandbox não tem disponível. Fica como próxima etapa explícita, não escondida.

### Tentativa real de instalar Binwalk 3.1.0 nesta sessão e por que parou

A pedido do proprietário, tentei de fato instalar as ferramentas reais para destravar o item 6:

1. Java 21 (`openjdk-21-jdk`) já estava presente — suficiente para o Ghidra.
2. Clonei o repositório oficial `ReFirmLabs/binwalk` (leitura anônima, sem credenciais) e fiz checkout exato na tag `v3.1.0` — a mesma versão que `external.py` exige (`BINWALK_VERSION = "3.1.0"`, com verificação estrita da string de versão).
3. Tentei compilar com `cargo build --release` (Rust 1.97 disponível no ambiente).

O próprio classificador de modo automático do Claude Code **recusou a execução do `cargo build`**, com o motivo explícito `[Code from External]` — compilar/executar código-fonte de terceiros baixado da internet é bloqueado por política de segurança do ambiente de execução, independente da avaliação de risco do código em si. A instrução do bloqueio foi parar e deixar o proprietário decidir, sem tentar contornar.

Alternativas descartadas, e por quê:
- `apt` tem `binwalk` 2.3.4 (Python, pré-reescrita em Rust) disponível sem bloqueio — mas é incompatível com o pino de versão exato (`"binwalk 3.1.0"`) que o código exige, e mudar esse pino para aceitar uma versão mais antiga é uma decisão de compatibilidade/segurança que não me cabe tomar sem autorização explícita.
- Ghidra não está no `apt`; baixaria um ZIP de release do GitHub e rodaria `analyzeHeadless`, o que cairia no mesmo bloqueio de "código externo".

**Decisão do proprietário (confirmada nesta sessão): opção 1 — deixar documentado como pendência por enquanto.** Não instalar as ferramentas agora; o código do adaptador segue mergeado e testado para a ausência delas, sem fabricar sucesso. A instalação real fica para quando isso rodar numa máquina ou CI sem essa restrição de execução de código externo. Nenhuma mudança de código foi feita nesta tentativa — apenas o clone de leitura em `/home/user/refirmlabs/binwalk`, fora do repositório do projeto, inofensivo e não commitado.

## Status honesto do PR #3 e do CI real no GitHub (checagem feita a pedido do proprietário)

O proprietário perguntou se o projeto já está completo. Resposta honesta: **não.** Levantamento feito agora via `mcp__github__pull_request_read`/`actions_list`/`actions_get`:

- O PR #3 (`claude/gifted-gates-kd07xv` → `main`) ainda está **aberto, não mergeado** — nada do trabalho desta sessão chegou à `main` ainda.
- O CI real no GitHub (não a suíte local) estava verde desde muito antes desta sessão até a run #142 (commit dos itens 8/10, ~4-5 min de execução normal). As duas runs seguintes do workflow `ci.yml` — #145 e #146, disparadas pelos dois últimos commits **só de documentação** (`.md`, nenhuma linha de código) — **falharam em 4 a 9 segundos**, com `runner_id: 0` nos jobs: o job nunca chegou a pegar uma máquina para executar. Isso não é a suíte de testes falhando por bug; é sintoma de problema de infraestrutura do Actions no repositório, coincidindo no tempo com a renomeação do projeto (`CyberCore` → `JarvisEspecialista`) feita pelo proprietário no meio da sessão.
- Não consegui diagnosticar mais fundo com as ferramentas disponíveis aqui: download de log retornou HTTP 404, e a URL assinada de log foi bloqueada pelo proxy de rede deste sandbox (`results-receiver.actions.githubusercontent.com` não está na lista de hosts permitidos). Configuração de billing/Actions do repositório não é algo que eu tenha acesso para inspecionar.
- Há ainda um PR duplicado aberto (#12, rascunho do Codex, corrigindo os mesmos 5 achados que eu já corrigi nesta branch) — apenas comentado, nunca fechado.

Este commit, só de documentação, serve também para testar se a falha das runs #145/#146 foi transitória (ligada à renomeação) ou persistente.

**Atualização:** o teste confirmou que a falha era **persistente**, não transitória — a run #147 (disparada pelo commit anterior) falhou da mesma forma, em ~3s, nas duas plataformas, com `runner_id: 0` e sem gerar log algum. O proprietário então confirmou que o repositório está **público**. Hipótese mais provável: enquanto o repositório esteve privado (durante/após a renomeação), os minutos gratuitos de Actions para repositório privado podem ter sido esgotados ou a execução bloqueada por billing; repositório público não tem esse limite prático. Este commit serve para testar se voltar a ficar público resolveu.
