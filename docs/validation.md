# Validação — 16/10/2026

**Registro histórico anterior a esta mudança: 94 testes passaram, 0 falhas, 0 erros, 0 skips, em 376,611 segundos.** A entrega anterior teve 50 testes em 95,749 segundos. Comando: `python scripts/run-tests.py`, com o runtime Python 3.12.14. A primeira entrega teve 33 testes aprovados em 70,334 segundos. Não usar esses resultados como prova de módulos ainda pendentes.

Ambiente observado: Windows 10 build 19042, Python 3.12.14 (64 bits), SQLite 3.53.1, Git 2.55.0.windows.5, cryptography disponível. Python não estava no PATH inicial do shell; foi usado o runtime Python do aplicativo. O executável Codex foi descoberto no ambiente do processo Python e seu `exec --help` foi consultado. Claude e gh não foram encontrados.

Execuções iniciais: 10 testes do núcleo passaram; depois 21 testes de núcleo/CLI/AES passaram e 5 testes de subprocessos passaram. Revisão independente encontrou três falhas e cada uma foi reproduzida antes da correção: retorno do arquivo errado na fila; stdin bloqueado ignorando timeout; encadeamento concorrente de auditoria. Após correção, a suíte consolidada com 29 testes passou em 122,450 segundos.

Uma verificação adicional de banco corrompido mostrou traceback em vez de erro operacional; o tratamento de sqlite3.Error foi incluído e passou na execução final. Também passaram expiração de autorização, arquivo vazio e exigência de permissão separada para envio de resumo à nuvem.

A demonstração sintética passou nas 12 verificações solicitadas: investigação/autorização, assinatura, SHA-256, entropia, hipótese/experimento, persistência, relatório, pausa/retomada em processos novos, AES conhecido autenticado, rejeições de autorização/chave/escopo e integridade auditada. Binário: 32772 bytes, SHA-256 `1f1b0fd44bfd8ac41cefa1de8dd28989adcb25acf1f972fee97feebc5504ba58`, entropia 7,999999324684831. Plaintext recuperado: 40 bytes, SHA-256 `d886ecb5a92f302d5530a7dfd7da2d73a41f197d903aab8f952cb4ea71c8ea72`.

Integração real Codex: **não validada**. No sandbox, exit 1; `codex login status` informou `Could not find home directory`. Uma segunda chamada sob o usuário correto excedeu 30 segundos e foi encerrada pelo controle de timeout. Não houve resposta final do CLI nem autenticação comprovada. A revisão independente do código foi feita por agente de revisão do ambiente de desenvolvimento; isso não valida o adaptador Codex nem o Claude.

Instalação verificada: venv local criado com `--system-site-packages` para reutilizar cryptography 50.0.2 já instalado, sem download. `pip install --no-deps --no-build-isolation -e .` construiu e instalou cyber-core 0.1.0. A instalação foi repetida sem `--no-deps`: a resolução de dependências passou com cryptography 50.0.2, e `pip check` informou ausência de requisitos quebrados. O entrypoint `.venv/Scripts/cyber.exe doctor` executou com exit 0. `python -m compileall -q src scripts tests` passou.

Scripts PowerShell foram escritos, mas sua execução/validação não foi comprovada: o processo powershell.exe não retornou no ambiente de ferramentas e foi interrompido. Os testes e a instalação foram realizados pelos comandos Python diretos documentados no README. Não declarar o instalador PowerShell testado.

O Git HTTPS falhou no sandbox inicial; fetch autorizado fora dele funcionou. Publicação deve preservar o commit remoto anterior e13049b0ba3368d3b31c772f97ef8d856950f37f como ancestral.

## Atualização: investigação sem chave fornecida

O usuário esclareceu que o cliente fornece autorização e arquivos variados, sem chave. Foi implementado `assess-recovery` para arquivo ou lote autorizado, sem argumento de segredo. A cobertura está descrita em [recovery-coverage.md](recovery-coverage.md). A triagem não afirma ter recuperado dados.

Passaram testes de reconhecimento em 14 amostras de formatos, flags ZIP e campo AES, marcador PDF não conclusivo, amostragem limitada, entropia sem inferência automática de criptografia, lote sem chave, relatório persistido, escopo, revogação, limite de arquivos e recursão explícita.

Foram reproduzidas e corrigidas duas falhas de retomada: crescimento de arquivo depois da entrada na fila podia exceder o orçamento agregado; pausa podia reportar tarefas ainda pendentes como falhas. O esquema 2 conserva tetos por tarefa e a migração do esquema 1 foi testada preservando hashes, resultados e auditoria. A revisão independente confirmou o problema de contabilização após pausa; o problema de bytes também foi identificado e corrigido com teste de regressão.

A suíte completa de 50 testes passou após essas mudanças. Esse é o checkpoint anterior à continuação abaixo. Os limites de formato permanecem explícitos: prefixo de 64 KiB, assinatura sem validação integral, ZIP limitado ao primeiro cabeçalho, nenhuma extração, busca de segredos ou tentativa criptográfica durante a triagem. Naquela entrega não foi repetida chamada aos agentes de nuvem. A validação real posterior do Codex está descrita abaixo.

## Continuação: ciclo científico, firmware e CAN

Checkpoint validado: **94 testes aprovados, 0 falhas, 0 erros, 0 skips, em 376,611 segundos**, executando `python scripts/run-tests.py`. Inclui 21 testes científicos, 11 de firmware, 9 de CAN e 3 integrações CLI, além da suíte anterior. `compileall` também passou. O runner agora rejeita execução vazia e permite filtro opcional por nome de teste.

Implementado: esquema SQLite 3 aditivo; hipóteses e revisões; critérios de experimento como dados; avaliação de resultados reais vinculados ao digest auditado; verificação das cópias primária e secundária; revisão independente declarada; histórico, fontes e estados com snapshots. Testes negativos reproduziram e corrigiram observações ausentes classificadas como refutação, fechamento durante entrada de nova tarefa, cópia secundária adulterada, repetição por nomes diferentes, execuções contrárias sem revisão e estado sem solução contradizendo resultados favoráveis.

Firmware e CAN são analisados sobre cópias verificadas, sem execução nem hardware. Comparações preservam os dois originais. HEX/S-record têm teto rígido de 1 MiB decodificado; ELF/PE verificam apenas cabeçalhos e limites documentados. CAN aceita logs compactos clássicos e rejeita explicitamente tipos ainda não implementados. Não houve ensaio de bancada ou veículo.

Integração Codex posterior: `codex login status` executado sob o usuário correto retornou `Logged in using ChatGPT`. `scripts/agent-smoke.py`, com timeout de 120 segundos, passou em chamada real usando apenas resumo sintético. A resposta estruturada reconheceu as limitações da amostra. Uso informado pelo CLI: 19148 tokens de entrada (12544 em cache) e 104 de saída; isso é contabilização reportada, não teto financeiro garantido. Claude continua ausente. Nenhum dado de cliente foi enviado.

A revisão independente de código encontrou três problemas de fechamento/repetição, todos reproduzidos por testes antes da correção. Os nomes dos revisores do produto ainda são declarações locais, não identidades autenticadas. A plataforma completa continua pendente: isolamento/worktrees, perícia, ferramentas externas, pesquisa automática, worker e validação profissional seguem em desenvolvimento.

## Validação somente no GitHub — nova entrega

A orientação atual do proprietário substitui o fluxo de desenvolvimento local: alterações via GitHub, sem clonar, instalar dependências ou executar o projeto no computador. Os relatos locais acima são histórico preexistente e não foram repetidos nesta entrega.

Branch: `codex/github-validation`. Automação: `.github/workflows/ci.yml`, runner GitHub-hosted `windows-2022`, Python 3.12. Etapas: instalação do pacote, `pip check`, `compileall`, CLI instalada, suíte completa pelo runner existente e demonstração sintética. Sem chamadas reais aos agentes, credenciais ou dados de clientes.

**Execução comprovada no GitHub:** [run 38984887659](https://github.com/oscaveras-a11y/CyberCore/actions/runs/38984887659), [job Windows](https://github.com/oscaveras-a11y/CyberCore/actions/runs/38984887659/job/117253939975). Head do PR: `7de7829e3cad5c975fd8d5c555be7072213cee94`; merge temporário testado pelo evento pull_request: `68f736d35f3755575e810ae39905fec9dd374a67`, sobre base `35adb738fae9f1dcfeda75c7f643b1637467fa05`.

Em 16/10/2026, às 21:08 (America/Sao_Paulo), o runner Windows Server 2022 com CPython 3.12.10 concluiu **94 testes em 53,583 segundos: OK, sem falhas, erros ou skips reportados**. A demonstração terminou com 13 etapas sintéticas e quatro rejeições esperadas; `platform_complete` permaneceu false. Instalação do pacote, `pip check`, compilação e CLI instalada também passaram. Dependências observadas: cryptography 50.0.2, cffi 2.1.1 e pycparser 3.11.

A revisão independente das alterações do PR nesse head não encontrou achados acionáveis. A revisão foi estática, sem execução local, e não substitui os testes do GitHub. Este registro é vinculado ao commit citado; consulte os checks do PR para qualquer commit posterior. Não houve instalação nem execução do projeto no computador do proprietário. Integrações reais de agentes, ferramentas externas e hardware permanecem fora desta validação.

## Orquestração beta — 16/10/2026

Escopo aprovado como beta: worker sequencial sobre fila persistente, limites de tarefas/tempo, pausa, cancelamento permanente por investigação, checkpoints e retomada após interrupção. Desenvolvimento e execução de testes exclusivamente no GitHub, sem instalações no computador do proprietário.

**Resultado comprovado:** 114 testes em 49,166 segundos, OK (sem falhas, erros ou skips), e demonstração sintética aprovada. [execução 38986772289](https://github.com/oscaveras-a11y/CyberCore/actions/runs/38986772289), [job Windows](https://github.com/oscaveras-a11y/CyberCore/actions/runs/38986772289/job/117259961629), head `ef28b7a3bee68fff0bd02a58ee03d6f5fef49e4a`. Instalação no runner temporário, `pip check`, compilação e CLI instalada também passaram. O teste de merge temporário combina a branch da beta com a base do PR. Consulte os checks para o estado do commit mais recente, inclusive atualizações posteriores de documentação.

Os 20 testes novos cobrem drenagem da fila, orçamento de tarefas/tempo, opções inválidas, pausa/retomada em processo novo, falhas sem bloquear outras tarefas, leases válidos e vencidos, dois workers reais concorrentes, cancelamento idempotente, preservação de resultados/evidências confirmados, descarte de análises tardias, impedimento de retomada/reabertura, interrupção antes/depois do commit, respostas de agentes tardias, ordenação transacional de recuperação AES e cancelamento de lotes compartilhados. Não houve chamada real a agente: o ensaio de resposta tardia usa um adaptador controlado e comprova somente o comportamento do CORE.

### Falhas reproduzidas antes das correções

- A primeira execução, somente com testes novos, falhou pela ausência de `worker`, `cancel` e seu contrato; [run 38985763724](https://github.com/oscaveras-a11y/CyberCore/actions/runs/38985763724).
- [Run 38986128774](https://github.com/oscaveras-a11y/CyberCore/actions/runs/38986128774) reproduziu exclusão indevida de evidência após commit/interrupção, aceitação de resposta tardia de agente e lote cancelado informado como parcial. As correções preservam cópias de claims já confirmados, serializam autorização/publicação e distinguem itens cancelados.
- [Run 38986400394](https://github.com/oscaveras-a11y/CyberCore/actions/runs/38986400394) reproduziu recuperação aceita após cancelamento e itens já leased omitidos da lista de cancelados. A aceitação AES agora adquire writer lock antes da autorização final; a contagem reconcilia todo o lote com os estados duráveis.
- Uma execução posterior encontrou erro na sincronização do teste AES: inicialização do segundo banco dentro do bloqueio de escrita. O teste foi corrigido para preparar a conexão antes da operação, preservando sua verificação de ordem de commits.

A revisão independente estática foi realizada via GitHub e não encontrou novos achados após as correções e o ajuste do teste. A aprovação dos testes é limitada ao escopo coberto: não valida serviço de boot, persistência de disco entre jobs do GitHub, interrupção imediata de parsers, limites rígidos de recursos, hardware ou integrações reais Codex/Claude. A fase completa continua com essas pendências; veja [contrato da beta](orchestration-beta.md).

## Acompanhamento — ajustes de revisão do Claude (2026-10-17)

Sobre a base da orquestração beta acima, os ajustes descritos em [docs/review/2026-10-17-revisao-claude.md](review/2026-10-17-revisao-claude.md) — configuração carregada de verdade, limite de tempo relaxado para tarefas longas (teto apenas de sanidade), unificação de "hipótese" com a heurística de entropia virando nota de análise (`analysis_notes`, esquema 4) e CI em matriz Windows+Linux — acrescentaram 4 testes de configuração.

Execução **local de desenvolvimento** nesta sessão, no resultado já mesclado com a `main`: Linux, CPython 3.13.16, cryptography 50.0.2 — `python scripts/run-tests.py` concluiu **118 testes: OK**, 0 falhas/erros/skips; `compileall` passou; `python scripts/demo.py` terminou com exit 0 e `platform_complete` false. Este é um resultado de desenvolvimento em Linux, **não** o alvo oficial Windows/3.12; a contagem e os tempos oficiais são os que o workflow do GitHub reportar nos checks deste PR. O esquema SQLite passou para a versão 4 (migração aditiva; o teste de upgrade a partir da v1 preserva evidências e auditoria).

### Implementação do item 3 — planejamento do CORE (Codex pausado)

Com o Codex pausado pelo proprietário (sem trabalho concorrente, sem risco de colisão), o item ímpar 3 começou a ser **implementado** (não só projetado): classificação determinística do tipo de investigação, construção de plano de execução com passos ordenados e seleção de ferramenta restrita à allowlist. Novo módulo `cyber_core/planning/`; métodos `Core.classify/plan/plans`; comandos de CLI `classify`/`plan`/`plans`; esquema SQLite **5** (aditivo: `investigation_type`, `plans`, `plan_steps`). Design em `docs/design/03-arquitetura-core.md`.

Execução local (Linux/3.13): `python scripts/run-tests.py` → **129 testes: OK** (118 + 11 de planejamento), 0 falhas/erros/skips; `compileall` e `demo.py` (exit 0) passaram; teste ponta a ponta da CLI `classify`/`plan` confirmado. Contagem/tempo oficiais seguem os checks do GitHub.

Incrementos seguintes do item 3 — **decomposição e distribuição**: `Core.decompose` materializa tarefas do plano sobre um arquivo autorizado, vincula-as ao plano (`plan_tasks`) e registra a decisão do broker de execução (`task_assignments`); `Core.assign`/`assignments` expõem o roteamento (execução local no CORE; agentes só em revisão de metadados). Esquema SQLite **6** (aditivo). CLI: `decompose`, `assignments`. Execução local (Linux/3.13): **134 testes: OK** (129 + 5 de decomposição), `compileall` e `demo.py` (exit 0) passaram; CLI `decompose`/`assignments` confirmada ponta a ponta.

Incremento final do item 3 — **autorização e autoteste de recuperação**: `authorization_basis` (esquema SQLite **7**, aditivo) com dois tipos, `owner_consent` e `legal_authority` (mandado/processo/perito/escopo), exigidos antes de operações sensíveis; `Core.set_authorization_basis`/`authorization_basis`. Modo de autoteste honesto em arquivo próprio: envelope de laboratório `CCPW1` (scrypt+AES-256-GCM) com `cryptanalysis/selftest.py`; `Core.self_test_recovery` tenta senhas candidatas sob limites de tentativas/tempo, exige base `owner_consent`, registra só o resultado (nunca a senha nem o plaintext) e marca `recovery_demonstrated` honestamente (senha fraca presente → recuperada; forte/ausente → false). CLI: `authorize-basis`, `self-test-recovery`. Execução local (Linux/3.13): **142 testes: OK** (134 + 8), `compileall` e `demo.py` (exit 0) passaram; CLI de autorização e autoteste confirmada ponta a ponta (recusa sem base; recuperação de senha fraca com base). Um bug de colisão de opção na CLI (`--max-attempts`) foi encontrado e corrigido (flag do autoteste renomeado para `--max-candidates`).
