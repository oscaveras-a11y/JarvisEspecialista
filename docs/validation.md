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

**Estado inicial desta entrega: aguardando execução e inspeção dos logs do GitHub Actions.** O registro de 94 testes acima não é o resultado deste workflow. A configuração do CI, por si só, não comprova aprovação. O PR e os checks associados são a fonte do resultado por commit; falhas e bloqueios devem ser registrados sem apresentar sucesso presumido.
