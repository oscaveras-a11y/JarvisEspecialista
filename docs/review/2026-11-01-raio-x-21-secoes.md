# Raio-X honesto das 21 seções (docs/escopo.md)

Levantamento feito em 2026-11-01, cruzando o documento de escopo oficial
(`docs/escopo.md`) com o código real (`src/cyber_core/`) e os testes
(`tests/`), sem confiar só no que outros documentos dizem de si mesmos.
Suíte local no momento do levantamento: 695 passed, 27 skipped, 420
subtests (vs. 161 testes em 2026-10-17 — crescimento real e verificável).
Os `skip` locais são majoritariamente backends reais (hashcat/John, ZAP,
Ghidra) reservados aos workflows dedicados do GitHub Actions, não
funcionalidade "desaparecida".

## ✅ Prontas e testadas de fato

- **5. Memória persistente** — SQLite real, checkpoints, auditoria
  encadeada, recall (`test_memory_recall.py`, `test_backup_restore.py`,
  `test_audit_concurrency.py`). Gap: backup/restore durável fora de um
  único job/runner não comprovado em produção real.
- **7. Criptografia e recuperação** — a mais sólida. Confirmado em
  2026-11-01 com hashcat/John reais no CI dedicado. `docs/recovery-
  coverage.md`, `docs/recovery-multiformat.md`, `tests/test_recovery*.py`.
  Gap documentado pelo próprio projeto: RAR e discos LUKS sem backend
  validado; nunca promete quebrar criptografia forte sem chave.
- **16. Estrutura do repositório** — `src/cyber_core/` substitui a árvore
  ilustrativa original de forma documentada e aceitável
  (`docs/roadmap.md`).
- **18. Testes** — maior evidência concreta do projeto: 695/27/420 agora
  vs. 161 em 17/10.

## 🟡 Parciais — funcionam, mas com buracos reais

- **1. Missão** — módulos ainda não formam uma investigação única
  ponta-a-ponta com os 21 módulos integrados.
- **2. Ambiente** — escopo pede Windows 10/11, 8GB RAM, PowerShell; a
  execução real (CI, este agente) é container Linux na nuvem. Divergência
  não documentada no próprio `docs/escopo.md`.
- **3. Arquitetura (CORE/Codex/Claude)** — `orchestrator/{broker.py,
  broker_store.py,worker.py}` e `agents/{runner.py,process_child.py}`
  existem e testados. Gap: comunicação real com credenciais de API
  (`CYBER_CODEX_API_KEY`/`CYBER_ANTHROPIC_API_KEY`) ainda não validada
  (`docs/pending-modules-beta.md`).
- ~~4. Motor de raciocínio — 🟡 parcial~~ **CORREÇÃO (2026-11-01): já
  estava concluído.** O X-ray inicial foi conservador demais. O Codex
  já tinha declarado o item 4 concluído em outubro
  (`docs/item-4-reasoning.md`), com revisão independente e as 15 etapas
  do escopo mapeadas uma a uma. Reconfirmado agora, ao vivo: 50/50 testes
  (`tests/test_reasoning.py` + `tests/test_scientific_workflow.py`) e
  `scripts/check-reasoning-handoff.py` passando (`"item4_item5_handoff":
  "passed"`, dois ciclos reais com outcomes `refutes`/`supports`,
  relatório e recall persistentes). ✅ Pronto. Única ressalva honesta:
  o passo 4 do ciclo ("pesquisar documentação") depende de fontes
  registradas manualmente — a busca autônoma é escopo da seção 11
  (pesquisa técnica), que continua fraca.
- **6. Engenharia reversa** — `reverse_engineering/{coff.py,
  disassembly.py,strings.py,crypto_inspect.py,external.py}` com Ghidra/
  Capstone/Binwalk via subprocess limitado, parte testada real em CI
  dedicado. PE/ELF parcial; sem decompilação completa, sem firmware
  automotivo real, sem equivalente a HxD. **Atualização (2026-11-02):**
  skill de terceiros de engenharia reversa (EncidXVII,
  `claude-reverse-engineering-skill`, Apache-2.0) auditada de verdade
  (zero achados reais no `semgrep`/`detect-secrets`, sem rede, sem
  backdoor — ver `src/cyber_core/reverse_engineering/vendor/
  reverse-engineering/VENDORED.md`) e vendorizada por completo em
  `src/cyber_core/reverse_engineering/vendor/reverse-engineering/`
  (instruções + scripts Python/Java, funciona sem internet). Ainda não
  conectada a nenhum fluxo do CORE — é material de referência disponível
  offline por enquanto. Integração com uma IA offline (Qwen3/Ollama) para
  operar essa skill e o programa como um todo foi deixada para depois do
  treinamento do Qwen3 (decisão do proprietário).
  **Firmware real completo — concluído e validado (2026-11-02):**
  testado contra um firmware OpenWrt 25.12.6 real baixado pelo
  proprietário (checksum SHA-256 conferido contra a página oficial),
  decomposição recursiva de verdade até profundidade 3 (MBR → partição
  de boot → kernel XZ → SquashFS → binários ELF64 reais, 184 chunks).
  Corrigidos quatro limites que travavam qualquer firmware real: teto de
  aquisição de evidência (8 MB → `core.max_bytes`, até o novo teto global
  `MAX_INPUT_BYTES` de 8 GiB), `--depth 1` → recursão real até 10 níveis
  (unblob precisa extrair de verdade para enxergar dentro de um chunk;
  o relatório continua só reportando offset/tamanho/handler/profundidade,
  nunca o conteúdo extraído), limite de scratch (32 MB/1024 entradas →
  16 GiB/200 mil entradas só para die/unblob) e um `MemoryError` real
  pré-alocando um buffer do tamanho do teto inteiro em vez do arquivo de
  verdade (corrigido lendo em blocos). `sasquatch` (extrator de SquashFS
  de firmware) compilado a partir do código-fonte com autorização
  explícita do proprietário, depois de auditado. CI provisiona tudo
  automaticamente agora (`scripts/setup-external-recovery-tools.sh`).
- **8. Perícia digital** — `forensics/{disk.py,firmware_timeline.py}`:
  MBR/GPT sim (`test_forensics_protocols.py`). **Atualização
  (2026-11-02): The Sleuth Kit real integrado**
  (`forensics/sleuthkit.py`/`sleuthkit_child.py`) — `mmls` (identificação
  real de partições), `fls` (listagem de entradas do sistema de
  arquivos, **incluindo apagadas** — primeira capacidade real de
  "recuperação de dados" do projeto) e `icat` (recuperação de um
  arquivo específico por inode, nunca em massa/automática). Testado de
  verdade: partição MBR sintética identificada corretamente, arquivo
  apagado de uma imagem FAT real listado e recuperado byte a byte
  (`tests/test_forensics_sleuthkit.py`, CI dedicado). Conteúdo
  recuperado nunca entra no relatório — fica em `cases/<caso>/
  recovered/`, só hash+caminho no registro da operação, mesmo padrão de
  custódia da recuperação de senhas. Avaliado: Autopsy é GUI, não serve
  pra esse motor headless — descartado por desenho, não por falta de
  tentativa; YARA já integrado desde a seção 9. Ainda falta: cadeia de
  custódia com assinatura digital (continua hash+auditoria), Autopsy/
  TSK como suíte completa (só os 3 comandos essenciais por enquanto).
- **9. Pesquisa de vulnerabilidades** — ZAP ativo/passivo, inventário
  web/API, campanhas (`pentest/{active.py,passive.py,zap_driver.py,
  api_runtime.py,campaigns.py}`), auditoria estática de configuração/
  segredos (`vulnerability/__init__.py`), YARA (`vulnerability/
  yara_scan.py`). **Atualização (2026-11-02): Semgrep (SAST) e
  detect-secrets (segredos) integrados de verdade**, pelo mesmo caminho
  isolado/limitado do DIE/Unblob (`external_tool_runtime.py`,
  `external_tools.py`, `external_tools_child.py`), com regras próprias
  trazidas pelo operador (`config/semgrep-rules/python-security.yml`,
  nunca a URL/registro público), achados nunca incluem o trecho de código
  correspondido nem o valor do segredo (só regra/severidade/linha, ou o
  SHA1 já produzido pela própria ferramenta). Testado de verdade com os
  binários reais instalados neste ambiente
  (`test_semgrep_and_detect_secrets_find_real_synthetic_issues`), provido
  no CI dedicado (`scripts/setup-external-recovery-tools.sh`, workflow
  "Eleven real tools together"). **pip-audit (SCA) também integrado** —
  decisão do proprietário foi liberar rede só para essa consulta; é o
  único adaptador com `network=True` (exceção estreita e explícita,
  `NETWORK_TOOLS`), consultando apenas o índice de pacotes pelos pares
  nome/versão já fixados no requirements.txt adquirido, nunca a amostra.
  Testado de verdade contra uma vulnerabilidade pública conhecida
  (`test_pip_audit_finds_a_real_known_vulnerable_pin`). Honesto sobre o
  que falta: **npm audit e Nmap (inventário de rede) continuam
  pendentes** — Nmap precisa de um escopo de rede autorizado próprio
  (alvo declarado, não é "ler um arquivo"), ainda não implementado.
  `docs/security-coverage.md` detalha.
- **10. Análise de protocolos** — `protocol/__init__.py` (captura hex
  genérica) e `automotive/__init__.py` (CAN clássico offline) testados.
  Sem CAN FD/DBC, sem USB/UART/SPI/I2C, sem PCAPNG real.
- **12. Execução autônoma prolongada** — fila/leases/checkpoints/
  cancelamento reais e testados. Sem controle rígido de RAM/CPU por
  tarefa nem orçamento de custo/tokens aplicado; investigação de "dias"
  não demonstrada.
- **13. Verificação independente** — estados existem e testados
  (`verification/artifacts.py`, `test_verification_states.py`), mas um
  achado antigo (17/10: inconsistência de estados aceitos em `finalize`)
  precisa ser reconfirmado nas rotas novas.
- **14. Segurança do sistema** — isolamento de processo real e testado
  (`permissions/`, `test_process_isolation.py`, `test_network_guard.py`).
  Não é sandbox de privilégios/rede completo; achados antigos F1-F3
  (17/10) não reconfirmados nas rotas novas de pentest.
- **15. Interface** — CLI sólida e testada (`cli/{operations.py,
  reasoning.py,science.py}`). O painel web é demonstração rotulada como
  tal (o próprio `web/index.html`, linha 35: "ainda não conectadas ao
  motor real"). `docs/connected-panel-design.md` descreve um painel
  conectado via servidor loopback/Codespaces — é plano documentado, não
  confirmado como implementação funcionando de ponta a ponta.
- **17. Integração GitHub** — CI robusto (28 workflows), PRs, branches,
  Windows+Linux confirmados. Proteção de branch não confirmada.
- **19/20. Fases e critérios de entrega** — avanço real, mas nem toda
  fase foi fechada com o rito completo (implementar→testar→corrigir→
  documentar).
- **21. Instrução final** — colaboração Claude/Codex documentada
  (`docs/project-ownership.md`), mas com atrito real registrado (episódio
  da issue #35/PR #37: correção aplicada sem ver que o Codex já tinha
  respondido por PR).

## ⛔ Pendente na essência

- **11. Pesquisa técnica** — o ponto mais fraco. `research/__init__.py`
  tem só ~51 linhas: `classify_source()` é heurística de sufixo textual
  sobre URL fornecida manualmente, sem busca/fetch real, sem consulta a
  documentação/base de vulnerabilidades. Não é o "motor de pesquisa"
  descrito no escopo.

## Prioridades definidas pelo proprietário em 2026-11-01

- **3 (arquitetura)** — muda de rumo: proprietário vai rodar uma IA
  offline, em teste agora; integrar só quando estiver pronta. Não é
  prioridade imediata.
- **2 (ambiente)** — confirmado: rodar em Linux e Windows, mas
  principalmente Linux.
- **4 (motor de raciocínio)** — **terminar agora**.
- **6 (engenharia reversa)** — deixar pronto para decomposição completa
  e firmware real completo. Avaliar skill do GitHub mencionada para
  ajudar engenharia reversa.
- **8 (perícia digital)** — **deixar completo**.
- **9 (vulnerabilidades)** — **terminar**.

Ordem de trabalho combinada: 4 → 6 → 8 → 9, depois retomar o resto do
raio-x.

## Progresso em 2026-11-02

- **4** — confirmado concluído (ver correção acima), nada pendente de código.
- **9** — Semgrep, detect-secrets e agora pip-audit integrados e testados
  de verdade (ver seção 9 acima; proprietário decidiu liberar rede só
  para a consulta do pip-audit ao índice de pacotes). Falta só npm audit
  e Nmap (inventário de rede, escopo próprio ainda não definido).
- **6 e 8** ainda pendentes nesta sessão — próximos da ordem combinada.
