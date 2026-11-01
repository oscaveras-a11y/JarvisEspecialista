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
  automotivo real, sem equivalente a HxD.
- **8. Perícia digital** — `forensics/{disk.py,firmware_timeline.py}`:
  MBR/GPT sim (`test_forensics_protocols.py`). Sem Autopsy/TSK/YARA
  forense integrado como suíte; sem recuperação de apagados; cadeia de
  custódia é hash+auditoria, não assinatura digital.
- **9. Pesquisa de vulnerabilidades** — maior salto da sessão (ZAP ativo/
  passivo, inventário web/API, campanhas — mergeado em 2026-11-01,
  commit `0c59911`). `pentest/{active.py,passive.py,zap_driver.py,
  api_runtime.py,campaigns.py}`, `vulnerability/yara_scan.py`. Validação
  com ZAP real só no workflow dedicado. `docs/security-coverage.md` é
  honesto: faltam Semgrep (SAST), SCA (pip-audit/npm audit), Gitleaks
  (segredos), Nmap.
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
