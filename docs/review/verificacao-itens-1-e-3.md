# Verificação de conformidade — itens 1 e 3 do escopo

Revisor: **Claude Code** (papel de revisão/investigação). Data: 2026-10-17.
Base: branch `claude/gifted-gates-kd07xv` já mesclada com `main` (orquestração beta do Codex).
Método: leitura estática do código atual. **Nenhum código de núcleo foi reescrito** nesta verificação — os itens 1 e 3 do escopo são território de engenharia do Codex; aqui eu confirmo o que já está pronto e aponto, com precisão, o que falta.

> Classificação: **[FATO]** verificado no código · **[PARCIAL]** existe, mas incompleto frente ao escopo · **[PENDENTE]** ainda não existe. Divisão acordada: itens **ímpares = Claude**, **pares = Codex**. Os itens 1 e 3 são meus para *verificar/documentar*; a implementação de núcleo que faltar neles é Fase 2 e pertence ao Codex.

---

## Item 1 — Missão principal → **PRONTO (como carta/princípios)**

O item 1 é a declaração de missão e o princípio fundamental, não código. Está **atendido e versionado**:

- Texto de missão e princípio "qualidade acima de velocidade" agora versionados em [`docs/escopo.md`](../escopo.md) §1 (base autoritativa, antes ausente do repositório). **[FATO]**
- Os princípios do item 1 estão **refletidos no comportamento do código**, não só no texto:
  - "Uma investigação pode durar horas ou dias" → limite de tempo deixou de ser prazo operacional (`service.py`, `MAX_TIMEOUT`); `worker.run_queue` drena a fila com checkpoints e retomada. **[FATO]**
  - "Não declarar sucesso sem comprovação" → estado `RESOLVIDO` exige evidência + revisão independente (`investigation/workflow.py`); a demo termina com `platform_complete: false`. **[FATO]**
  - "Não inventar descobertas" → relatórios distinguem observação, hipótese e conclusão não validada (`reporting/`). **[FATO]**

**Conclusão:** item 1 concluído do meu lado. Nada a implementar; serve de carta do projeto.

---

## Item 3 — Arquitetura central → **SUBSTANCIALMENTE IMPLEMENTADO, com lacunas de Fase 2**

### CORE (orquestrador) — responsabilidades do escopo × código

| Responsabilidade (item 3) | Estado | Evidência / observação |
|---|---|---|
| Receber problemas e objetivos | **[FATO]** | `Core.investigate(project, objective, scope, owner, reason)` |
| Verificar o escopo autorizado | **[FATO]** | `Core.authorize`, `permissions.scoped_path` (rejeita traversal/UNC/ADS/symlink) |
| Acompanhar a execução | **[FATO]** | `Core.run_one`, `orchestrator/worker.run_queue` (fila durável, budgets) |
| Controlar recursos computacionais | **[FATO]** | limites de bytes/tempo/tentativas; `worker` com `max_tasks`/`max_seconds` |
| Registrar evidências | **[FATO]** | cópia verificada + hash (`reverse_engineering.analyze`), auditoria encadeada |
| Verificar resultados | **[FATO]** | `verification/artifacts.verified_result`, `verify_audit` |
| Produzir relatórios finais | **[FATO]** | `reporting.write_report` |
| Formular hipóteses | **[PARCIAL]** | nota automática de entropia (`analysis_notes`) + hipóteses científicas manuais; não há geração automática de hipóteses pelo motor de raciocínio (item 4, do Codex) |
| Identificar falhas e bloqueios | **[PARCIAL]** | estados de tarefa `failed`/erros e `worker` reporta `blocked`; sem diagnóstico causal automático |
| Identificar o tipo de investigação | **[PENDENTE]** | a ferramenta é escolhida pelo operador na CLI; não há classificação automática do tipo |
| Criar planos de execução | **[PENDENTE]** | não há componente `planner` |
| Dividir problemas complexos em tarefas | **[PENDENTE]** | tarefas existem, mas sem decomposição automática de um problema em subtarefas |
| Distribuir tarefas entre agentes | **[PENDENTE]** | execução local + revisão do Codex por resumo (`orchestrator.review_summary`); não há distribuição/balanceamento entre agentes |
| Escolher ferramentas adequadas | **[PENDENTE]** | há allowlist de ferramentas, mas a seleção é do operador, não automática |

### Agentes (item 3)

| Requisito | Estado | Evidência |
|---|---|---|
| Adaptador Codex independente | **[FATO]** | `agents/runner.py` `CodexAdapter` (subprocesso limitado, sem shell) |
| Claude preparado, sem ser obrigatório | **[FATO]** | `ClaudeAdapter` é stub que falha explícito; núcleo roda só com Codex |
| Compartilhar tarefas/resultados pelo CORE | **[PARCIAL]** | `review_summary` envia só campos derivados em allowlist; não há troca estruturada de tarefas entre agentes |
| Não presumir permissões/limites iguais | **[FATO]** | adaptadores separados; `doctor` marca autenticação como "não verificada" |

### Conformidade de layout (informativo)

O escopo (item 16) descreve `core/{orchestrator,planner,scheduler,verifier,permissions,memory}` e `modules/…`. O repositório usa um layout **plano** em `src/cyber_core/` (orchestrator, memory, permissions, verification, reverse_engineering, cryptanalysis, firmware, automotive, investigation). É uma decisão de empacotamento já registrada em `docs/roadmap.md`, não um defeito — mas vale alinhar: ou atualizar o escopo (item 16, do Codex) para refletir o layout plano, ou migrar para a árvore aninhada. **[FATO / decisão pendente do Codex]**

---

## Veredito e handoff

- **Item 1:** concluído (carta + princípios refletidos no código).
- **Item 3:** o esqueleto arquitetural **existe e funciona** (CORE com autorização, execução/fila, evidência, verificação, limites, relatórios; adaptadores de agente independentes; Claude opcional). As lacunas — identificação automática de tipo, planejamento, decomposição de tarefas, distribuição entre agentes e seleção automática de ferramentas — são o **miolo do motor de raciocínio (item 4) e da orquestração (Fase 2)**, que são **itens pares / engenharia do Codex**. Não as implemento aqui para não colidir com o trabalho ativo dele; ficam registradas como handoff.

**Próximo ímpar meu:** item 5 (Memória persistente) — verificar o esquema SQLite atual contra a lista do escopo e apontar o que falta.
