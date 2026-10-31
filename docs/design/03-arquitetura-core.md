# Item 3 — Arquitetura do CORE: design das partes faltantes

Autor: **Claude Code** (item ímpar 3, papel de design/revisão). Data: 2026-10-17.
Complementa [a verificação dos itens 1 e 3](../review/verificacao-itens-1-e-3.md), que apontou o esqueleto pronto mas sem as responsabilidades "inteligentes" do CORE.

> **Fronteira de responsabilidade.** Este documento é **design** (item 3, meu). A **implementação** é Fase 2 / motor de raciocínio (item 4), do Codex, que já desenvolve a orquestração. Proponho contratos e modelo de dados **aditivos**, compatíveis com o código atual (`service.Core`, `orchestrator/worker.py`, `agents/runner.py`), para o Codex construir sem retrabalho. Não escrevo o código do núcleo aqui para não colidir com o trabalho ativo dele.

## 1. Lacunas a cobrir (do escopo, item 3)

| # | Responsabilidade do CORE | Hoje |
|---|---|---|
| G1 | Identificar o tipo de investigação | ausente (operador escolhe a ferramenta) |
| G2 | Criar planos de execução | ausente (sem `planner`) |
| G3 | Dividir problemas complexos em tarefas | ausente (tarefa é unitária) |
| G4 | Escolher ferramentas adequadas | manual (allowlist sem política) |
| G5 | Distribuir tarefas entre agentes | ausente (execução local + resumo ao Codex) |
| G6 | Formular hipóteses (automático) | parcial (nota de entropia) |

## 2. Pipeline de orquestração proposto

```
investigação criada
   │
   ▼
[classify] tipo de investigação (G1) ─────────► investigation_type
   │
   ▼
[plan] cria plano com passos ordenados (G2) ──► plans + plan_steps
   │
   ▼
[decompose] passo → 1..n tarefas (G3) ────────► tasks (já existe)
   │
   ▼
[select-tool] política sobre allowlist (G4) ──► tasks.tool
   │
   ▼
[assign] tarefa → agente/execução (G5) ───────► task_assignments
   │
   ▼
[execute] worker.run_queue (JÁ EXISTE)
   │
   ▼
[verify] verified_result / revisão (JÁ EXISTE, item 13)
   │
   ▼
[hypothesize] gancho de hipóteses (G6, liga ao item 4)
   │
   ▼
[report] write_report (JÁ EXISTE)
```

Tudo que está "JÁ EXISTE" é reaproveitado; o design cobre as caixas `classify → assign`.

## 3. Contratos propostos (compatíveis com o estilo atual)

Funções puras quando possível, `CoreError` para falha operacional sem conteúdo sensível, retorno `dict` serializável. Nenhuma recebe conteúdo de evidência; operam sobre metadados do caso.

### G1 — Classificador de tipo
```
classify_investigation(objective: str, hints: dict) -> dict
# -> {'type': 'firmware'|'crypto'|'forensics'|'protocol'|'vuln'|'generic',
#     'confidence': float, 'rationale': str, 'signals': [...]}
```
Regras determinísticas primeiro (palavras-chave do objetivo, extensão/assinatura do arquivo já lida por `reverse_engineering.identify`); o motor de raciocínio (item 4) pode refinar. Nunca decide sozinho executar nada — só rotula.

### G2 — Planner
```
plan_investigation(core, case, investigation_type) -> plan_id
# grava plans + plan_steps (passos ordenados, declarativos)
```
Um **plano** é uma sequência de passos declarados (dados, não código), cada passo com objetivo, ferramenta candidata e critério de sucesso. Versionável e auditável, como as hipóteses científicas.

### G3 — Decompositor
```
decompose_step(core, case, step_id) -> [task_id, ...]
# materializa tarefas na fila existente (service._enqueue)
```
Reaproveita a fila e os leases atuais. Um passo pode virar várias tarefas (ex.: lote de arquivos — já há precedente em `cryptanalysis/intake`).

### G4 — Seletor de ferramentas
```
select_tool(investigation_type, step, available: list) -> str
```
Política explícita e auditável sobre a **allowlist já existente** (`analyze-file`, `assess-recovery`, `analyze-firmware`, `analyze-can`, …). Sem seleção "mágica": cada escolha registra o porquê. Ferramenta fora da allowlist nunca é selecionável.

### G5 — Broker de distribuição entre agentes
```
assign_task(core, case, task_id) -> dict
# -> {'executor': 'core'|'codex'|'claude', 'reason': str}
```
O CORE decide **quem** executa, respeitando que: execução de análise é local (CORE); revisão/segunda-opinião vai a um agente via adaptador; o sistema funciona só com Codex (Claude é opcional). Usa os adaptadores independentes já existentes (`CodexAdapter`, `ClaudeAdapter`). **Não** presume permissões/limites iguais entre agentes (item 3 e 14).

### G6 — Gancho de hipóteses
O CORE expõe um ponto de extensão onde o item 4 (Codex) pluga a formulação automática de hipóteses, gravando em `hypothesis_records` (fluxo científico já existente). O design só define a interface; a lógica é do item 4.

## 4. Modelo de dados proposto (migração aditiva, esquema 5)

Mantém a disciplina aditiva atual (esquema hoje em 4). Tabelas novas, nada removido:

```sql
CREATE TABLE IF NOT EXISTS investigation_type(
 case_id TEXT PRIMARY KEY REFERENCES investigations(id),
 type TEXT NOT NULL, confidence REAL NOT NULL, rationale TEXT NOT NULL, created TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS plans(
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id),
 investigation_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'OPEN',
 author TEXT NOT NULL, created TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS plan_steps(
 id TEXT PRIMARY KEY, plan_id TEXT NOT NULL REFERENCES plans(id),
 case_id TEXT NOT NULL REFERENCES investigations(id), ordinal INTEGER NOT NULL,
 goal TEXT NOT NULL, candidate_tool TEXT NOT NULL, success_criterion TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending', created TEXT NOT NULL,
 UNIQUE(plan_id, ordinal));

CREATE TABLE IF NOT EXISTS task_assignments(
 task_id TEXT PRIMARY KEY REFERENCES tasks(id), case_id TEXT NOT NULL REFERENCES investigations(id),
 executor TEXT NOT NULL, reason TEXT NOT NULL, created TEXT NOT NULL);
```

Cada escrita passa pela auditoria encadeada existente (`memory.audit`).

## 5. Máquina de estados

Reaproveita os estados do item 13 (`EM INVESTIGACAO`, `AGUARDANDO …`, `RESOLVIDO`, `SEM SOLUCAO VIAVEL DEMONSTRADA`, `FALHA DE EXECUCAO`) e o `CANCELADO` já introduzido pela beta. O planner opera dentro de `EM INVESTIGACAO`; um plano sem passos executáveis e sem caminhos fundamentados leva a `SEM SOLUCAO VIAVEL DEMONSTRADA` (com a verificação do item 13), nunca a um "resolvido" automático.

## 6. Critérios de teste (para a implementação do Codex, item 18)

- G1: objetivos sintéticos conhecidos → tipo esperado; baixa confiança não dispara execução.
- G2/G3: plano gera passos ordenados; passo decompõe em tarefas na fila; retomável após reinício (checkpoint).
- G4: seleção só dentro da allowlist; escolha registra justificativa; ferramenta desconhecida é rejeitada.
- G5: com só Codex disponível, nada é roteado ao Claude; sem agente, execução local não quebra; limites por agente respeitados.
- G6: hipótese automática entra como `hypothesis_records` e **não** burla os portões de finalização (continua exigindo revisão independente).
- Todos: nenhuma rota envia conteúdo de evidência a agente; auditoria encadeada íntegra após cada etapa.

## 7. Não-objetivos / handoff ao Codex

- Não implemento G1–G6 em código aqui (núcleo ativo do Codex; evitar colisão e retrabalho).
- A implementação é Fase 2 + item 4; este design é o contrato para ela.
- O layout (plano em `src/cyber_core/` vs árvore `core/` do item 16) precisa de uma decisão do Codex; o design acima independe dessa escolha.

## 8. Perguntas abertas para o Codex

1. O `planner`/`scheduler` entram como novos módulos ou estendem `orchestrator/`?
2. O broker de agentes (G5) deve suportar execução paralela já na Fase 2, ou sequencial (como `worker.run_queue`) primeiro?
3. A classificação de tipo (G1) fica puramente determinística no CORE, deixando o refino probabilístico para o item 4?
