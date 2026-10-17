# Item 5 — Memória persistente: verificação e implementação

Autor: **Claude Code** (item ímpar 5). Data: 2026-10-17. Base: branch `claude/gifted-gates-kd07xv`.

## Conformidade com a lista do escopo (item 5)

| O escopo pede armazenar/permitir | Estado | Onde |
|---|---|---|
| Investigações, objetivos | **[FATO]** | tabela `investigations` |
| Hipóteses | **[FATO]** | `hypothesis_records` (+ histórico e revisões) |
| Experimentos | **[FATO]** | `experiments`, `experiment_runs` |
| Ferramentas utilizadas | **[FATO]** | `tasks.tool`, `task_assignments` |
| Comandos executados | **[PARCIAL]** | auditoria de chamadas de agente/eventos; o sistema não executa shell arbitrário |
| Resultados | **[FATO]** | `results` |
| Erros | **[FATO]** | `tasks.error` + eventos `task_failed` na auditoria |
| Evidências, arquivos analisados | **[FATO]** | cópias verificadas + `audit` (origem, hash, cópia) |
| Hashes criptográficos | **[FATO]** | `results.sha256`, auditoria |
| Descobertas, soluções validadas | **[FATO]** | `verification_records`, estados do item 13 |
| Pontos de retomada (checkpoints) | **[FATO]** | `checkpoints`; worker grava checkpoints; retomada testada em processo novo |
| Pesquisar investigações anteriores | **[FATO]** | `history` (objetivo/hipótese/fonte) em `investigation/workflow.py` |
| Reaproveitar conhecimento técnico | **[IMPLEMENTADO AGORA]** | ver abaixo |
| Evitar segredos/dados pessoais desnecessários | **[FATO]** | auditoria nunca registra chave/senha/plaintext; material por id opaco |

## Implementado neste incremento — recall (reaproveitamento)

A única lacuna real do item 5 era **reaproveitar conhecimento entre investigações**. Implementado como camada de *recall*, **somente metadados** (nunca conteúdo de evidência nem caminho de cópia):

- `Core.recall_by_hash(sha256)` — reconhecimento de artefato por SHA-256 **entre casos**: identifica quando o mesmo arquivo já foi analisado antes (caso/tarefa/formato/tamanho/data). Útil em perícia para reconhecer um artefato conhecido.
- `Core.recall_by_type(tipo)` — lista investigações anteriores do mesmo tipo, para reaproveitar abordagens.
- CLI: `cyber recall --sha256 <hex>` e `cyber recall --type <tipo>`.

Sem mudança de esquema (lê `results` e `investigation_type` já existentes). Validação local (Linux/3.13): **147 testes OK** (142 + 5 de recall), `compileall` e `demo.py` (exit 0); CLI `recall` confirmada ponta a ponta (mesmo hash reconhecido entre dois casos).

## Veredito

Item 5 **completo** do lado do CORE: toda a lista do escopo está coberta; a busca e o reaproveitamento de conhecimento agora existem. "Comandos executados" permanece limitado por design (o sistema não executa shell arbitrário; registra chamadas de agente e operações de ferramenta via auditoria), o que é coerente com os itens 7/9/14.
