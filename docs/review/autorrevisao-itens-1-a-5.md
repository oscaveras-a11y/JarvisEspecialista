# Autorrevisão — itens 1 a 5 (trabalho do Claude)

Autor: **Claude Code**. Data: 2026-10-17. Escopo: revisão crítica do que eu mesmo implementei/documentei nos itens ímpares 1, 3 e 5 (e nos ajustes de revisão), antes de o item 4 do Codex entrar. Objetivo: achar defeitos e inconsistências reais, não validar meu próprio trabalho.

Classificação: **[ALTO]** corrige antes de usar · **[MÉDIO]** deveria ser resolvido · **[BAIXO]** melhoria · **[OK]** verificado sem defeito.

## Achados

### F1 — Autoteste não tem como criar o alvo pela CLI, e só aceita o formato de laboratório **[MÉDIO]**
`self-test-recovery` consome um envelope `CCPW1`, mas **não há comando CLI para criá-lo** — o operador teria de gerar o arquivo com um trecho Python (`cryptanalysis.selftest.seal`). Isso quebra o fluxo que o proprietário pediu ("fazer um arquivo e tentar quebrar"). Além disso, o autoteste **só** entende `CCPW1`, não um ZIP/PDF real com senha. 
*Proposta:* adicionar um comando (ex.: `make-lab-envelope`) que sela um arquivo próprio com uma senha dada, e deixar claro na ajuda que o autoteste é sobre o envelope de laboratório, não arquivos reais arbitrários (estes exigem ferramentas externas, itens 7/8).

### F2 — Inconsistência entre o design 03b e a implementação sobre autorização **[MÉDIO]**
`docs/design/03b-agentes-autorizacao-etica.md` §3 diz: "O CORE **exige** uma base de autorização registrada antes de qualquer análise/recuperação." Na prática, **só** `self_test_recovery` exige `authorization_basis` (`owner_consent`). `analyze-file`, `decompose`, `recover-aes` e `assess-recovery` continuam exigindo apenas a autorização do `investigate()` (dono/escopo/prazo/revogação), **não** a `authorization_basis`. 
*Proposta:* reconciliar — ou (a) suavizar o design para dizer que `authorization_basis` é exigida apenas em recuperação/autoteste por ora, ou (b) passar a exigir `authorization_basis` também nas análises sensíveis. Como isso toca o núcleo (área do item 4 do Codex), **registrar como proposta** e decidir com ele, sem alterar agora.

### F3 — `config.py` aceita valores que o `Core` rejeita depois **[BAIXO]**
`load_defaults` aceita qualquer inteiro ≥ 0, mas `Core` exige `1 ≤ max_bytes` e `0 < timeout`. Um `config/default.toml` com `timeout_seconds = 0` ou `max_bytes = 0` passa na config e depois falha no `Core` com a mensagem genérica "Invalid resource limits". 
*Proposta:* validar faixas mínimas na própria config, com mensagem clara apontando a chave.

### F4 — `recall_by_hash` varre apenas os 5000 resultados mais recentes **[BAIXO]**
Para um store grande, uma correspondência de hash antiga pode não aparecer, silenciosamente. É aceitável para um laboratório, mas não está documentado no retorno. 
*Proposta:* ou documentar o teto, ou criar um índice `sha256 → (case, task)` alimentado na aquisição (mudança de esquema; coordenar com o item 4).

### F5 — `recall` é global ao store do operador **[BAIXO / informativo]**
`recall_by_hash`/`recall_by_type` cruzam todos os casos e expõem objetivos/hashes entre investigações. Isso é **intencional** (item 5: reaproveitar conhecimento) e assume um store local de operador único — coerente com o escopo (dados de clientes ficam fora do Git e por `CYBER_HOME` separado). Registrado para ficar explícito; não é defeito.

## Verificados sem defeito (amostras) **[OK]**
- **Auditoria encadeada:** todos os eventos novos (`investigation_classified`, `plan_created`, `plan_decomposed`, `task_assigned`, `authorization_basis_set`, `self_test_recovery`) passam por `memory.audit`; `verify_audit` continua íntegro nos testes.
- **Segredos:** o autoteste nunca registra a senha nem o plaintext (só resultado + SHA-256/tamanho); o `recall` nunca expõe caminho de cópia; teste cobre a ausência da senha na auditoria.
- **Allowlist de ferramentas:** `select_tool`/`decompose` nunca escolhem ferramenta fora da allowlist (testado).
- **Estados:** `classify`/`plan`/`decompose`/`self_test_recovery` recusam caso `CANCELADO`/revogado/expirado via `authorize` (testado).
- **Fix do Linux (reap POSIX):** teste antes falho passa 10/10; suíte 162 OK; não desabilita teste.
- **Transações:** as chamadas aninhadas (`decompose`→`plan`→`classify`) rodam sequencialmente, cada uma commitando sua própria transação antes da seguinte; sem `with self.db` aninhado.

## Correções aplicadas (2026-10-17)

- **F1 — resolvido.** Novo comando `cyber make-lab-envelope` (método `Core.make_lab_envelope`) cria um envelope `CCPW1` no escopo próprio, exigindo `owner_consent` e sem registrar a senha; a ajuda do `self-test-recovery` aponta para ele. Fluxo ponta a ponta pela CLI confirmado (criar → autoteste recupera senha fraca). Fica explícito que o autoteste é sobre o envelope de laboratório, não arquivos reais arbitrários.
- **F2 — reconciliado (documental).** `03b` §3 agora descreve o estado real: `authorization_basis` é exigida para recuperação/autoteste; exigi-la nas demais análises é um passo de núcleo (item 14) a coordenar com o item 4 do Codex. Sem alterar o núcleo dele.
- **F3 — resolvido.** `config.load_defaults` valida faixas mínimas por chave (erro claro nomeando a chave), batendo com os limites do `Core`.
- **F4 — resolvido.** `recall_by_hash` deixou de ter teto de varredura de 5000; varre todo o store, limitando apenas o número de correspondências.
- **F5** — permanece como nota informativa (comportamento intencional).

Suíte após as correções: **165 testes OK** (2 skipped só-Windows); `compileall` e `demo.py` (exit 0). CLI `make-lab-envelope`/`self-test-recovery` confirmada ponta a ponta.

## Resumo
Nenhum achado **[ALTO]**. Os dois **[MÉDIO]** (F1 fluxo do autoteste pela CLI; F2 inconsistência design×implementação de autorização) valem correção; F1 é seguro de corrigir agora (só nos meus arquivos), F2 toca o núcleo e deve ser decidido junto com o item 4 do Codex. Os **[BAIXO]** são melhorias.
