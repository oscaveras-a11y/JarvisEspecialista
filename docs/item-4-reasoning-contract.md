# Item 4 — contrato do motor de investigação

Entrega autorizada: completar o fluxo científico existente, somente no GitHub.
Base: main após PR #5. Integração de memória: contrato aditivo independente,
sem editar a branch do Claude ou a versão global do SQLite.

## Contrato público v1

`cyber_core.investigation.reasoning.Reasoning(core)` usa as hipóteses,
experimentos, fontes, tarefas, evidências e revisões do `Workflow` existente.

- `register(case, experiment, actor, cost=1, risk=0, evidence=(), sources=(), alternative_to=None, rationale=...)`: vincula experimento científico a uma estratégia; nunca inventa ferramentas/comandos.
- `rank(case)`: classifica estratégias por evidência verificada, plausibilidade declarada, custo e risco. É prioridade operacional, não probabilidade científica calculada.
- `block(case, strategy, kind, detail, actor)` e `unblock(case, blocker, reason, actor)`: registram falta de dados, hardware, chaves, autorização ou recursos; resolver registro não concede permissão.
- `note(case, kind, statement, actor)`: registra somente INFERENCE ou UNKNOWN. Fatos vêm de evidência verificada; hipóteses do Workflow.
- `step(case, path, actor, second_path=None, strategy=None, time_budget=None)`: seleciona, reserva persistentemente, executa ferramenta permitida, interpreta critérios e registra próximo estado.
- `run(case, path, actor, max_steps=10, max_seconds=300, second_path=None)`: repete passos limitados, sem declarar solução.
- `snapshot(case)`: contrato JSON versionado com objetivo, fatos, tecnologias observadas, hipóteses, prioridades, fontes, inferências, desconhecidos, bloqueios e ciclos.
- Relatório técnico existente inclui esse snapshot. CLI disponível em `experiment`: strategy, rank, cycle, block, unblock, note, reasoning.

## Persistência para o item 5

Tabelas aditivas com prefixo `reasoning_`, versão de extensão 1,
criadas transacionalmente sem alterar `PRAGMA user_version`.
Referências a `investigations`, `experiments`, `tasks` e `source_records`
existentes. O item 5 pode consumir `Reasoning.snapshot(case)`; não precisa
reimplementar raciocínio, alterar migrações existentes nem executar ferramentas.
Ciclos reservados conservam task_id e revisão da hipótese; reinício retoma a
mesma tarefa/evidência, sem duplicar publicação.

## Regras de decisão

Experimento já avaliado aguarda revisão; refutação só descarta o caminho após
revisão aceita. Alternativa declarada só fica elegível após refutação revisada
do pai. Nenhuma estratégia nova é inventada para justificar sucesso.
Critérios idênticos sobre os mesmos bytes/revisão não geram novo progresso.
Evidência alterada, nova revisão, cancelamento, pausa e revogação são
rechecados antes de reservar/publicar. Concorrência serializada por SQLite.

Pontuação: `(.5 * plausibility + .5 * min(unique_evidence_hashes/3, 1)) *
(1-risk) / (1+cost)`. Valores finitos, custo de 0 a 100, risco de 0 a 1.
Risco 1 bloqueia execução automática. A fonte e a justificativa acompanham
a estratégia. Estimativas não são fatos nem probabilidades calibradas.

## Critério de conclusão

Testes reais em runners GitHub: ciclo até revisão, alternativas, bloqueios,
persistência/reinício, concorrência, reuso de resultado após interrupção,
entradas inválidas, evidência adulterada, escopo, cancelamento/revogação,
não repetição, relatório e CLI. Executar também a suíte e demonstração
combinadas com o SHA exato do candidato Claude. Registrar evidência e revisão.

Pesquisa documental usa referências consultadas e registradas pelo operador
ou agente (integração do item 11), sem busca ou envio externo implícito.
O motor não substitui ferramentas especializadas futuras nem revisão
independente do item 13. Não transforma inferência em solução validada.
