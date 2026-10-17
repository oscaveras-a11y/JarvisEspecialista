# Item 4 — motor de raciocínio e investigação

O motor conecta o fluxo científico existente a decisões persistentes de
execução. Hipóteses e critérios vêm do operador/agente e são explicitamente
identificados; o CORE calcula a prioridade, escolhe experimentos elegíveis,
executa somente ferramentas autorizadas e compara observações aos critérios.

## Cobertura das 15 etapas do documento original

| Etapa | Implementação operacional |
|---|---|
| 1. Entender o problema | Objetivo e escopo de `Core.investigate`, expostos no snapshot |
| 2. Coletar informações | Aquisição verificada por `Core.run_one`; fatos vinculados a tarefa/hash |
| 3. Identificar tecnologias | Assinaturas/formatos observados e resultados dos parsers; sem inferir arquitetura completa de assinatura |
| 4. Pesquisar documentação | `Workflow.add_source`/`cyber research`, referências consultadas pelo operador/agente com URL, versão e proveniência; estratégias ligadas a source_ids |
| 5. Formular hipóteses | `Workflow.add_hypothesis` e revisões justificadas; não confundir heurística com fato |
| 6. Classificar | `Reasoning.rank`: evidência verificada, plausibilidade declarada, custo e risco finitos |
| 7. Selecionar experimentos | Maior prioridade entre estratégias elegíveis, com motivos explícitos para exclusões |
| 8. Executar autorizadamente | Reserva transacional e tarefa allowlisted; execução em processo monitorado e rechecagem de autorização |
| 9. Interpretar | Critérios escalares permitidos, sem execução de texto; supports/refutes/inconclusive |
| 10. Comparar com hipóteses | Avaliação vinculada à revisão reservada, verificada na publicação transacional |
| 11. Descartar caminhos inválidos | Estado refuted exige avaliação e revisão aceita; evidência e critérios são revalidados |
| 12. Desenvolver alternativas | Estratégias alternativas declaradas são liberadas somente após refutação revisada do pai |
| 13. Validar descobertas | Portões existentes do Workflow: evidência, revisão independente declarada e critérios reproduzíveis |
| 14. Registrar conclusões | Runs, verifications, notas rotuladas e checkpoints; sem promoção automática para RESOLVIDO |
| 15. Gerar relatório técnico | Relatório inclui snapshot de fatos, hipóteses, prioridades, inferências, desconhecidos, bloqueios e ciclos |

Na mesma estratégia, repetição dos mesmos bytes/teste/revisão não cria nova tarefa nem progresso. Outra hipótese/experimento exige registro e justificativa próprios.
Uma revisão justificada da hipótese pode iniciar um novo ciclo. Campos de
evidência são verificados novamente; tempo e quantidade de passos do ciclo
são limitados. Interrupções retomam a mesma reserva e recuperam avaliações
já confirmadas, sem duplicá-las. Dados, hardware, chaves, autorização e recursos
faltantes têm bloqueios próprios; resolver um bloqueio não concede permissão.

A formulação de hipóteses e a consulta documental são entradas do
operador/agente. A busca online automática pertence ao item 11; o motor não
faz consulta de rede nem envia evidência implicitamente. Alternativas também
são declaradas e testáveis, nunca descobertas inventadas para anunciar sucesso.

## Uso

O contrato Python e as tabelas estão em
[item-4-reasoning-contract.md](item-4-reasoning-contract.md).
O item 5 pode consumir `Reasoning(core).snapshot(case)` sem mudar seu esquema
global: a extensão usa `reasoning_meta.version=1` e conserva `user_version`.

Após criar hipótese e experimento pelos comandos científicos existentes:

```text
cyber experiment strategy CASE EXPERIMENT --actor analista --rationale "Critério falsificável" --cost 1 --risk 0
cyber experiment rank CASE
cyber experiment cycle CASE ARQUIVO --operator operador --max-steps 10 --max-seconds 300
cyber experiment reasoning CASE
cyber report CASE
```

As opções `--evidence TASK`, `--source SOURCE` e
`--alternative-to STRATEGY` vinculam contexto ao registro de estratégia.
`experiment block`, `unblock` e `note` registram dependências e conhecimento
rotulado. Nenhum desses comandos é executado no computador do proprietário
nesta entrega; os exemplos documentam a API testada em runners GitHub.

## Evidência de desenvolvimento

- Testes anteriores ao código: run 39029580318 falhou por ausência de
  `cyber_core.investigation.reasoning`.
- Revisão independente detectou retomada ignorando bloqueio novo e corrida
  entre revisão e avaliação. Regressões reproduziram ambas no run39029883609,
  além de snapshot sem prioridades. Correções mantêm aquisição fora da
  transação e usam revisão esperada na publicação.
- Testes incluem concorrência com duas conexões, interrupções antes da
  aquisição e após commit, preservação da versão global, escopo,
  cancelamento, pausa, adulteração, CLI e relatórios.
- `scripts/check-reasoning-handoff.py` executa a sequência sintética completa:
  refutar hipótese de tamanho incorreto, revisar, liberar alternativa,
  validar controle de três bytes, gerar relatório, fechar/reabrir e
  reencontrar os hashes pela memória do Claude.

A autorização de execução continua sendo a registrada no `investigate`: escopo, responsável, motivo, validade e revogação, além da permissão específica de recuperação quando aplicável. `authorization_basis` do candidato Claude mantém seu contrato próprio; resolver um bloqueio do motor não cria nem altera essa base.

## Resultado da entrega

**Item 4 concluído no contrato operacional descrito acima.** Código revisado
independentemente no head `9886c42f4a56a80672d5b26752647ae497fe0292`, sem
novos achados acionáveis após as correções. Revisão estática pelo GitHub;
execução comprovada no GitHub Actions.

| Conjunto | Plataforma | Descobertos | Executados | Skips | Resultado |
|---|---|---:|---:|---:|---|
| Base própria | Windows | 161 | 161 | 0 | OK em 112.943s |
| Combinação com Claude | Windows | 194 | 194 | 0 | OK em 99.383s |
| Combinação com Claude | Linux | 194 | 192 | 2 | OK em 18.802s |
| Sondas adicionais de prazo/tentativas | Windows | 3 | 3 | 0 | OK em 1.590s |
| Sondas adicionais de prazo/tentativas | Linux | 3 | 3 | 0 | OK em 0.145s |

[Run da base](https://github.com/oscaveras-a11y/CyberCore/actions/runs/39030452687)
e [run combinado](https://github.com/oscaveras-a11y/CyberCore/actions/runs/39030452614).
Todos os passos de instalação no runner, dependências, compilação, CLI,
suíte e demonstração foram aprovados. Os dois skips Linux são testes
específicos de Job Objects executados com sucesso no Windows.

A demonstração dos itens 4 e 5 passou nos dois sistemas: duas estratégias,
refutação revisada seguida de alternativa suportada/revisada, conclusão
validada do controle sintético, relatório, reabertura e recall. Conservou
`PRAGMA user_version=7` e o contrato de raciocínio 1.

Candidato Claude testado: `00adab4ccc187f517ee8272a29e285087b54e347`.
Combinação feita somente no runner; a branch/PR do Claude não foi editada
nem integrada por esta entrega. O item 5 pode usar o módulo da main após
integrar a atualização na própria branch.

Além das regressões de concorrência já descritas, foram reproduzidas e
corrigidas conclusões armazenadas incompatíveis com critérios
(run39030013043), seleção parada em entrada já fracassada mesmo com outro
experimento disponível (run39030156272), e reserva bloqueada impedindo
trabalho independente (run39030359143). Há 29 testes novos do motor.

Essa validação cobre o contrato operacional do item 4; não conclui os módulos
especializados dos itens 6, 8, 10 ou a plataforma inteira. As estimativas
de prioridade não são probabilidades científicas calibradas; identidades de
revisores permanecem declarações locais conforme o contrato existente.

