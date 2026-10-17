# Orquestração beta

**Beta implementada e validada em amostras sintéticas:** 114 testes aprovados, sem falhas ou skips, e demonstração aprovada na [execução 38986772289](https://github.com/oscaveras-a11y/CyberCore/actions/runs/38986772289), head `ef28b7a3bee68fff0bd02a58ee03d6f5fef49e4a`. São 20 testes novos de orquestração além dos 94 anteriores. Consulte os checks do PR para alterações posteriores. Esta beta não comprova a conclusão de toda a fase de orquestração do projeto original.

## Contrato

`cyber worker CASE` processa a fila persistente de uma investigação, sequencialmente, reutilizando os claims transacionais, tokens e leases do núcleo. Vários processos podem compartilhar a fila sem publicar o mesmo resultado duas vezes. O comando `run` continua processando uma única tarefa.

Limites por invocação: `--max-tasks 100`, `--max-seconds 300`, `--poll-interval 0.2` e `--idle-timeout 0`, por padrão. O teto de tarefas aceita 1–100000, o de tempo 0,001–86400 segundos, polling 0,01–60 segundos e espera ociosa 0–3600 segundos; valores não finitos são rejeitados. Os limites por arquivo e por tarefa do núcleo continuam aplicados. Cada tarefa recebe no máximo o menor entre o tempo do núcleo e o tempo restante do worker.

Por padrão, o worker drena o trabalho disponível e termina. Espera ociosa positiva permite aguardar novas tarefas ou leases vencidos dentro do orçamento total. Um lease ainda válido é informado como `awaiting_lease`, nunca como fila vazia. Um novo processo pode executar `worker` novamente para continuar. Nenhum serviço, tarefa de boot ou agendamento é instalado.

Os orçamentos de tempo são cooperativos: bloqueios de SQLite, filesystem e uma chamada de parser em andamento não são interrompidos à força. Não há limite rígido de CPU/RAM ou garantia de serviço 24 horas no GitHub Actions. O runner de CI tem também seu timeout próprio de 20 minutos.

## Pausa, cancelamento e interrupção

- `pause CASE` impede a próxima aquisição; a operação já em andamento pode concluir. `resume CASE` continua o mesmo caso se ainda autorizado.
- `cancel CASE --reason "Motivo do operador"` coloca a investigação em `CANCELADO` permanentemente. Tarefas pendentes/em execução ficam `cancelled`, tokens e leases são invalidados, e novos trabalhos/retomada são recusados. Para continuar a investigação, crie um novo caso com autorização adequada.
- Resultados e evidências já confirmados são preservados. Status, histórico e exportação de relatório continuam disponíveis. Repetir cancelamento não duplica seu evento.
- Análise em andamento pode demorar até chegar ao próximo ponto de verificação. Depois do cancelamento, seu resultado não pode ser publicado; cópias provisórias são removidas quando o processo recupera o controle. Isso não equivale a matar imediatamente um processo ou desfazer uma transmissão já realizada.
- Interrupção cooperativa (`KeyboardInterrupt`) limpa cópias provisórias e devolve a tarefa para a fila se ainda houver tentativas. Após encerramento abrupto do processo, o lease vence e permite retomada, respeitando o teto de três tentativas. Encerramento abrupto pode deixar cópias não confirmadas no disco; coleta automática dessas sobras não é implementada.
- O comando não reinicia sozinho após boot nem oferece persistência do disco do runner entre jobs. A persistência testada é SQLite em disco protegido durante a vida do ambiente de execução.

## Resultados e auditoria

A resposta JSON informa `run_id`, `status`, contadores desta invocação, tempo decorrido e `queue_counts` da investigação. Estados de parada: `drained`, `drained_with_errors`, `awaiting_lease`, `task_limit`, `time_limit`, `paused`, `cancelled` e `blocked`. A existência de trabalho restante não é uma solução validada. O retorno normal da CLI é JSON com exit 0, inclusive paradas controladas com erros de tarefas; operadores devem examinar status e contadores. Interrupção usa exit 130.

Checkpoints `worker_started`, `worker_progress` e `worker_stopped` e os eventos correspondentes de auditoria permitem consultar progresso e causa de parada. Falhas de tarefas não são repetidas automaticamente sem um lease interrompido elegível. O worker não formula novas hipóteses com IA e não resolve a investigação automaticamente.

## Validação e pendências

Os testes da beta usam arquivos sintéticos e executam pelo GitHub Actions. Integrações reais Codex/Claude, instalação como serviço, isolamento de processos de análise, worktrees de agentes, recursos financeiros rígidos e agendamento duradouro continuam fora deste incremento. Nenhum arquivo de cliente ou segredo deve ir para o repositório, CI ou logs. Nenhuma instalação no computador do proprietário é exigida.

A sequência acordada mantém orquestração antes de investigação de arquivos, perícia e agentes. Cada requisito externo pendente será registrado, sem considerar um teste com adaptador sintético como validação real de provedor ou hardware.
