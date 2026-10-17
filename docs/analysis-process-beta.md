# Processos monitorados de análise — beta

Entrega das seções 12 (execução), 14 (segurança) e 18 (testes), sob responsabilidade do Codex. Veja a [divisão das 21 seções](project-ownership.md) e a [validação desta entrega](validation-analysis-process-beta.md).

## Comportamento

Os caminhos existentes `analyze-file`, `assess-recovery`, `analyze-firmware` e `analyze-can` usam um processo Python filho fixo para adquirir cópias e executar seus parsers estáticos, inclusive comparações. Não há comando arbitrário vindo de um arquivo analisado. O filho não publica no SQLite; o processo principal revalida autorização e claim/token antes de confirmar resultado e auditoria.

O comando é construído pelo programa, sem shell. `-I` ignora PYTHONPATH e o diretório atual, e o bootstrap insere somente a raiz de pacote confiável. O ambiente repassado contém apenas SystemRoot/WINDIR, diretórios temporários e locale. Isso evita herdar automaticamente variáveis de credenciais, mas não impede leitura de arquivos pelo mesmo usuário.

Entrada JSON limitada a 64 KiB; stdout + stderr limitados a 2 MiB por padrão, com teto da API de 16 MiB. Saída inválida, processo com erro, excesso de saída ou metadados básicos incompatíveis são rejeitados. Não há reprodução do stderr bruto na mensagem operacional.

O supervisor monitora o tempo do processo, cancelamento, revogação/expiração e substituição do claim. A pausa continua valendo na fronteira entre operações, sem matar a análise atual. A execução recebe o tempo restante do orçamento do núcleo. O timeout não é um prazo máximo da investigação inteira: o caso pode ser retomado em execuções posteriores.

## Encerramento e preservação

No Windows, o filho aguarda stdin enquanto é associado a um Job Object sem breakaway e com `KILL_ON_JOB_CLOSE`. Falha de associação não libera a entrada de trabalho. O encerramento pede término de toda a árvore do job, aguarda handles de processo capturados e confirmação `ACTIVE_PROCESS_ZERO` via completion port, associada antes de iniciar o trabalho. A confirmação tem espera limitada a cinco segundos. Notificações do Windows podem faltar: nesse caso há falha, não uma confirmação presumida.

Até uma saída normal do processo líder provoca encerramento dos descendentes restantes. O Job Object também pede encerramento dos membros se o supervisor morrer abruptamente. Em POSIX existe uma implementação por grupo de processos, mas essa portabilidade não comprova a garantia Windows de fechamento do job após morte do pai.

Após o supervisor recuperar o controle, cópias não confirmadas são removidas. Resultados já confirmados antes de uma interrupção são preservados. Cancelamento invalida claims; um resultado tardio não pode ser publicado. Após morte abrupta do pai, pode restar uma cópia provisória sem registro confirmado: a retomada usa novo token e não apresenta essa sobra como evidência validada. Coleta automática dessas sobras permanece pendente.

Um evento `analysis_process_started` registra tarefa, PID e o tipo de contenção. Ele não comprova sucesso; o sucesso continua dependendo da transação `analysis_verified`, hash e critérios de verificação.

## Limites da beta

Este é isolamento de execução e gerenciamento de ciclo de vida, **não uma sandbox de privilégios ou rede**. O filho usa a identidade do processo principal. Não há bloqueio de rede, ACL por caso, VM, isolamento de kernel, limite rígido de CPU/RAM ou garantia de latência em tempo real. Bloqueios do sistema operacional/SQLite e limpeza podem adicionar tempo ao prazo de análise.

Somente código confiável de parsers é executado; as evidências são dados. A recuperação AES-GCM independente e os CLIs de agentes não foram movidos para este supervisor; continuam sob seus contratos existentes. Não houve instalação de serviço de boot nem promessa de persistência entre jobs do GitHub Actions.

O núcleo/CLI público e a versão SQLite não mudam nesta entrega. O ajuste em `service.py` é limitado à passagem da análise para o filho e à supervisão do claim. Alterações paralelas de configuração e contratos feitas pelo Claude precisam de validação conjunta antes de integração.

## Referências

- [Microsoft: Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [AssignProcessToJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject)
- [Completion ports associados a jobs](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_associate_completion_port)
