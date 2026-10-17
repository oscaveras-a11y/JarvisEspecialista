# Conclusão incremental das pendências — 17/10/2026

Autorização preservada: o proprietário pediu concluir as pendências e dispensou aprovações intermediárias (AGENTS.md, docs/continuation-plan.md). Desenvolvimento e testes somente no GitHub; nenhuma instalação no computador do proprietário. A branch do Claude não será editada nem integrada automaticamente.

## Entregas
1. Integrar os módulos já testados dos PRs 14 e 15 na main (concluído), preservando contratos.
2. Disponibilizar comandos do coordenador persistente Codex/Claude, inventário autorizado de disco/PCAP e inspeção/varredura de chaves. Resumos enviados só mediante autorização explícita; resultados e limites são reconstruíveis no relatório.
3. Sessões persistentes de recuperação: janela inicial de 24 horas, candidata a extensão explícita por prioridade e motivo; arquivo de candidatas fornecido pelo proprietário, CCAES1 com chaves hex de 32 bytes ou chave SSH privada com senhas UTF-8. Sem geração ou busca universal de chaves.
4. SQLite separado por namespace, leases e token por trabalhador, checkpoint após cada tentativa, retomada após processo interrompido. Pausa/revogação/cancelamento e validade da autorização são rechecados antes de tentativas e antes de publicação.
5. Arquivo alvo adquirido por cópia verificada e SHA-256; candidatas não persistidas no SQLite nem em relatórios. Vinculação das candidatas por HMAC com segredo local independente, fora do Git. Processo filho fixo recebe uma candidata por stdin, nunca por argumentos; limites de tempo/saída e árvore de processos.
6. GCM: somente publicar plaintext após autenticação, hash, verificação de claim e autorização. SSH: validar senha/estrutura sem exportar a chave privada descriptografada. Relatórios contêm metadados e resultado, nunca senhas ou material de chave.
7. Testes negativos antes da implementação, suíte completa Windows/Linux no Actions e combinação temporária com candidato Claude imutável. Validação real dos provedores exige secrets e resposta efetiva; testes offline não a substituem.

## Limites operacionais
Janela de 24h não exige 24h de CPU: uma lista esgotada encerra a sessão. Trabalhadores executam fatias limitadas com checkpoints. Um job do GitHub hospedado não oferece execução ininterrupta de 24h nem armazenamento operacional durável entre runners. Não exportar bancos/candidatas/evidências reais como artefatos do CI; esta entrega testa apenas material sintético. Execução prolongada real necessita armazenamento autorizado e infraestrutura durável, ainda não provisionados.

ZIP/PDF e recuperação de chave privada perdida continuam limitados à triagem e inventário de backups; não alegar recuperação universal. Ausência de senha correta/chave recuperável não é solucionada ampliando o tempo. Sem login adicional na aplicação nesta fase; não há garantia técnica de exclusividade de identidade.
