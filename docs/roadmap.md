# Estado das fases

| Fase | Estado desta entrega | Próximo critério |
|---|---|---|
| 1 — núcleo | Concluída no escopo inicial: CLI, configuração por arquivo/ambiente/flags, SQLite versionado, investigações, autorizações, auditoria; a suíte de testes passou e o entrypoint instalado executou (contagem atual em [validação](validation.md)) | Evoluir pela Fase 2 sem presumir módulos profissionais prontos |
| 2 — orquestração | Tarefas/leases/checkpoints, Codex autenticado e chamada real sintética validada; interface Claude opcional | Claude ausente, worktrees e locks em desenvolvimento, distribuição e revisão cruzada automatizada pendentes |
| 3 — investigação | Hipóteses versionadas, experimentos falsificáveis vinculados a evidências, revisão declarada, rejeição de repetições e critérios de estado testados | Planejamento automatizado de estratégias, autenticação de revisores, disposição de tarefas fracassadas e ensaios profissionais |
| 4 — ferramentas | Triagem, hashes/entropia, AES-GCM opcional sintético; parsers BIN/HEX/S-record/ELF/PE limitados e logs CAN clássicos com comparação offline | Perícia, segurança, parsers integrais por família e adaptadores de ferramentas profissionais ainda em desenvolvimento |
| 5 — autonomia | Persistência, pausa, retomada manual e limite de tentativas | Worker Windows, boot, cancelamento cooperativo, monitoramento e limites financeiros/recursos rígidos |
| 6 — validação completa | Testes automatizados do protótipo e demonstração sintética | Matriz integral dos módulos profissionais, testes de falhas, hardware e isolamento |

Não há pesquisa web automática, buscas de vulnerabilidades, recuperação de senhas, extração de chaves, execução de malware, gravação automotiva ou varredura de redes nesta entrega. Estados finais resolvidos exigirão um contrato de verificação adicional; o protótipo não promove resultados automaticamente.

Decisões: a raiz do repositório é a raiz do pacote, sem pasta cyber-core redundante. Diretórios de módulos futuros não são criados como implementações vazias. argparse e unittest evitam dependências adicionais. cryptography fornece AES-GCM; não foi escrita criptografia própria. `.env.example` é documentação e não carrega arquivos .env automaticamente; variáveis devem ser definidas explicitamente.
