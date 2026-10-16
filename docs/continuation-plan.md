# Continuação até a validação integral

Autorização: o proprietário solicitou continuar até o último passo, mantendo a dispensa das aprovações intermediárias de desenvolvimento. A autorização operacional de cada caso continua obrigatória; isso não concede acesso a sistemas de terceiros.

Base: main 7c46ce2; 50 testes aprovados. A meta só termina quando todos os módulos previstos estiverem implementados, integrados, documentados e validados. Ausência de hardware/CLI/credenciais não deve ser mascarada por simulação.

## Entregas executáveis

1. **Ciclo científico e verificação**: hipóteses manuais, histórico de revisão, experimentos com critérios declarados, vinculação a resultados reais e fontes, revisão independente registrada e transições de estado condicionadas a evidências. Código em investigation/, verification/ e research/, com migração SQLite aditiva. Testar isolamento entre casos, resultados adulterados, revisão do próprio autor, experimentos pendentes e reabertura após nova evidência.
2. **Formatos e protocolos offline**: parsers com limites para Intel HEX, Motorola S-record, ELF/PE básicos, comparação de firmware, logs CAN e comparação estatística, ZIP e SQLite integrais quando viável, metadados e timelines. Cada parser terá vetores sintéticos válidos, truncamentos e checksums incorretos. Nenhum comando de atuação ou gravação em hardware.
3. **Orquestração**: mensagens estruturadas persistentes, atribuição/leases, worktrees Git exclusivas com aprovação e locks por arquivo, limites de chamadas/tokens informados e falhas explícitas de provedores. Validar o adaptador real Codex e o contrato Claude quando disponível; disponibilidade não equivale a autenticação.
4. **Ferramentas profissionais**: inventário/versionamento dos executáveis, adaptadores allowlist com argv sem shell, arquivos de saída limitados e autorizações específicas. Só marcar a integração como validada após execução real sobre controles sintéticos. Não executar malware nem varreduras em alvos ausentes.
5. **Autonomia**: worker persistente com checkpoints, cancelamento/pausa, recuperação de leases, detecção de repetições e ausência de progresso, monitoramento e instalação explícita como tarefa gerenciada Windows. Testes de reinício em novos processos. Não instalar tarefas de boot sem configuração concreta e autorização correspondente.
6. **Validação final**: suíte consolidada, teste de ponta a ponta, matriz de integrações reais/ausentes, revisão independente e documentação de operação. Publicar somente código/testes geradores/documentação. Não marcar a plataforma completa com itens externos pendentes.

## Contratos entre implementadores

Analisadores puros recebem Path para cópia verificada e limites explícitos e retornam dict serializável, sem modificar originais. Levantam CoreError com mensagem sem conteúdo sensível. Integração no serviço, SQLite, CLI e relatórios fica centralizada para evitar edição simultânea.

Firmware: `analyze_firmware(path, *, max_bytes=67108864, max_records=100000) -> dict`; `compare_firmware(first, second, *, max_bytes=67108864) -> dict`.

CAN: `analyze_can(path, *, max_bytes=16777216, max_frames=100000) -> dict`; `compare_can(first, second, *, max_bytes=16777216, max_frames=100000) -> dict`.

Cada tarefa segue teste negativo → implementação → teste positivo; achados da revisão recebem regressão antes da correção. Cada entrega só altera os caminhos sob sua responsabilidade. Contagens de testes e pendências são atualizadas com evidência real.
