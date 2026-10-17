# Pending modules implementation plan

**Goal:** concluir os fluxos de uso dos módulos já autorizados e a recuperação persistente por candidatas.
**Spec:** docs/pending-modules-design.md.
**Execution:** implementação nesta sessão; dispensa de aprovações intermediárias preservada de AGENTS.md e docs/continuation-plan.md.

## Restrições
- Somente GitHub e runners temporários; Windows/Linux; nenhum dado real no CI.
- Não alterar/integrar automaticamente a branch do Claude.
- Senhas/chaves por stdin ou arquivos protegidos; nunca em argv, SQLite, logs, relatórios ou artefatos.
- Sem login adicional no beta e sem inventar validação real dos provedores.

## Tarefas
- [x] Integrar PRs 14 e 15, já testados também na combinação com ferramentas reais.
- [x] Publicar contratos negativos de chaves e sessões, observar ausência dos módulos no Actions.
- [ ] Publicar/verificar contratos negativos de comandos de inventário e coordenador.
- [ ] Integrar inspeção de chaves da entrega anterior usando tabela própria aditiva para resultados.
- [ ] Implementar RecoverySessions.start/get/jobs/work/pause/resume/cancel/extend, namespace separado da versão global SQLite, compromisso HMAC das candidatas, claim/checkpoints e subprocesso fixo para uma tentativa.
- [ ] Integrar CLI de sessões, agent-jobs e inventário verificado de disco/PCAP, com relatórios.
- [ ] Verificar suíte completa e demonstração em Windows/Linux; corrigir falhas e reproduzir regressões.
- [ ] Validar combinação exata com candidato Claude imutável em runner.
- [ ] Revisar branch inteira, documentar evidências e integrar somente a própria entrega.
- [ ] Verificar recursos/credenciais para teste real dos provedores; executar somente se configurados, sem criar credenciais implicitamente.

## Revisão focada
Mutação de fonte/candidatas entre retomadas; pausa/revogação/cancelamento durante trabalho; perda/expiração de lease; publicação parcial ou após cancelamento; segredo acidental em saída. Cada condição deve ter teste negativo e a suíte completa deve passar.
