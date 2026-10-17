# Beta pessoal — testes de funcionamento sem login

**Orientação atual do proprietário:** o beta não precisa de login no momento.
Primeiro ele quer testar e verificar o funcionamento. Essa orientação
substitui a exigência anterior de autenticação antes do teste pessoal.

O uso e a administração do beta continuam reservados ao proprietário.
Codex e Claude continuam desenvolvendo e testando nas tarefas autorizadas,
sem pedir confirmação a cada execução de teste ou mudança já autorizada.

## Escopo desta fase

- Permitir o teste pessoal de funcionamento **sem criar login, senha, cadastro
  ou sessão de autenticação**.
- Não tratar a ausência de autenticação como bloqueio para esses testes.
- Manter desenvolvimento e execução dos testes somente no GitHub, sem
  instalar, clonar ou executar o produto no computador do proprietário.
- Usar os testes e demonstrações com dados sintéticos/autorizados já
  previstos no projeto; registrar o que funcionou, falhou e continua pendente.
- Preservar a validação de escopo, limites de recursos, auditoria, integridade,
  pausa, cancelamento e proteção dos resultados já implementados.
- Manter Codex e Claude nos trabalhos de desenvolvimento e testes; não
  conceder por isso operação de casos reais, administração do beta ou
  autorização para convidar terceiros.
- Não publicar um serviço nem ampliar acesso automaticamente. Qualquer
  inclusão de usuários ou mudança para uso compartilhado exige nova decisão
  do proprietário.

## Papéis

| Papel | Identidade/escopo | Pode fazer nesta fase |
|---|---|---|
| Proprietário do beta | `oscaveras-a11y`, GitHub user ID `329758463` | Testar o funcionamento e administrar o beta pessoal, sem login adicional da aplicação |
| Codex e Claude | Agentes nas tarefas autorizadas | Implementar, revisar e executar testes sintéticos nos runners GitHub |
| Terceiros | Sem concessão definida | Sem autorização de uso ou administração; nenhum cadastro ou convite automático |

A reserva de uso ao proprietário é uma regra de operação. **Sem login da
aplicação, ela não é uma garantia técnica de identidade ou de acesso
exclusivo.** Isso não impede a fase pessoal de testes escolhida pelo
proprietário. Autenticação fica fora do escopo atual e poderá ser retomada
se ele solicitar posteriormente.

## Como verificar o funcionamento agora

No GitHub, consultar os resultados de **Actions / Offline validation** e
os checks dos PRs. O workflow existente permite disparo manual pela
interface do GitHub na branch padrão; isso usa o acesso normal à conta
GitHub e não exige implementar login adicional no beta.

A validação existente instala o pacote somente no runner temporário,
confere a CLI, executa a suíte e a demonstração sintética. Os resultados
devem identificar o commit testado e as limitações. O repositório e os
jobs de CI ainda não são um serviço persistente com painel interativo;
não declarar que esse serviço já está disponível.

Bancos operacionais, evidências, segredos e dados reais de clientes
continuam fora do Git e dos logs/artefatos de CI. A orientação de não
instalar nada no computador permanece válida.

## Referência de propriedade

Repositório atual: `oscaveras-a11y/JarvisEspecialista`, ID `1415716753`
(o mesmo projeto antes chamado CyberCore). A consulta anterior do conector
GitHub confirmou o proprietário `oscaveras-a11y` (ID `329758463`),
permissão `admin` e visibilidade `private`; essa consulta não constitui
login da aplicação nem inventário de todos os colaboradores.

As instruções para os dois agentes estão em [AGENTS.md](../AGENTS.md) e
[CLAUDE.md](../CLAUDE.md). Esta atualização corrige a política e não remove
autenticação de código: nenhum login da aplicação havia sido implementado.
