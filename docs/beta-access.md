# Beta privado — controle exclusivo do proprietário

**Escolha expressa do proprietário:** só ele usa e administra o beta;
Codex e Claude continuam desenvolvendo e testando.

**Estado atual: política registrada; autenticação e exclusividade operacional
ainda não implementadas.** O projeto não oferece hoje um serviço hospedado
com login. A CLI valida escopo e responsável declarado, mas isso não prova
a identidade de quem a executa. Esta entrega não transforma esses campos
em autenticação nem configura permissões externas.

## Papéis

| Papel | Identidade/escopo | Pode fazer |
|---|---|---|
| Proprietário do beta | GitHub user ID `329758463`, login atual `oscaveras-a11y` | Usar e administrar o beta quando o acesso autenticado estiver validado; decidir autorização de casos e acesso operacional |
| Codex e Claude | Agentes de desenvolvimento, nas tarefas autorizadas | Implementar, revisar e testar amostras sintéticas em branches e runners GitHub |
| Terceiros | Nenhuma concessão operacional definida | Sem uso/administração do beta; não abrir cadastro, convites ou compartilhamento automaticamente |

Permissões de repositório e permissões de aplicação são diferentes. Poder
editar código ou executar CI não concede acesso a bancos, evidências,
credenciais ou administração operacional do beta. Credenciais de operação
devem permanecer separadas das credenciais de desenvolvimento.

O proprietário não escolheu aprovar cada execução de teste ou cada mudança
de desenvolvimento. As autorizações de trabalho existentes continuam válidas.
Publicação, inclusão de usuários e delegação administrativa não estão
autorizadas por essa escolha.

## Condições para liberar uso operacional

1. Definir o ponto real de entrada e execução do beta. O repositório e os jobs
   temporários de CI não são um serviço de investigação persistente.
2. Autenticar o proprietário por uma identidade verificada. Validar o ID
   permanente da conta, não nome digitado, parâmetro de CLI ou variável
   de ambiente isolada. Não guardar senha/token em código, banco de casos,
   logs ou artefatos.
3. Aplicar a autorização exclusiva em todas as operações e leituras de dados
   operacionais, inclusive administração, relatórios, memória e recuperação.
   Ocultar botões ou confiar apenas no cliente não é suficiente.
4. Negar acesso sem autenticação, com identidade diferente, sessão expirada
   ou contexto inválido. Acesso de desenvolvimento não pode desativar a
   verificação em um ambiente operacional.
5. Preservar a restrição GitHub-only atual. Não instalar ferramentas ou
   componentes no computador do proprietário; não levar dados reais de
   clientes aos runners para testar o login.
6. Validar casos positivos e negativos antes de declarar o beta exclusivo:
   proprietário correto; outro usuário; mesmo nome com outro ID; ausência,
   expiração e adulteração de credenciais; acesso direto a operações;
   tentativa de usar perfil de testes para ler dados operacionais.
7. Registrar evidência de validação e os limites reais do ambiente escolhido.
   Não disponibilizar o beta a terceiros nem tratá-lo como serviço seguro
   enquanto esses critérios estiverem pendentes.

Essas condições são requisitos da próxima implementação de controle de
acesso; **não são testes já executados** nem garantias presentes.

## Verificação desta decisão

Em 2026-10-17, o conector autenticado do GitHub identificou o proprietário
como `oscaveras-a11y` (ID `329758463`), confirmou sua permissão `admin` e
a visibilidade `private` do repositório ID `1415716753`.

Isso confirma a identidade/permissão consultadas no GitHub, não exclusividade
de administração de todos os colaboradores nem autenticação da aplicação.
Não foram alterados colaboradores, visibilidade, proteção de branches,
secrets, credenciais ou a branch do Claude.

As regras para os dois agentes estão em [AGENTS.md](../AGENTS.md) e
[CLAUDE.md](../CLAUDE.md). Nenhuma instalação ou execução do produto no
computador do proprietário foi feita.
