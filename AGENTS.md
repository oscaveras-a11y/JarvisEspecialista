# CYBER CORE — instruções para os agentes

## Autoridade e beta privado

O proprietário confirmou: **só ele usa e administra o beta; Codex e Claude
continuam desenvolvendo e testando**.

Proprietário verificado pelo GitHub em 2026-10-17:
`oscaveras-a11y`, user ID `329758463`.
Repositório: `oscaveras-a11y/JarvisEspecialista`, repository ID `1415716753`.

- Uso e administração do beta pertencem ao proprietário. Ele escolheu testar
  primeiro o funcionamento **sem login adicional da aplicação nesta fase**.
- Acesso ao código, revisão, CI ou credenciais de desenvolvimento não concede
  papel de operador/admin do beta.
- Codex e Claude podem continuar implementações, correções, revisões e testes
  sintéticos dentro das tarefas autorizadas. Não exigir aprovação a cada teste
  ou mudança já autorizada.
- Não operar casos reais, convidar usuários, delegar administração, disponibilizar
  o beta a terceiros ou alterar permissões operacionais por decisão dos agentes.
- Não criar credenciais ou operar o beta em nome do proprietário por autorização
  implícita. Uma identidade declarada em texto não é identidade autenticada.
- Não criar login, senha, cadastro ou sessão nem exigir autenticação da
  aplicação como condição para o teste pessoal atual. Essa orientação expressa
  substitui a exigência anterior de login antes dos testes do proprietário.
- Sem login, não declarar que há garantia técnica de identidade ou exclusividade.
  Autenticação fica adiada; manter os controles de escopo, auditoria, integridade
  e cancelamento existentes. Não ampliar o uso para terceiros automaticamente.
- Política e critérios dos testes: [docs/beta-access.md](docs/beta-access.md).

## Ambiente autorizado

Desenvolvimento e validação **somente no GitHub**. Não instalar, clonar ou
executar o produto no computador do proprietário. Testes executam em runners
temporários do GitHub com arquivos sintéticos/autorizados, sem dados reais de
clientes, bancos operacionais, segredos ou evidências privadas em Git, logs
ou artefatos do CI.

## Divisão e entrega

Codex cuida das seções pares da lista original de 21 seções; Claude das
ímpares. Ver [docs/project-ownership.md](docs/project-ownership.md).
Cada agente trabalha em sua branch. Não editar ou integrar automaticamente
a branch do outro agente. Ajustes em contratos compartilhados exigem preservar
os dois lados e validar a combinação exata.

Apresentar o que foi implementado, o que foi executado, o resultado e o
pendente separadamente. Não confundir número de PR com item do projeto,
política documentada com controle de acesso implementado, teste sintético
com ensaio profissional ou revisão declarada com identidade autenticada.
