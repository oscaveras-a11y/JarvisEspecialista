# Item 15 — Interface do sistema: fase visual (protótipo web)

A pedido do proprietário ("vamos criar uma interface para rodar esse programa,
tem que ser fácil de usar e intuitiva, com cara de moderna"), iniciei a fase
gráfica do item 15, que o escopo já descreve em duas etapas: "Inicialmente,
terminal funcional [...]. Depois, interface gráfica profissional [...]".
O terminal (CLI `cyber`, 38 subcomandos) já existe e está testado; isto cobre
a fase seguinte.

## Decisão de escopo (confirmada com o proprietário)

- **Entrega agora**: painel web estático (HTML/CSS/JS puro, sem build, sem
  dependências), publicado via GitHub Pages — "por enquanto vamos deixar
  rodando no servidor do GitHub", nas palavras do proprietário.
- **Fluxo coberto nesta primeira versão** ("fluxo essencial primeiro"):
  criar investigação, acompanhar tarefas, ver logs/hipóteses, pausar/
  retomar/cancelar, exportar relatório — o mesmo conjunto que o escopo
  descreve para o terminal funcional, agora visual.
- **Entrega futura, já combinada**: app desktop nativo para Windows,
  reaproveitando este HTML/CSS/JS como camada visual.

## O que é e o que não é (honestidade de estado)

Esta é a camada **visual** apenas. Não está conectada ao motor real do CORE:
criar uma "investigação" nesta interface não chama `cyber investigate`, não
grava no SQLite real, não analisa arquivo nenhum. Isso está dito explicitamente
num banner na própria página (`web/index.html`), não escondido em letra miúda.

O que a interface faz de verdade, sem fingir:
- Estado local persistido em `localStorage` do navegador (investigações,
  tarefas, trilha de auditoria) — sobrevive a recarregar a página, não sai
  do navegador.
- Trilha de auditoria com **SHA-256 real** via Web Crypto API, seguindo o
  mesmo princípio do `memory.audit()` do backend (cada evento guarda o hash
  do evento anterior); botão "verificar integridade da cadeia" recalcula e
  compara de verdade.
- Geração e download de um relatório Markdown real, montado a partir dos
  dados da investigação selecionada.
- Confirmação obrigatória (motivo + diálogo) antes de cancelar uma
  investigação — mesmo princípio de "confirmação para ações destrutivas"
  do item 14, aplicado também na camada visual.

## Validação feita

- `node --check web/app.js` — sem erros de sintaxe.
- HTML validado com `html.parser` do Python — sem erros de parsing.
- Teste de ponta a ponta com Playwright/Chromium (headless, já disponível
  no ambiente): criar investigação → enfileirar tarefa → verificar cadeia
  de hash (resultado: íntegra) → gerar relatório → captura de tela do
  painel renderizado. Nenhum erro de console/JS durante o fluxo.
- Suíte Python completa (391 testes) revalidada sem alteração — esta
  entrega não toca nenhum arquivo Python.

## Publicação

`.github/workflows/pages.yml` publica `web/` via GitHub Pages a cada push
em `main` ou nesta branch de desenvolvimento. Passo manual único, que só o
proprietário pode fazer: **Settings → Pages → Source: GitHub Actions**
(instruções completas em `web/README.md`).

## Pendências explícitas (não escondidas)

- Sem conexão com o backend real — ações na UI não produzem efeito no
  CORE de verdade. Ligar isso é o próximo passo combinado.
- Sem autenticação — consistente com a decisão já registrada em
  `CLAUDE.md`/`AGENTS.md` de adiar login até o teste pessoal terminar.
- App desktop nativo (Windows) fica para uma etapa seguinte, já acordada
  com o proprietário.
