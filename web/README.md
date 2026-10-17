# CYBER CORE — interface web (protótipo)

Item 15 do escopo ("Interface do sistema"), fase visual: um painel moderno,
em HTML/CSS/JS puro (sem build, sem dependências), para validar o fluxo
essencial do CORE antes de conectar a um backend real ou empacotar como
app desktop.

## O que é e o que não é

- **É**: HTML/CSS/JS estático, sem nenhuma chamada de rede. Todo estado
  (investigações, tarefas, trilha de auditoria) fica em `localStorage`,
  só no navegador de quem está usando. A cadeia de auditoria usa SHA-256
  real (Web Crypto API) com o mesmo princípio do `memory.audit()` do
  backend (cada evento guarda o hash do anterior) — dá para ver a cadeia
  quebrar se os dados forem adulterados manualmente no `localStorage`.
  O botão de relatório gera e baixa um Markdown real a partir dos dados
  da investigação selecionada.
- **Não é**: não está conectado ao motor real do CORE (o CLI `cyber`).
  Criar uma "investigação" aqui não chama `cyber investigate`, não grava
  no SQLite real, não analisa arquivo nenhum. Isso é intencional nesta
  fase — ver `docs/escopo.md`, item 15: terminal funcional primeiro,
  depois interface gráfica.

O banner no topo da página deixa isso explícito para quem for usar.

## Rodar localmente

Não precisa de nada além de um servidor estático (são arquivos simples):

```bash
cd web
python3 -m http.server 8080
# abra http://localhost:8080/
```

Ou simplesmente abra `index.html` direto no navegador.

## Publicar no GitHub Pages

Workflow em `.github/workflows/pages.yml` publica esta pasta automaticamente
a cada push na branch padrão. Passo manual único e necessário (só o
dono do repositório pode fazer, via configurações do GitHub):

1. **Settings → Pages**
2. Em "Build and deployment" → **Source**, selecionar **GitHub Actions**
   (não "Deploy from a branch").

Depois disso o workflow passa a publicar sozinho; a URL aparece em
Settings → Pages após o primeiro deploy bem-sucedido.

## Próximos passos (fora desta fase)

- Ligar a um backend real (API local em cima de `cyber_core.service.Core`)
  para que as ações passem a valer de verdade.
- App desktop nativo (Windows), reaproveitando este HTML/CSS/JS como a
  camada visual dentro de um WebView, conforme combinado com o
  proprietário.
