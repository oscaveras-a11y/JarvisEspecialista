# Memória local ampla de programação segura para o Jarvis

**Estado:** escopo aprovado pelo proprietário; primeira entrega sem integração de modelo  
**Data:** 2026-11-02  
**Base examinada:** `main` em `d7218fbfde77097dac79e3d490efa16cd978ec98`

## Intenção

Adicionar ao Jarvis uma biblioteca local, ampla, revisável e pesquisável de programação segura, persistida em SQLite no disco. Esta etapa prepara a memória para uso futuro pela Qwen3, mas não integra nem chama Ollama agora. O objetivo é ajudar a reconhecer pontos frágeis em código autorizado, explicar evidências, propor correções e sugerir testes — sem prometer código sem erros.

“Locais frágeis de invadir” significa pontos de revisão defensiva: entradas, consultas, execução de processos, saída em navegador, autenticação/autorização, dados serializados, arquivos, configuração, dependências, serviços expostos e tratamento de segredos.

## Estado encontrado

- `src/cyber_core/memory/__init__.py` mantém o banco operacional e registros/auditoria.
- `Core.recall_by_hash` e `Core.recall_by_type` recuperam casos anteriores; não existe busca de guias de programação.
- O pacote não possui cliente de chat Ollama/Qwen3.
- A memória de conhecimento ficará em banco SQLite separado, para preservar o banco de casos e sua versão global.

## Abordagens consideradas

1. Arquivos Markdown com busca simples: muito simples, mas sem ranking ou limites uniformes de resultado.
2. Guias Markdown detalhados e catalogados + índice SQLite FTS5 local/reconstruível: mantém fontes legíveis, busca ordenada, baixo consumo e nenhuma dependência de embeddings. **Escolhida.**
3. Banco vetorial/embeddings: busca semântica potencialmente útil, mas exige outro modelo, dependências e RAM; desnecessário para esta etapa.

## Escopo da primeira entrega

- Uma biblioteca extensa, autoral e em português com **18 guias**: visão geral/revisão segura; Python; JavaScript/TypeScript; validação de entradas; SQL; comandos de sistema; XSS; autenticação e armazenamento defensivo de senhas; autorização; segredos/configuração; dependências; serviços/APIs expostos; uploads; caminhos/arquivos; desserialização; logs/erros; criptografia aplicada; testes/revisão de código.
- Cada guia cobre contexto, sinais de risco no fluxo de código, evidências para confirmar ou descartar alerta, correções, teste de regressão e fontes oficiais. Conteúdo original em resumo, não cópia extensa de terceiros.
- A biblioteca foca proteção, revisão em código autorizado e correção. Não contém payloads ou receitas passo a passo para explorar alvos.
- Um catálogo versionado fornece ID, tópico, título, versão e referências. Guias ficam empacotados como Markdown; o índice FTS5 é derivado e reconstruível.
- Funções `default_database_path()`, `build_index(path=None)` e `search_index(query, path=None, limit=5)` mantêm o índice no disco e oferecem busca lexical limitada com tópico, título, versão do guia, trecho e fontes.
- CLI `cyber knowledge index` e `cyber knowledge search`. Os comandos não inicializam nem alteram o banco operacional de casos.
- Caminho padrão do índice fica na pasta local de dados do usuário (XDG no Linux/macOS; LOCALAPPDATA no Windows); `--db` permite configuração explícita e testes. Nenhuma conversa, código do proprietário, evidência ou resultado será indexado automaticamente.
- Integração que injeta contexto na Qwen3/Ollama fica para etapa futura e exige novo desenho/teste. Nenhum peso ou adaptador será alterado nesta entrega.
- Consultas sintéticas por tópico avaliam a recuperação no GitHub Actions; isso não mede geração ou proficiência de IA.

## Fora do escopo

- Integração com chat, API Ollama/Qwen3, chamadas de modelo, treinamento ou fusão de pesos.
- Importação automática de repositórios/código privados, documentos arbitrários ou conversas.
- Senhas, credential stuffing, quebra de credenciais, instruções para invadir ou exploração de sistemas reais.
- Embeddings, banco vetorial, serviço online ou dependência externa de busca.
- Instalar/executar o produto no computador do proprietário.

## Critérios de aceitação

1. O catálogo contém 18 guias completos, com tamanho mínimo verificável, as seções de sinais, evidência, correção e teste, e referências oficiais HTTPS.
2. `cyber knowledge index` constrói/reconstrói o banco separado de forma idempotente; a busca retorna até 10 resultados com tópico, título, trecho e fontes.
3. Uma consulta sintética por guia recupera o tópico esperado; consulta vazia/sem correspondência não inventa material.
4. Limites de consulta/resultado são aplicados; termos são tratados como dados, não como SQL/FTS bruto.
5. FTS5 ausente falha claramente sem traceback e sem tocar no banco operacional.
6. Linux e Windows no GitHub Actions usam só dados sintéticos. A integração Qwen3/Ollama permanece explicitamente pendente.
7. O PR só é integrado à `main` após checks aprovados, conforme autorização expressa do proprietário.

## Limitações

FTS5 é busca lexical e pode não encontrar sinônimos; corpus curado não cobre todas as linguagens/frameworks. A memória oferece referências para revisão, não um scanner ou prova de vulnerabilidade. Ela não altera a Qwen3 até a futura etapa de integração. CI valida índice e busca, não inferência real. Material externo deve ser revisado quando suas referências ou versões mudarem.
