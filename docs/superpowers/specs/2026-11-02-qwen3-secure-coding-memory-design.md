# Memória local de programação segura para o Jarvis

**Estado:** desenho aprovado; primeira entrega sem integração de modelo  
**Data:** 2026-11-02  
**Base examinada:** `main` em `d7218fbfde77097dac79e3d490efa16cd978ec98`

## Intenção

Adicionar ao Jarvis uma biblioteca local, pequena e revisável de programação segura, consultável por busca textual e persistida em SQLite no disco. Esta etapa prepara a memória para uso futuro por Qwen3, mas não integra nem chama Ollama agora. O objetivo é ajudar a localizar riscos em código autorizado e apresentar evidências, correções e fontes; não prometer código sem erros.

A expressão “locais frágeis de invadir” será tratada como pontos de código que merecem revisão defensiva: entradas, validação, autenticação/autorização, limites de confiança e tratamento de segredos.

## Estado encontrado

- `src/cyber_core/memory/__init__.py` mantém o banco operacional e registros/auditoria.
- `Core.recall_by_hash` e `Core.recall_by_type` recuperam casos anteriores; não existe busca de guias de programação.
- O pacote não possui cliente de chat Ollama/Qwen3.
- A memória de conhecimento ficará em banco SQLite separado, para preservar o banco de casos e sua versão global.

## Abordagens consideradas

1. Arquivos Markdown com busca simples: muito simples, mas sem ranking ou limites uniformes de resultado.
2. Guias Markdown versionados + índice SQLite FTS5 local e reconstruível: mantém fontes legíveis, busca ordenada, baixo consumo e nenhuma dependência de embeddings. **Escolhida.**
3. Banco vetorial/embeddings: busca semântica potencialmente útil, mas exige outro modelo, mais dependências e memória; não é necessário para esta primeira versão.

## Escopo da primeira entrega

- Guias Markdown incluídos no pacote, com catálogo estável de ID, tópico, título, versão e referências.
- Conteúdo defensivo sobre SQL parametrizado, chamadas de processo, XSS, autenticação, autorização, segredos, dependências, serviços expostos, uploads e testes de regressão.
- Cada guia descreve sinais de risco no fluxo de dados/código, evidências a verificar, mitigação e teste corretivo. Não traz receitas de exploração ou descoberta de credenciais.
- Um módulo `KnowledgeBase` dedicado cria/recria índice FTS5 num banco separado e expõe busca lexical limitada com título, tópico, trecho e fontes.
- CLI `cyber knowledge index` e `cyber knowledge search`. Os comandos não inicializam nem alteram o banco de casos.
- Caminho padrão do índice fica na pasta local de dados do usuário (XDG no Linux/macOS; LOCALAPPDATA no Windows); `--db` permite teste/configuração explícita. O índice é derivado e pode ser reconstruído.
- Nenhuma conversa, código do proprietário, evidência ou resultado será indexado automaticamente. Nenhum prompt será gravado.
- A integração que injeta resultados na Qwen3/Ollama é uma etapa futura e requer novo desenho/teste. Nenhum modelo ou adaptador é alterado nesta entrega.
- Validação de recuperação usa consultas sintéticas por tópico no GitHub Actions; não mede geração nem proficiência de IA.

## Fora do escopo

- Integração com chat, API Ollama/Qwen3, qualquer chamada de modelo ou treinamento/fusão de pesos.
- Importar repositórios/código privados, documentos arbitrários ou gravar conversas sem pedido explícito.
- Senhas, credential stuffing, quebra de credenciais, instruções para invadir ou exploração de sistemas reais.
- Dependências externas de busca vetorial, embeddings ou serviço online.
- Instalar ou executar o produto no computador do proprietário.

## Critérios de aceitação

1. `cyber knowledge index` constrói ou reconstrói o banco local a partir dos guias empacotados, de forma idempotente.
2. `cyber knowledge search` retorna até 10 resultados relevantes, com tópico, título, trecho e referências verificáveis; consulta vazia/sem correspondência não inventa resultado.
3. Limites de tamanho da consulta e quantidade de resultados são aplicados; texto de busca é passado como dado, não como SQL/FTS bruto.
4. Os comandos falham claramente se SQLite não oferecer FTS5 e não alteram o banco operacional.
5. Testes em Linux e Windows do GitHub usam somente diretórios/banco e conteúdo sintéticos; não executam Ollama nem código analisado.
6. PR permanece separado; integração na `main` só após a validação em CI desta entrega. A autorização atual do proprietário permite integrar quando os checks forem aprovados.

## Limitações

Busca lexical pode não encontrar sinônimos; artigos curtos e curados não cobrem todas as linguagens/frameworks. O conteúdo fornece referência para revisão, não resultado de scanner nem prova de vulnerabilidade. A memória não torna a Qwen3 melhor até uma integração futura conectar a recuperação ao prompt. Os checks de CI validam apenas índice e busca, não inferência real.
