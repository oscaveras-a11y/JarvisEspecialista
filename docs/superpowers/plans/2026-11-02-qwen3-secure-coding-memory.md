# Memória ampla de programação segura — Plano de implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Entregar uma biblioteca local ampla de programação segura, pesquisável em SQLite FTS5 e pronta para futura integração com Qwen3, sem conectar o modelo nesta entrega.

**Architecture:** Dezoito guias Markdown autorais, em português e com fontes oficiais, são catalogados e indexados numa base SQLite FTS5 independente do banco operacional. A CLI indexa e busca trechos; o índice vive no diretório local de dados, pode ser reconstruído e não guarda código ou conversas do usuário.

**Tech Stack:** Python 3.12+, SQLite FTS5, `importlib.resources`, `argparse`, unittest existente; nenhuma dependência nova.

**Spec:** `docs/superpowers/specs/2026-11-02-qwen3-secure-coding-memory-design.md`

## Global Constraints

- Desenvolvimento e validação somente no GitHub Actions, com conteúdo e consultas sintéticos.
- Não alterar/migrar o banco operacional `Core` (schema 8).
- Guias públicos genéricos podem ser versionados; índice local contém apenas cópias derivadas desses guias.
- Sem integração Qwen3/Ollama, rede, embeddings, execução de código, credenciais reais ou coleta automática.
- Busca retorna no máximo 10 itens; consulta até 256 caracteres.
- PR separado; proprietário autorizou merge na `main` após checks aprovados.

## Review Focus

- SQLite sem FTS5: falhar com mensagem clara sem traceback ou alteração no banco de casos.
- Consulta com operadores ou caracteres SQL/FTS: tratar como texto, nunca como sintaxe executável.
- Reindexação repetida ou catálogo modificado: resultado idempotente e remoção de guias obsoletos.
- CLI de conhecimento com `--home`: não cria nem abre o banco operacional.
- Wheel/sdist: todos os 18 guias e catálogo permanecem acessíveis por `importlib.resources`.

---

## Entrega implementada

- Catálogo e 18 guias Markdown autorais em português, com revisão, evidências, correção, regressão, limites e fontes oficiais.
- Conteúdo empacotado com importlib.resources e disponível no pacote instalado.
- Índice separado SQLite FTS5: `default_database_path()`, `build_index(path=None)`, `search_index(query, path=None, limit=5)`. Reindexação substitui o índice em transação; consulta limitada e parametrizada.
- CLI `cyber knowledge index` e `cyber knowledge search QUERY` despacha antes de criar `Core`, mantendo o banco operacional independente.
- Guia de uso em `docs/secure-programming-memory.md`.
- Qwen3/Ollama, integração de chat, dados de usuário e treinamento continuam fora do escopo.

## Validação

Os checks e resultados Linux/Windows estão vinculados à aba Actions do PR. Execução local de produto/testes não foi feita, conforme AGENTS.md; as validações usam GitHub Actions e fixtures sintéticas.
