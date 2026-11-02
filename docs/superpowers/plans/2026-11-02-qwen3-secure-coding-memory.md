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

### Task 1: Corpus amplo, catálogo e pacote

**Files:**
- Create: `src/cyber_core/memory/guides/catalog.json`
- Create: 18 guias `src/cyber_core/memory/guides/*.md` conforme lista no catálogo
- Modify: `pyproject.toml`
- Test: `tests/test_knowledge.py)

**Interfaces:**
- Cada entrada do catálogo tem `id`, `title`, `topic`, `version`, `path`, `sources`.
- Cada guia tem pelo menos 1.500 caracteres e as seções `Como revisar`, `Evidências`, `Correção`, `Teste de regressão`, `Limites` e `Fontes`.
- Os 18 temas são os listados em `Escopo da primeira entrega` na spec; material é defensivo e escrito em português.

- [ ] **Step 1: Write failing catalog tests** — `test_catalog_contains_eighteen_complete_topics`, `test_guide_sections_and_minimum_length`, `test_catalog_paths_and_ids_are_valid`, `test_sources_are_official_https`.
- [ ] **Step 2: Run focused tests in GitHub Actions** with `python scripts/run-tests.py test*.py TestKnowledgeGuideCatalog`; expected RED for missing catalog and guides.
- [ ] **Step 3: Add 18 original guides and catalog**. Include official OWASP/CWE/language documentation references, concrete review cues, safe remediation examples, regression-test ideas, and uncertainty/false-positive notes. No exploit payloads or credential-discovery procedure.
- [ ] **Step 4: Package resource files** via setuptools package-data for `cyber_core.memory`.
- [ ] **Step 5: Run focused catalog tests** in GitHub Actions; verify package resources are readable with `importlib.resources`.

### Task 2: Separate SQLite FTS5 index

**Files:**
- Create: `src/cyber_core/memory/knowledge.py`
- Modify: `tests/test_knowledge.py`

**Interfaces:**
- `default_knowledge_path() -> Path`: Windows `LOCALAPPDATA/CyberCore/knowledge.sqlite3`; otherwise `XDG_DATA_HOME/cyber-core/knowledge.sqlite3` or `~/.local/share/cyber-core/knowledge.sqlite3`.
- `KnowledgeBase(database: str | Path)`: separate database, schema version 1.
- `KnowledgeBase.index_builtin_guides() -> int`: transactional replacement from packaged catalog; returns 18.
- `KnowledgeBase.search(query: str, limit: int = 5) -> list[dict]`: returns `id`, `title`, `topic`, `snippet`, `sources`, `version`; query length 1–256 and limit 1–10.
- `KnowledgeBase.close() -> None`.

- [ ] **Step 1: Write failing index tests** — `test_index_is_idempotent`, `test_search_returns_ranked_source_snippets`, `test_search_no_match_is_empty`, `test_fts_operators_are_literal`, `test_invalid_query_and_limit_fail_clearly`, `test_rebuild_removes_obsolete_rows`, `test_missing_fts5_reports_clear_error`.
- [ ] **Step 2: Run focused tests in Actions** with `python scripts/run-tests.py test*.py TestKnowledgeIndex`; expected RED for missing KnowledgeBase.
- [ ] **Step 3: Implement FTS5** with parameterized SQL and normalized/quoted tokens; detect missing FTS5; replace the complete index in one transaction; load packaged guides via `importlib.resources`.
- [ ] **Step 4: Run focused index tests** on GitHub Linux and Windows.

### Task 3: CLI commands without Core side effects

**Files:**
- Create: `src/cyber_core/cli/knowledge.py`
- Modify: `src/cyber_core/cli/__init__.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- `cyber knowledge index [--db PATH]`
- `cyber knowledge search QUERY [--db PATH] [--limit N]`
- `cyber_core.cli.knowledge.execute(args) -> dict`; knowledge dispatch occurs before `Core(args.home, ...)`.

- [ ] **Step 1: Write failing subprocess tests** — `test_knowledge_index_and_search_cli`, `test_knowledge_cli_does_not_initialize_case_store`, `test_knowledge_cli_invalid_limit_is_clear`.
- [ ] **Step 2: Run focused CLI tests in Actions** with `python scripts/run-tests.py test*.py TestKnowledgeCLI`; expected RED for absent command.
- [ ] **Step 3: Add nested argparse and isolated dispatch**; use `--db` with temp paths in tests; output JSON, safe errors, no traceback.
- [ ] **Step 4: Run CLI-focused tests** in Actions; assert no `core.sqlite3` under isolated `--home`.

### Task 4: Documentation and cross-platform validation

**Files:**
- Create: `docs/secure-coding-memory.md`
- Modify: `README.md`
- Test: `tests/test_knowledge.py`, `tests/test_cli.py`

- [ ] **Step 1: Document** the 18 guide topics, source review/versioning, Linux/Windows database paths, CLI usage, rebuilding, limitations and deferred Qwen3 integration.
- [ ] **Step 2: Add retrieval smoke tests** with one natural-language synthetic query per topic and expected topic/source.
- [ ] **Step 3: Run full CI** on GitHub Linux and Windows with Python 3.12; require full suite and packaging checks to pass.
- [ ] **Step 4: Review the exact PR diff and Actions results**; resolve failures before integration.
- [ ] **Step 5: Merge to `main` only after all required checks pass**, as authorized by the owner.

