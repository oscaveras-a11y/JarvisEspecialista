# Memória local de programação segura — Plano de implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Entregar uma biblioteca local e pesquisável de guias defensivos, separada do banco operacional, pronta para uma futura integração com Qwen3.

**Architecture:** Guias Markdown versionados e catalogados são indexados em uma base SQLite FTS5 separada, reconstruível no disco local. A CLI oferece indexação e busca lexical com fontes, sem invocar modelo, rede, ferramentas ou registrar automaticamente consultas.

**Tech Stack:** Python 3.12+, SQLite FTS5, `importlib.resources`, `argparse`, unittest existente; nenhuma dependência nova.

**Spec:** `docs/superpowers/specs/2026-11-02-qwen3-secure-coding-memory-design.md`

## Global Constraints

- Desenvolvimento e validação somente no GitHub Actions, com conteúdo sintético.
- Não alterar nem migrar o banco operacional `Core` (schema 8).
- Banco de conhecimento fica fora do repositório e contém somente guias públicos empacotados.
- Sem Ollama/Qwen, rede, embeddings, execução de código, credenciais reais ou coleta automática.
- Busca retorna fonte e limite máximo de 10 resultados; consulta até 256 caracteres.
- PR separado; proprietário autorizou merge à `main` após checks aprovados.

## Review Focus

- SQLite sem FTS5: o comando deve falhar com mensagem de recurso indisponível e sem tracebacks.
- Consulta contendo sintaxe FTS/SQL especial: deve ser tratada como texto e não vazar erro SQLite.
- Reindexação repetida: não duplica guias e remove entradas obsoletas do catálogo.
- Chamada CLI de conhecimento com `--home`: não cria nem abre o banco operacional de casos.
- Empacotamento wheel/sdist: os Markdown e o catálogo precisam estar disponíveis via `importlib.resources`.

---

### Task 1: Guias fonte e pacote

**Files:**
- Create: `src/cyber_core/memory/guides/catalog.json`
- Create: `src/cyber_core/memory/guides/sql-injection.md`
- Create: `src/cyber_core/memory/guides/command-injection.md`
- Create: `src/cyber_core/memory/guides/xss.md`
- Create: `src/cyber_core/memory/guides/authentication.md`
- Create: `src/cyber_core/memory/guides/authorization.md`
- Create: `src/cyber_core/memory/guides/secrets.md`
- Create: `src/cyber_core/memory/guides/dependencies.md`
- Create: `src/cyber_core/memory/guides/exposed-services.md`
- Create: `src/cyber_core/memory/guides/uploads.md`
- Modify: `pyproject.toml`
- Test: `tests/test_knowledge.py`

**Interfaces:**
- Catalog entries contain `id`, `title`, `topic`, `version`, `path`, `sources`.
- Each Markdown guide contains defensive signals, evidence, remediation, a regression-test idea, and only high-level safe examples.

- [ ] **Step 1: Write failing packaging/content tests** — assert all catalog paths exist, IDs are unique, sources are HTTPS URLs, and each of the nine named topics has non-empty content with evidence and remediation sections.
- [ ] **Step 2: Run the focused test in GitHub Actions** — `python scripts/run-tests.py test*.py TestKnowledgeGuideCatalog`; expect failure because the catalog/guides/tests do not exist.
- [ ] **Step 3: Add catalog and guides** using concise author-written defensive material with official OWASP/CWE documentation links; do not include real credentials, private code, or exploit recipes.
- [ ] **Step 4: Package guide resources** with `[tool.setuptools.package-data]` entry for `cyber_core.memory = ["guides/*.json", "guides/*.md"]`.
- [ ] **Step 5: Run focused packaging/content tests** and confirm package resources are readable through `importlib.resources`.

### Task 2: Separate FTS5 knowledge index

**Files:**
- Create: `src/cyber_core/memory/knowledge.py`
- Modify: `tests/test_knowledge.py`

**Interfaces:**
- `default_knowledge_path() -> Path`: use `LOCALAPPDATA/CyberCore/knowledge.sqlite3` on Windows; otherwise `XDG_DATA_HOME/cyber-core/knowledge.sqlite3` or `~/.local/share/cyber-core/knowledge.sqlite3`.
- `KnowledgeBase(database: str | Path)`: opens a separate database and ensures schema version 1.
- `KnowledgeBase.index_builtin_guides() -> int`: transactionally replaces the indexed packaged catalog and returns indexed document count.
- `KnowledgeBase.search(query: str, limit: int = 5) -> list[dict]`: returns `id`, `title`, `topic`, `snippet`, `sources`, and `version`; accepts 1–10 results and 1–256 query characters.
- `KnowledgeBase.close() -> None`.

- [ ] **Step 1: Write failing tests** named `test_index_is_idempotent`, `test_search_returns_ranked_source_snippets`, `test_search_no_match_is_empty`, `test_query_fts_operators_are_literal`, `test_invalid_query_and_limit_fail_clearly`, `test_rebuild_removes_stale_catalog_rows`, and `test_missing_fts5_reports_clear_error`.
- [ ] **Step 2: Run focused tests in Actions** with `python scripts/run-tests.py test*.py TestKnowledgeIndex`; record the expected RED result.
- [ ] **Step 3: Implement FTS5 storage** using parameterized SQL and quoted/tokenized query terms; detect FTS5 support at database creation; perform complete index replacement in one transaction; use `importlib.resources` for installed guides.
- [ ] **Step 4: Run focused index tests** on the GitHub Linux and Windows runners and verify every asserted behavior.

### Task 3: Knowledge CLI without Core side effects

**Files:**
- Create: `src/cyber_core/cli/knowledge.py`
- Modify: `src/cyber_core/cli/__init__.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- Add `cyber knowledge index [--db PATH]`.
- Add `cyber knowledge search QUERY [--db PATH] [--limit N]`.
- `cyber_core.cli.knowledge.execute(args) -> dict` returns JSON-ready indexed-count or result-list.
- Dispatch knowledge commands before constructing `Core(args.home, ...)`.

- [ ] **Step 1: Write failing subprocess CLI tests** named `test_knowledge_index_and_search_cli`, `test_knowledge_cli_does_not_create_operational_database`, and `test_knowledge_cli_invalid_limit_is_clear`.
- [ ] **Step 2: Run focused CLI tests in Actions** with `python scripts/run-tests.py test*.py TestKnowledgeCLI`; expect missing subcommand/dispatch failures.
- [ ] **Step 3: Implement nested argparse commands and isolated dispatch**; require `--db` to use a temporary path in tests; output JSON only, and print safe errors without traceback.
- [ ] **Step 4: Run CLI-focused tests** in GitHub Actions and verify operational `--home` has no `core.sqlite3`.

### Task 4: User documentation and cross-platform regression

**Files:**
- Create: `docs/secure-coding-memory.md`
- Modify: `README.md`
- Test: `tests/test_knowledge.py`, `tests/test_cli.py`

- [ ] **Step 1: Document** offline setup, commands, default paths for Linux/Windows, rebuilding, source provenance, limitations, and that Qwen3/Ollama integration is deferred.
- [ ] **Step 2: Add retrieval smoke coverage** mapping synthetic natural-language queries to expected topics across all nine guides; assert returned snippets carry the corresponding source URL.
- [ ] **Step 3: Run the full existing CI workflow** on Linux and Windows with Python 3.12; require full suite and package build to pass with no new skips/failures.
- [ ] **Step 4: Review PR diff and checks**; leave integration in the branch if any required check is failing.
- [ ] **Step 5: Merge into `main` only after all required checks are green**, per the owner's explicit request.

