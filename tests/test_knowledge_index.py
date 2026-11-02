import contextlib
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cyber_core.memory.knowledge import build_index, search_index


class TestKnowledgeIndex(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "reference.sqlite3"

    def tearDown(self):
        self.temp.cleanup()

    def test_build_and_search_local_reference(self):
        result = build_index(self.database)
        self.assertEqual(result["indexed"], 18)
        found = search_index("autorização por objeto", self.database, limit=3)
        self.assertGreaterEqual(found["count"], 1)
        self.assertIn("authorization", {item["topic"] for item in found["results"]})
        self.assertTrue(all(item["snippet"] and item["version"] == "2026-11" for item in found["results"]))

    def test_rebuild_replaces_rows_without_duplicates(self):
        build_index(self.database)
        build_index(self.database)
        db = sqlite3.connect(self.database)
        try:
            count = db.execute("SELECT count(*) FROM guide_search").fetchone()[0]
        finally:
            db.close()
        self.assertEqual(count, 18)

    def test_query_and_limit_are_bounded(self):
        build_index(self.database)
        for query, limit in (("", 5), ("x" * 257, 5), ("sql", 0), ("sql", 11)):
            with self.subTest(query_length=len(query), limit=limit):
                with self.assertRaises(ValueError):
                    search_index(query, self.database, limit=limit)

    def test_search_query_is_parameterized_and_handles_fts_syntax(self):
        build_index(self.database)
        result = search_index('" OR * : { }', self.database)
        self.assertEqual(result["count"], 0)


    def test_each_topic_is_retrievable(self):
        build_index(self.database)
        queries = {
            "secure-review": "revisão segura fluxo código",
            "python": "Python subprocessos desserialização",
            "javascript-typescript": "TypeScript runtime JSON",
            "input-validation": "normalização canônica entradas",
            "sql-injection": "SQL parâmetros consulta",
            "command-injection": "shell argumentos separados",
            "xss": "XSS contexto saída",
            "authentication": "autenticação armazenamento senhas",
            "authorization": "autorização objeto servidor",
            "secrets": "segredos configuração revogação",
            "dependencies": "dependências lockfile SBOM",
            "exposed-services": "OpenAPI métodos TLS",
            "uploads": "upload quarentena nomes",
            "path-traversal": "caminho links contenção",
            "deserialization": "desserializar polimorfismo schema",
            "logging": "logs segredos telemetria",
            "cryptography": "criptografia AEAD nonce",
            "secure-testing": "fixture sintética regressões",
        }
        for topic, query in queries.items():
            with self.subTest(topic=topic):
                found = search_index(query, self.database, limit=10)
                self.assertIn(topic, {item["topic"] for item in found["results"]})

    def test_missing_fts5_has_clear_error(self):
        from cyber_core.memory.knowledge import _connect
        fake_db = mock.Mock()
        fake_db.execute.side_effect = sqlite3.OperationalError("no such module: fts5")
        with mock.patch("cyber_core.memory.knowledge.sqlite3.connect", return_value=fake_db):
            with self.assertRaisesRegex(ValueError, "FTS5 support is unavailable"):
                _connect(self.database)
        fake_db.close.assert_called_once()

    def test_missing_index_has_actionable_message(self):
        with self.assertRaisesRegex(FileNotFoundError, "cyber knowledge index"):
            search_index("python", self.database)

    def test_knowledge_cli_does_not_open_operational_core(self):
        from cyber_core.cli import main
        output = io.StringIO()
        with mock.patch("cyber_core.cli.Core") as core, contextlib.redirect_stdout(output):
            code = main(["knowledge", "index", "--db", str(self.database)])
        self.assertEqual(code, 0)
        self.assertEqual(core.call_count, 0)
        self.assertIn('"indexed": 18', output.getvalue())


if __name__ == "__main__":
    unittest.main()
