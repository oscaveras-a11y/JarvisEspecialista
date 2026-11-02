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
        self.assertTrue(all(item["excerpt"] for item in found["results"]))

    def test_rebuild_replaces_rows_without_duplicates(self):
        build_index(self.database)
        build_index(self.database)
        with sqlite3.connect(self.database) as db:
            count = db.execute("SELECT count(*) FROM guide_search").fetchone()[0]
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
