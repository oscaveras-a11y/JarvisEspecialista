import json
import re
import unittest
from importlib.resources import files
from urllib.parse import urlparse


EXPECTED_TOPICS = {
    'secure-review', 'python', 'javascript-typescript', 'input-validation',
    'sql-injection', 'command-injection', 'xss', 'authentication',
    'authorization', 'secrets', 'dependencies', 'exposed-services',
    'uploads', 'path-traversal', 'deserialization', 'logging',
    'cryptography', 'secure-testing',
}
REQUIRED_SECTIONS = (
    '## Como revisar',
    '## Evidências',
    '## Correção',
    '## Teste de regressão',
    '## Limites',
    '## Fontes',
)


def load_catalog(test):
    resource = files('cyber_core.memory').joinpath('guides', 'catalog.json')
    test.assertTrue(resource.is_file(), 'catálogo de programação segura ausente')
    return json.loads(resource.read_text(encoding='utf-8'))


class TestKnowledgeGuideCatalog(unittest.TestCase):
    def test_catalog_contains_eighteen_complete_topics(self):
        catalog = load_catalog(self)
        self.assertEqual(len(catalog), 18)
        self.assertEqual({entry['topic'] for entry in catalog}, EXPECTED_TOPICS)

    def test_guide_sections_and_minimum_length(self):
        catalog = load_catalog(self)
        for entry in catalog:
            with self.subTest(topic=entry['topic']):
                guide = files('cyber_core.memory').joinpath('guides', entry['path'])
                self.assertTrue(guide.is_file(), entry['path'])
                text = guide.read_text(encoding='utf-8')
                self.assertGreaterEqual(len(text), 1500, entry['topic'])
                for heading in REQUIRED_SECTIONS:
                    self.assertIn(heading, text, (entry['topic'], heading))

    def test_catalog_paths_and_ids_are_valid(self):
        catalog = load_catalog(self)
        ids = [entry['id'] for entry in catalog]
        paths = [entry['path'] for entry in catalog]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(paths), len(set(paths)))
        for entry in catalog:
            self.assertRegex(entry['id'], r'^[a-z0-9-]{2,48}$')
            self.assertRegex(entry['version'], r'^\d{4}-\d{2}$')
            self.assertNotIn('..', entry['path'].split('/'))
            self.assertTrue(entry['path'].endswith('.md'))

    def test_sources_are_official_https(self):
        catalog = load_catalog(self)
        for entry in catalog:
            with self.subTest(topic=entry['topic']):
                self.assertTrue(entry['sources'])
                for source in entry['sources']:
                    parsed = urlparse(source)
                    self.assertEqual(parsed.scheme, 'https')
                    self.assertIn(parsed.hostname, {
                        'cheatsheetseries.owasp.org',
                        'owasp.org',
                        'cwe.mitre.org',
                        'docs.python.org',
                        'developer.mozilla.org',
                        'nodejs.org',
                        '12factor.net',
                    })


if __name__ == '__main__':
    unittest.main()
