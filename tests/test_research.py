import tempfile
import unittest
from pathlib import Path

from cyber_core.service import Core, CoreError
from cyber_core.research import classify_source


class ResearchUnitTests(unittest.TestCase):
    def test_categories(self):
        self.assertEqual(classify_source('https://nist.gov/x')['category'], 'official')
        self.assertEqual(classify_source('https://arxiv.org/abs/1')['category'], 'academic')
        self.assertEqual(classify_source('https://mit.edu/p')['category'], 'academic')
        self.assertEqual(classify_source('https://github.com/a/b')['category'], 'community')
        self.assertEqual(classify_source('https://example.test/p')['category'], 'unknown')

    def test_rejects_non_http(self):
        with self.assertRaises(CoreError):
            classify_source('ftp://x/y')
        with self.assertRaises(CoreError):
            classify_source('')


class ResearchServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        scope = root / 'inputs'
        scope.mkdir()
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Pesquisa técnica', str(scope), 'owner', 'auth')

    def test_sources_listed_with_authority(self):
        from cyber_core.investigation.workflow import Workflow
        Workflow(self.core).add_source(self.case, title='Spec', url='https://ietf.org/rfc', version='1',
                                       provenance='documented', author='op')
        listed = self.core.sources(self.case)
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]['authority'], 'official')


if __name__ == '__main__':
    unittest.main()
