import os
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

    def test_similar_domain_is_not_misclassified(self):
        # Regression: a bare-suffix check (host.endswith('ietf.org')) would wrongly
        # label an unrelated host official just for sharing a text suffix.
        self.assertEqual(classify_source('https://unrelated-ietf.org/x')['category'], 'unknown')
        self.assertEqual(classify_source('https://notietf.org/x')['category'], 'unknown')

    def test_real_subdomain_still_matches(self):
        # A genuine subdomain of a full-domain marker must still match.
        self.assertEqual(classify_source('https://www.ietf.org/x')['category'], 'official')
        self.assertEqual(classify_source('https://docs.nist.gov/x')['category'], 'official')


class FetchChildUnitTests(unittest.TestCase):
    """Pure validation of fetch_child.fetch()'s own argument/URL checks — no
    network involved, so these always run."""

    def test_rejects_non_https_url(self):
        from cyber_core.research.fetch_child import fetch
        with self.assertRaises(ValueError):
            fetch('http://example.test/x', max_bytes=1024, timeout=10)
        with self.assertRaises(ValueError):
            fetch('ftp://example.test/x', max_bytes=1024, timeout=10)

    def test_rejects_invalid_byte_limit_and_timeout(self):
        from cyber_core.research.fetch_child import fetch
        with self.assertRaises(ValueError):
            fetch('https://example.test/x', max_bytes=0, timeout=10)
        with self.assertRaises(ValueError):
            fetch('https://example.test/x', max_bytes=1024, timeout=0)
        with self.assertRaises(ValueError):
            fetch('https://example.test/x', max_bytes=1024, timeout=1000)


@unittest.skipUnless(os.environ.get('CYBER_REQUIRE_RESEARCH_FETCH_NETWORK') == '1',
                     'Requires outbound network to fetch a real URL; opt-in separately '
                     '(narrower than pip-audit/npm-audit: owner approved this only for an '
                     'explicit URL the caller names, never a search)')
class RealFetchSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        scope = root / 'inputs'
        scope.mkdir()
        self.core = Core(root / 'state', timeout=60)
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Pesquisa técnica real', str(scope), 'owner', 'auth')

    def test_fetch_source_records_a_real_url_with_hash_and_classification(self):
        from cyber_core.research.fetch import fetch_source
        result = fetch_source(self.core, self.case, 'https://pypi.org/pypi/requests/json',
                              provenance='documented', author='owner')
        fetch = result['fetch']
        self.assertEqual(fetch['status'], 200)
        self.assertEqual(len(fetch['sha256']), 64)
        self.assertGreater(fetch['bytes'], 0)
        self.assertEqual(result['classification']['host'], 'pypi.org')
        listed = self.core.sources(self.case)
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]['url'], 'https://pypi.org/pypi/requests/json')
        self.assertTrue(self.core.verify_audit(self.case))

    def test_non_https_url_is_rejected_before_any_fetch(self):
        from cyber_core.research.fetch import fetch_source
        with self.assertRaises(CoreError):
            fetch_source(self.core, self.case, 'http://pypi.org/pypi/requests/json',
                         provenance='documented', author='owner')

    def test_byte_limit_is_enforced_on_a_real_response(self):
        from cyber_core.research.fetch import fetch_source
        with self.assertRaises(CoreError):
            fetch_source(self.core, self.case, 'https://pypi.org/pypi/requests/json',
                         provenance='documented', author='owner', max_bytes=256)


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
