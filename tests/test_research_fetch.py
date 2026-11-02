import io
import tempfile
import unittest
import urllib.error
from pathlib import Path

from cyber_core.errors import CoreError
from cyber_core.service import Core
from cyber_core.research.fetch import fetch_reference


class FakeResponse:
    def __init__(self, body=b'', ctype='text/html; charset=utf-8', status=200):
        self.status = status
        self.headers = {'Content-Type': ctype}
        self._body = body

    def read(self, n=-1):
        return self._body if n < 0 else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def opener_for(response):
    return lambda request, timeout=None: response


PAGE = b'<html><head><title>RFC  Test</title><script>alert(1)</script></head><body><p>Hello &amp; welcome</p></body></html>'


class FetchTests(unittest.TestCase):
    def go(self, url='https://www.ietf.org/rfc', allow=('www.ietf.org',), response=None, **kw):
        return fetch_reference(url, allow_hosts=allow, opener=opener_for(response or FakeResponse(PAGE)), **kw)

    def test_success_records_digest_and_inert_excerpt(self):
        r = self.go()
        self.assertEqual(r['category'], 'official')
        self.assertEqual(r['page_title'], 'RFC Test')
        self.assertIn('Hello & welcome', r['excerpt'])
        self.assertNotIn('alert', r['excerpt'])
        self.assertEqual(len(r['sha256']), 64)

    def test_requires_allow_host_and_match(self):
        with self.assertRaises(CoreError):
            self.go(allow=())
        with self.assertRaises(CoreError):
            self.go(allow=('other.org',))

    def test_rejects_http_credentials_and_bad_limits(self):
        for url in ('http://www.ietf.org/x', 'https://u:p@www.ietf.org/x', ''):
            with self.assertRaises(CoreError):
                self.go(url=url)
        with self.assertRaises(CoreError):
            self.go(max_bytes=0)
        with self.assertRaises(CoreError):
            self.go(timeout=0)

    def test_size_type_status_limits(self):
        with self.assertRaises(CoreError):
            self.go(response=FakeResponse(b'x' * 11), max_bytes=10)
        with self.assertRaises(CoreError):
            self.go(response=FakeResponse(b'MZ', ctype='application/octet-stream'))
        with self.assertRaises(CoreError):
            self.go(response=FakeResponse(b'x', status=204))

    def test_redirect_and_network_errors_are_refused(self):
        def boom(request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, 302, 'Found', {}, io.BytesIO())
        with self.assertRaises(CoreError):
            fetch_reference('https://www.ietf.org/x', allow_hosts=['www.ietf.org'], opener=boom)

    def test_private_resolution_blocked(self):
        for addr in ('127.0.0.1', '10.0.0.5', '169.254.169.254', '::1'):
            with self.assertRaises(CoreError):
                fetch_reference('https://www.ietf.org/x', allow_hosts=['www.ietf.org'], resolver=lambda h, a=addr: [a])


class FetchWorkflowTests(unittest.TestCase):
    def test_retrieval_registers_source_and_audits_digest(self):
        from cyber_core.investigation.workflow import Workflow
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)          # runs last: after the database is closed (Windows file locks)
        root = Path(tmp.name)
        (root / 'in').mkdir()
        core = Core(root / 'state')
        self.addCleanup(core.close)
        case = core.investigate('p', 'Pesquisa', str(root / 'in'), 'owner', 'auth')
        r = fetch_reference('https://www.ietf.org/rfc', allow_hosts=['www.ietf.org'], opener=opener_for(FakeResponse(PAGE)))
        Workflow(core).add_retrieved_source(case, r, title='RFC', version='1', provenance='documented', author='op')
        self.assertEqual(core.sources(case)[0]['authority'], 'official')
        events = [dict(x) for x in core.db.execute("SELECT * FROM audit WHERE case_id=?", (case,))]
        self.assertTrue(any('source_retrieved' in str(e) and r['sha256'] in str(e) for e in events))


if __name__ == '__main__':
    unittest.main()
