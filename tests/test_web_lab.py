import importlib
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

class WebLabTests(unittest.TestCase):
    def test_real_http_unauthorized_write_and_restoration(self):
        try:
            audit=importlib.import_module('cyber_core.web_lab').audit
        except ImportError:
            self.fail('Web laboratory runner missing')
        class Handler(BaseHTTPRequestHandler):
            title='original'
            def log_message(self,*args): pass
            def do_GET(self):
                data=json.dumps({'title':self.title}).encode()
                self.send_response(200);self.end_headers();self.wfile.write(data)
            def do_POST(self):
                type(self).title=json.loads(self.rfile.read(int(self.headers['Content-Length'])))['title']
                self.send_response(204);self.end_headers()
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            import tempfile
            from pathlib import Path
            from cyber_core.service import Core
            module=importlib.import_module('cyber_core.web_lab')
            self.assertTrue(callable(getattr(module,'run_lab',None)),'CORE laboratory operation missing')
            with tempfile.TemporaryDirectory() as folder:
                manifest=Path(folder)/'lab.json'
                manifest.write_text(json.dumps({'origin':'http://127.0.0.1:%d'%server.server_port,'allow_write':True}))
                core=Core(Path(folder)/'store')
                try:
                    case=core.investigate('lab','Synthetic web',folder,'owner','Synthetic laboratory')
                    operation=module.run_lab(core,case,manifest)
                    result=operation['analysis']
                    self.assertTrue(core.verify_audit(case))
                    self.assertIn('web_lab',core.report(case).read_text())
                    core.pause(case)
                    from cyber_core.errors import CoreError
                    with self.assertRaises(CoreError):
                        module.run_lab(core,case,manifest)
                finally:
                    core.close()
            self.assertTrue(result['unauthenticated_write_observed'])
            self.assertTrue(result['restored'])
            self.assertEqual(Handler.title,'original')
        finally:
            server.shutdown();server.server_close();thread.join()

    def test_external_targets_rejected_before_network(self):
        try:
            audit=importlib.import_module('cyber_core.web_lab').audit
        except ImportError:
            self.fail('Web laboratory runner missing')
        for url in ('https://example.com','http://localhost:80','http://127.0.0.1:80/path'):
            with self.subTest(url=url),self.assertRaises(ValueError):
                audit(url)
