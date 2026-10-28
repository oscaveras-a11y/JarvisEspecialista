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
            result=audit('http://127.0.0.1:%d'%server.server_port)
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
