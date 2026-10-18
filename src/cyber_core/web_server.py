"""Personal beta HTTP bridge. Same-origin UI, bounded uploads, existing CORE only.

Run remotely in a private GitHub Codespace. No provider credentials, shell
commands, client filesystem paths, or analyzed-program execution are accepted.
"""
import argparse
import base64
import binascii
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import re
import secrets
import signal
import threading
from urllib.parse import urlsplit
from uuid import uuid4

from cyber_core.errors import CoreError
from cyber_core.permissions import storage_root
from cyber_core.service import Core

MAX_FILE = 4 * 1024 * 1024
MAX_BODY = 6 * 1024 * 1024
TOOLS = {"analyze-file", "analyze-firmware", "assess-recovery", "inventory-disk", "inventory-pcap", "recover-password"}
MAX_CANDIDATES_WEB = 5000
ASSETS = {"index.html", "app.js", "engine.js", "styles.css",
          "assets/icons.svg", "assets/core-shield.svg"}
CASE_ROUTE = re.compile(r"/api/cases/([a-f0-9]{32})/(files|pause|resume|cancel|report|run)")


class HTTPFault(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def text(data, key, maximum=1000):
    value = data.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise HTTPFault(400, "Preencha corretamente: " + key)
    return value.strip()


def only(data, fields):
    if set(data) - set(fields):
        raise HTTPFault(400, "Campos não permitidos na operação")


class Application:
    def __init__(self, home, web_root):
        self.home = storage_root(home)
        self.uploads = storage_root(self.home / "uploads").resolve()
        self.web_root = Path(web_root).resolve(strict=True)
        if not (self.web_root / "index.html").is_file():
            raise ValueError("Web assets are missing")
        self.token = secrets.token_urlsafe(32)
        self.job_lock = threading.Lock()
        self.worker = None
        self.last_error = None
        self.last_recovery = None
        self.external = {}
        ghidra, java, binwalk = (os.environ.get(k) for k in
                                ("CYBER_GHIDRA_HOME", "JAVA_HOME", "CYBER_BINWALK"))
        if ghidra and java:
            self.external["ghidra"] = {"home": ghidra, "java_home": java}
        if binwalk:
            self.external["binwalk"] = {"executable": binwalk}
        with self.core() as core:
            from cyber_core.operations import ensure
            ensure(core)

    @contextmanager
    def core(self):
        core = Core(self.home / "core", max_bytes=MAX_FILE, timeout=180)
        try:
            core.configure_external_tools(self.external)
            yield core
        finally:
            core.close()

    def capabilities(self):
        ghidra = self.external.get("ghidra", {})
        binwalk = self.external.get("binwalk", {})
        return {
            "ghidra": bool(ghidra and (Path(ghidra["home"]) / "support" / "analyzeHeadless").is_file()),
            "binwalk": bool(binwalk and Path(binwalk["executable"]).is_file()),
            "max_file_bytes": MAX_FILE, "providers": False,
        }

    def snapshot(self):
        from cyber_core.operations import saved_operations
        cases, tasks, events, results, operations, valid, reports = [], [], [], {}, {}, {}, []
        result_errors = {}
        with self.core() as core:
            for row in core.db.execute("SELECT id FROM investigations ORDER BY created DESC,id LIMIT 100").fetchall():
                case = core.get(row["id"])
                case.update(allowRecovery=bool(case["recovery_allowed"]), authorization=case["reason"])
                identifier = case["id"]
                valid[identifier] = core.verify_audit(identifier)
                cases.append(case)
                tasks.extend(core.tasks(identifier))
                events.extend(core.audit(identifier))
                try:
                    results[identifier] = self.verified_results(core, identifier)
                    operations[identifier] = saved_operations(core, identifier)
                except CoreError:
                    results[identifier], operations[identifier] = [], []
                    result_errors[identifier] = "Integridade do resultado ou da cópia não confirmada. Não use estes dados como verificados."
                report_folder = core.home / "cases" / identifier / "reports"
                if report_folder.is_dir():
                    reports.extend({"case_id": identifier} for file in report_folder.glob("*.md") if file.is_file())
        return dict(cases=cases, tasks=tasks, audit=events, results=results,
                    operations=operations, audit_valid=valid, reports=reports,
                    activeCase=None, busy=self.job_lock.locked(), last_error=self.last_error, result_errors=result_errors,
                    recovery_result=self.last_recovery)

    def verified_results(self, core, identifier):
        from cyber_core.verification.artifacts import verified_result
        if not core.verify_audit(identifier):
            raise CoreError("Audit integrity failed")
        rows = core.db.execute("SELECT task_id FROM results WHERE case_id=? ORDER BY created", (identifier,)).fetchall()
        return [verified_result(core, identifier, row["task_id"])[0] for row in rows]

    def require_case(self, core, identifier, *, active=False):
        try:
            case = core.get(identifier)
        except CoreError:
            raise HTTPFault(404, "Investigação não encontrada") from None
        if active:
            core.authorize(identifier)
            if case["paused"]:
                raise HTTPFault(409, "A investigação está pausada")
        return case

    def create_case(self, data):
        only(data, {"project", "objective", "owner", "authorization", "validHours", "allowRecovery"})
        fields = [text(data, key) for key in ("project", "objective", "owner", "authorization")]
        hours = data.get("validHours", 24)
        recovery = data.get("allowRecovery", False)
        if type(hours) not in (int, float) or not 1 <= hours <= 8760 or type(recovery) is not bool:
            raise HTTPFault(400, "Validade ou permissão inválida")
        with self.core() as core:
            if core.db.execute("SELECT COUNT(*) FROM investigations").fetchone()[0] >= 100:
                raise HTTPFault(409, "Limite de 100 investigações deste beta atingido")
            scope = storage_root(self.uploads / uuid4().hex)
            identifier = core.investigate(fields[0], fields[1], str(scope), fields[2], fields[3],
                                          valid_hours=hours, recovery=recovery)
            if recovery:
                # Checking "Permitir operações de recuperação" in this single-operator
                # beta IS the owner's consent declaration; record it in the same
                # authorization_basis shape recover_password()/self_test_recovery()
                # already require, instead of asking for it again in a second form.
                core.set_authorization_basis(identifier, kind="owner_consent", authority=fields[2],
                                             reference=fields[3], examiner=fields[2], scope_note=fields[0])
        return {"id": identifier}

    def submit_file(self, identifier, data):
        only(data, {"name", "tool", "content_base64", "candidates"})
        name, tool = text(data, "name", 160), text(data, "tool", 64)
        if not re.fullmatch(r"[\w .()-]{1,160}", name) or name in {".", ".."} or ".." in name:
            raise HTTPFault(400, "Nome de arquivo inválido")
        if tool not in TOOLS:
            raise HTTPFault(400, "Análise não permitida")
        candidates = None
        if tool == "recover-password":
            raw_candidates = data.get("candidates")
            if not isinstance(raw_candidates, list) or not 1 <= len(raw_candidates) <= MAX_CANDIDATES_WEB:
                raise HTTPFault(400, "Forneça de 1 a " + str(MAX_CANDIDATES_WEB) + " senhas candidatas")
            candidates = []
            for item in raw_candidates:
                if not isinstance(item, str) or not item or len(item) > 1024:
                    raise HTTPFault(400, "Senha candidata inválida")
                candidates.append(item)
        encoded = data.get("content_base64")
        if not isinstance(encoded, str):
            raise HTTPFault(400, "Conteúdo do arquivo ausente")
        if len(encoded) > ((MAX_FILE + 2) // 3) * 4:
            raise HTTPFault(413, "O limite por arquivo é 4 MiB")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise HTTPFault(400, "Conteúdo do arquivo inválido") from None
        if len(raw) > MAX_FILE:
            raise HTTPFault(413, "O limite por arquivo é 4 MiB")
        if not self.job_lock.acquire(blocking=False):
            raise HTTPFault(409, "Aguarde a análise atual terminar")
        source = None
        try:
            with self.core() as core:
                case = self.require_case(core, identifier, active=True)
                if tool in ("assess-recovery", "recover-password"):
                    core.authorize(identifier, recovery=True)
                scope = Path(case["scope"])
                if not scope.is_relative_to(self.uploads):
                    raise HTTPFault(409, "Escopo não gerido por este painel")
                source = scope / (uuid4().hex + "-" + name)
                with source.open("xb") as handle:
                    handle.write(raw)
                task = None
                if tool not in {"inventory-disk", "inventory-pcap", "recover-password"}:
                    task = core.enqueue(identifier, source, tool=tool)
            self.last_error = None
            if tool == "recover-password":
                self.last_recovery = None
            self.worker = threading.Thread(target=self.execute, args=(identifier, tool, source, task, candidates), daemon=True)
            self.worker.start()
            return {"accepted": True, "task": task}
        except BaseException:
            if source:
                source.unlink(missing_ok=True)
            self.job_lock.release()
            raise

    def execute(self, identifier, tool, source=None, task=None, candidates=None):
        try:
            with self.core() as core:
                if tool == "inventory-disk":
                    from cyber_core.operations import inventory_disk
                    inventory_disk(core, identifier, source, max_bytes=MAX_FILE)
                elif tool == "inventory-pcap":
                    from cyber_core.operations import inventory_pcap
                    inventory_pcap(core, identifier, source, max_bytes=MAX_FILE)
                elif tool == "recover-password":
                    result = core.recover_password(identifier, source, candidates, max_attempts=100000, max_seconds=180)
                    self.last_recovery = dict(result)
                elif tool == "pending":
                    core.run_queue(identifier, max_tasks=20, max_seconds=300)
                else:
                    core.run_one(identifier, task_id=task)
        except Exception as exc:
            self.last_error = str(exc) if isinstance(exc, CoreError) else "A análise não pôde ser concluída"
        finally:
            self.job_lock.release()

    def operation(self, identifier, action, data):
        if action == "files":
            return 202, self.submit_file(identifier, data)
        only(data, {"reason"} if action == "cancel" else set())
        with self.core() as core:
            case = self.require_case(core, identifier)
            if action == "report":
                self.verified_results(core, identifier)
                report = core.report(identifier).read_text(encoding="utf-8")
                return 200, {"text": report, "filename": "relatorio-core-" + identifier[:8] + ".md"}
            if case["state"] == "CANCELADO":
                raise HTTPFault(409, "Investigação cancelada; crie uma nova para continuar")
            if action == "cancel":
                core.cancel(identifier, reason=text(data, "reason", 1024))
            elif action in {"pause", "resume"}:
                getattr(core, action)(identifier)
            elif action == "run":
                self.require_case(core, identifier, active=True)
                if not self.job_lock.acquire(blocking=False):
                    raise HTTPFault(409, "Aguarde a análise atual terminar")
                self.last_error = None
                self.worker = threading.Thread(target=self.execute, args=(identifier, "pending"), daemon=True)
                self.worker.start()
                return 202, {"accepted": True}
        return 200, {"id": identifier, "operation": action}


class BetaServer(ThreadingHTTPServer):
    daemon_threads = True
    def server_close(self):
        super().server_close()
        worker = self.app.worker
        if worker and worker.is_alive():
            worker.join(timeout=310)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        # Do not place uploaded names, case metadata or evidence in console logs.
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def send(self, status, body, mime="application/json; charset=utf-8"):
        raw = json.dumps(body, ensure_ascii=False).encode() if mime.startswith("application/json") else body
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self'; connect-src 'self'; "
                         "img-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none'; "
                         "base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(raw)

    def check_request(self, *, mutation=False):
        host = self.headers.get("Host", "").lower()
        if host not in self.server.allowed_hosts:
            raise HTTPFault(403, "Host não permitido")
        origin = self.headers.get("Origin")
        if origin:
            parsed = urlsplit(origin)
            if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() not in self.server.allowed_hosts:
                raise HTTPFault(403, "Origem não permitida")
        if mutation or urlsplit(self.path).path == "/api/state":
            token = self.headers.get("X-Cyber-Request", "")
            if not secrets.compare_digest(token, self.server.app.token):
                raise HTTPFault(403, "Reabra o painel para restabelecer a sessão de requisições")

    def dispatch(self, mutation=False):
        try:
            self.check_request(mutation=mutation)
            app, path = self.server.app, urlsplit(self.path).path
            if not mutation:
                if path == "/api/health":
                    return self.send(200, {"service": "cyber-core", "version": 1, "token": app.token,
                                           "capabilities": app.capabilities()})
                if path == "/api/state":
                    return self.send(200, app.snapshot())
                asset = path.removeprefix("/web/") if path.startswith("/web/") else path.lstrip("/")
                if asset in {"", "web/"}:
                    asset = "index.html"
                if asset not in ASSETS:
                    raise HTTPFault(404, "Página não encontrada")
                file = app.web_root / asset
                if not file.is_file() or file.is_symlink():
                    raise HTTPFault(404, "Página não encontrada")
                mime = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
                content = file.read_bytes()
                if asset == "index.html":
                    content = content.replace(b"</head>", b'<meta name="cyber-engine" content="required"></head>')
                return self.send(200, content, mime + ("; charset=utf-8" if mime.startswith("text/") else ""))
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                raise HTTPFault(415, "Use conteúdo JSON")
            if self.headers.get("Transfer-Encoding"):
                raise HTTPFault(400, "Codificação de transferência não permitida")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise HTTPFault(400, "Tamanho inválido") from None
            if not 0 < length <= MAX_BODY:
                raise HTTPFault(413, "Requisição excede o limite")
            try:
                raw = self.rfile.read(length)
                data = json.loads(raw)
                if len(raw) != length or not isinstance(data, dict):
                    raise ValueError()
            except (ValueError, UnicodeError):
                raise HTTPFault(400, "JSON inválido") from None
            if path == "/api/cases":
                return self.send(201, app.create_case(data))
            match = CASE_ROUTE.fullmatch(path)
            if not match:
                raise HTTPFault(404, "Operação não encontrada")
            status, result = app.operation(match[1], match[2], data)
            self.send(status, result)
        except HTTPFault as exc:
            self.send(exc.status, {"error": exc.message})
        except CoreError as exc:
            self.send(409, {"error": str(exc)})
        except (OSError, ValueError):
            self.send(400, {"error": "Recurso inacessível ou entrada inválida"})
        except Exception:
            self.send(500, {"error": "O motor não pôde concluir a requisição"})

    def do_GET(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch(mutation=True)


def create_server(home, web_root, *, port=8765):
    app = Application(home, web_root)
    server = BetaServer(("127.0.0.1", port), Handler)
    server.app = app
    server.allowed_hosts = {"127.0.0.1:" + str(server.server_port), "localhost:" + str(server.server_port)}
    name, domain = os.environ.get("CODESPACE_NAME"), os.environ.get("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN", "app.github.dev")
    if name and re.fullmatch(r"[a-zA-Z0-9-]+", name) and re.fullmatch(r"[a-zA-Z0-9.-]+", domain):
        server.allowed_hosts.add((name + "-" + str(server.server_port) + "." + domain).lower())
    return server


def main():
    parser = argparse.ArgumentParser(description="CYBER CORE private remote beta panel")
    parser.add_argument("--home", type=Path, default=Path.home() / ".cyber-core-beta")
    parser.add_argument("--web-root", type=Path, default=Path.cwd() / "web")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--test-mode", action="store_true", help="Only for synthetic GitHub Actions tests")
    args = parser.parse_args()
    if not ((os.environ.get("CODESPACES") == "true") or
            (args.test_mode and os.environ.get("GITHUB_ACTIONS") == "true")):
        parser.error("Execute no GitHub Codespaces ou nos testes sintéticos do GitHub Actions")
    server = create_server(args.home, args.web_root, port=args.port)
    def terminate(*_):
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, terminate)
    print("CYBER CORE: http://127.0.0.1:" + str(server.server_port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
