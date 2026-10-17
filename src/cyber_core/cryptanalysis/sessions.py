"""Persistent owner-material recovery, bounded subprocess trials and durable checkpoints."""
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import sys
import stat
import time
from uuid import uuid4
from cyber_core.agents.runner import run_bounded
from cyber_core.errors import CoreError
from cyber_core.memory import audit, encoded, utc
from cyber_core.permissions import local_path, storage_root
from cyber_core.verification.artifacts import verified_result, result_digest

SCHEMA = """
CREATE TABLE IF NOT EXISTS recovery_session_meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS recovery_sessions(
 id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES investigations(id),
 mode TEXT NOT NULL,task_id TEXT NOT NULL REFERENCES tasks(id),
 material_path TEXT NOT NULL,material_commitment TEXT NOT NULL,plan_digest TEXT NOT NULL,
 total_candidates INTEGER NOT NULL,started REAL NOT NULL,deadline REAL NOT NULL,
 status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,cursor INTEGER NOT NULL DEFAULT 0,
 token TEXT,lease_until REAL NOT NULL DEFAULT 0,result TEXT,created TEXT NOT NULL);
"""
TERMINAL = {"succeeded", "exhausted", "cancelled", "resource_limited"}

def _number(value, low, high):
    return type(value) in (float, int) and math.isfinite(value) and low <= value <= high

def _cleanup_claim(core, row):
    token, job = row.get("token"), row["id"]
    if not token:
        return
    if any(len(v) != 32 or any(c not in "0123456789abcdef" for c in v) for v in (job,token)):
        raise CoreError("Invalid recovery cleanup identity")
    root = storage_root(core.home/"recovery-staging")
    folder = root/(job+"-"+token)
    # A private per-claim directory is also a tombstone: removing it prevents a
    # surviving child from creating a plaintext file after its parent is gone.
    if folder.exists():
        local_path(folder,directory=True)
        pending = folder/"result.pending"
        if pending.exists():
            local_path(pending).unlink()
        folder.rmdir()
    # The flat path is retained for cleanup of pre-release sessions.
    legacy = root/(job+"-"+token+".pending")
    if legacy.exists():
        local_path(legacy).unlink()
    output = storage_root(core.home/"cases"/row["case_id"]/"recovered")/(job+"-"+token+".recovered")
    if output.exists():
        local_path(output).unlink()

def stop_case_sessions(core, case, *, state="cancelled"):
    """Called under the same writer lock as case pause/revoke/cancellation."""
    if not core.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='recovery_sessions'").fetchone():
        return
    if not core.db.in_transaction or state not in ("paused","cancelled"):
        raise CoreError("Recovery stop requires the case writer lock")
    rows = core.db.execute("SELECT * FROM recovery_sessions WHERE case_id=? AND status NOT IN ('succeeded','exhausted')",(case,)).fetchall()
    for record in rows:
        row = dict(record)
        deferred = False
        try:
            _cleanup_claim(core,row)
        except (OSError,CoreError):
            deferred = True
        token = row["token"] if deferred else None
        core.db.execute("UPDATE recovery_sessions SET status=?,token=?,lease_until=0 WHERE id=?",(state,token,row["id"]))
        event = "recovery_session_paused" if state == "paused" else "recovery_session_cancelled"
        payload = {"session":row["id"],"cleanup_deferred":deferred}
        core.db.execute("INSERT INTO checkpoints(case_id,event,data,created) VALUES(?,?,?,?)",(case,event,encoded(payload),utc()))
        audit(core.db,case,event,payload)

class RecoverySessions:
    def __init__(self, core):
        self.core, self.db = core, core.db
        if self.db.in_transaction:
            raise CoreError("Initialize recovery sessions outside a transaction")
        self.db.executescript(SCHEMA)
        row = self.db.execute("SELECT version FROM recovery_session_meta WHERE id=1").fetchone()
        if row and row[0] != 1:
            raise CoreError("Unsupported recovery session version")
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO recovery_session_meta VALUES(1,1)")
        self.folder = storage_root(core.home / "recovery-material")

    def _ready(self, case):
        row = self.core.authorize(case, recovery=True)
        if row["paused"]:
            raise CoreError("Investigation is paused")
        return row

    def _row(self, case, job):
        row = self.db.execute("SELECT * FROM recovery_sessions WHERE case_id=? AND id=?", (case, job)).fetchone()
        if row is None:
            raise CoreError("Unknown recovery session in this investigation")
        return dict(row)

    def _public(self, row):
        result = {k: row[k] for k in ("id","case_id","mode","status","attempts","total_candidates","deadline","created")}
        result["result"] = json.loads(row["result"]) if row["result"] else None
        return result

    def get(self, case, job):
        self.core.get(case)
        row = self._row(case, job)
        self._validate(row)
        return self._public(row)

    def jobs(self, case):
        self.core.get(case)
        return [self.get(case,row["id"]) for row in self.db.execute(
            "SELECT id FROM recovery_sessions WHERE case_id=? ORDER BY rowid", (case,))]

    def _event(self, case, event, data):
        self.db.execute("INSERT INTO checkpoints(case_id,event,data,created) VALUES(?,?,?,?)",
                        (case, event, encoded(data), utc()))
        audit(self.db, case, event, data)

    def _progress(self, row):
        self._event(row["case_id"], "recovery_session_progress",
                    {"session": row["id"], "attempts": row["attempts"], "cursor": row["cursor"],
                     "result_digest": result_digest(json.loads(row["result"])) if row["result"] else None,
                     "status": row["status"]})

    def _plan(self, row):
        return result_digest({k: row[k] for k in
                             ("id","case_id","mode","task_id","material_path","material_commitment","total_candidates","started")})

    def _validate(self, row):
        case, job = row["case_id"], row["id"]
        if not self.core.verify_audit(case) or self._plan(row) != row["plan_digest"]:
            raise CoreError("Recovery plan or audit integrity failed")
        anchor, progress, deadline, state = None, None, None, None
        for item in self.db.execute("SELECT event,data FROM audit WHERE case_id=? AND event LIKE 'recovery_session_%' ORDER BY id", (case,)):
            data = json.loads(item["data"])
            if data.get("session") != job:
                continue
            if item["event"] == "recovery_session_created":
                anchor, deadline, state = data.get("plan_digest"), data.get("deadline"), "pending"
            elif item["event"] == "recovery_session_extended":
                deadline = data["deadline"]
                state = data["status"]
            elif item["event"] == "recovery_session_progress":
                progress = {k:v for k,v in data.items() if k != "status"}
                state = data["status"]
            elif item["event"] in ("recovery_session_paused","recovery_session_resumed","recovery_session_cancelled"):
                state = {"recovery_session_paused":"paused","recovery_session_resumed":"pending","recovery_session_cancelled":"cancelled"}[item["event"]]
            elif item["event"] == "recovery_session_checkpoint":
                state = data["status"]
        expected = {"session":job, "attempts":row["attempts"],"cursor":row["cursor"],
                    "result_digest": result_digest(json.loads(row["result"])) if row["result"] else None}
        if anchor != row["plan_digest"] or deadline != row["deadline"] or progress != expected:
            raise CoreError("Recovery checkpoint differs from audited plan")
        if row["status"] != state and not (row["status"] == "running" and state in ("pending","running")):
            raise CoreError("Recovery status differs from audited state")
        if (row["status"] == "succeeded") != (row["result"] is not None):
            raise CoreError("Recovery result and status are inconsistent")
        if row["status"] == "exhausted" and row["cursor"] != row["total_candidates"]:
            raise CoreError("Recovery exhaustion differs from checkpoint")

    def _material(self, case, path, secret, maximum=100000):
        source = self.core.authorize(case, path, recovery=True)
        if source.is_relative_to(self.core.home) or self.core.home.is_relative_to(source.parent):
            raise CoreError("Recovery material must not overlap operational storage")
        with source.open("rb") as handle:
            raw = handle.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise CoreError("Candidate material byte limit exceeded")
        values = raw.splitlines()
        if not values or len(values) > maximum or any(not 1 <= len(v) <= 1024 for v in values):
            raise CoreError("Candidate count or line limit exceeded")
        return values, hmac.new(secret, raw, hashlib.sha256).hexdigest()

    def _secret(self, job):
        path = local_path(self.folder / (job + ".key"))
        with path.open("rb") as handle:
            secret = handle.read(33)
        if len(secret) != 32:
            raise CoreError("Recovery material commitment is inaccessible")
        return secret

    def start(self, case, source, material, *, mode="ccaes1", hours=24, max_candidates=100000):
        self._ready(case)
        if mode not in ("ccaes1","ssh-private") or not _number(hours, 1/3600, 24):
            raise CoreError("Invalid recovery mode or initial time window")
        if type(max_candidates) is not int or not 1 <= max_candidates <= 100000:
            raise CoreError("Invalid recovery candidate limit")
        target = self.core.authorize(case, source, recovery=True)
        material_path = self.core.authorize(case, material, recovery=True)
        if target == material_path:
            raise CoreError("Target and candidate material must differ")
        with target.open("rb") as handle:
            header = handle.read(64)
        if (target.stat().st_size > min(self.core.max_bytes, 8*1024*1024) or
            (mode == "ccaes1" and not header.startswith(b"CCAES1")) or
            (mode == "ssh-private" and not header.startswith((b"-----BEGIN OPENSSH PRIVATE KEY-----",
                 b"-----BEGIN ENCRYPTED PRIVATE KEY-----",b"-----BEGIN RSA PRIVATE KEY-----",
                 b"-----BEGIN EC PRIVATE KEY-----",b"-----BEGIN PRIVATE KEY-----")))):
            raise CoreError("Unsupported or oversized recovery input")
        job, secret = uuid4().hex, os.urandom(32)
        values, commitment = self._material(case, material_path, secret, max_candidates)
        if mode == "ccaes1":
            try:
                if any(len(v) != 64 or len(bytes.fromhex(v.decode("ascii"))) != 32 for v in values):
                    raise ValueError()
            except (ValueError, UnicodeError):
                raise CoreError("CCAES1 candidates must be 64 hexadecimal characters per line") from None
        task = self.core.enqueue(case, target, tool="analyze-file")
        self.core.run_one(case, task_id=task)
        secret_path = self.folder / (job + ".key")
        try:
            fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(secret)
                handle.flush()
                os.fsync(handle.fileno())
            started = time.time()
            row = {"id":job,"case_id":case,"mode":mode,"task_id":task,"material_path":str(material_path),
                   "material_commitment":commitment,"total_candidates":len(values),"started":started,
                   "deadline":started+hours*3600,"status":"pending","attempts":0,"cursor":0,"result":None}
            row["plan_digest"] = self._plan(row)
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                self._ready(case)
                self.db.execute("""INSERT INTO recovery_sessions
                    (id,case_id,mode,task_id,material_path,material_commitment,plan_digest,total_candidates,
                     started,deadline,status,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (job,case,mode,task,str(material_path),commitment,row["plan_digest"],len(values),
                     started,row["deadline"],"pending",utc()))
                self._event(case,"recovery_session_created",{"session":job,"plan_digest":row["plan_digest"],
                            "deadline":row["deadline"],"mode":mode,"candidates":len(values)})
                self._progress(row)
        except BaseException:
            secret_path.unlink(missing_ok=True)
            raise
        return self.get(case,job)

    def _cleanup(self, row):
        _cleanup_claim(self.core,row)

    def _control(self, case, job, action, reason=None):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self.core.get(case) if action == "cancel" else self._ready(case)
            row = self._row(case,job)
            self._validate(row)
            if row["status"] in TERMINAL and not (row["status"] == "resource_limited" and action == "resume"):
                if action == "cancel" and row["status"] == "cancelled":
                    self._cleanup(row)
                    self.db.execute("UPDATE recovery_sessions SET token=NULL,lease_until=0 WHERE id=?", (job,))
                    return self._public(row)
                raise CoreError("Recovery session is terminal")
            state = {"pause":"paused","resume":"pending","cancel":"cancelled"}[action]
            if action == "resume" and row["status"] == "resource_limited":
                if not isinstance(reason,str) or not 1 <= len(reason.strip()) <= 1000:
                    raise CoreError("Resource-limited trial requires an explicit retry reason")
            elif action == "resume" and row["status"] != "paused":
                raise CoreError("Only paused recovery sessions can resume")
            if action in ("cancel","pause"):
                self._cleanup(row)
            self.db.execute("UPDATE recovery_sessions SET status=?,token=NULL,lease_until=0 WHERE id=?", (state,job))
            self._event(case,"recovery_session_"+{"pause":"paused","resume":"resumed","cancel":"cancelled"}[action],{"session":job})
        return self.get(case,job)

    def pause(self,case,job):
        return self._control(case,job,"pause")

    def resume(self,case,job,*,reason=None):
        return self._control(case,job,"resume",reason)

    def cancel(self,case,job):
        return self._control(case,job,"cancel")

    def extend(self,case,job,*,hours,reason,priority=False):
        if priority is not True or not _number(hours,1/3600,24) or not isinstance(reason,str) or not 1 <= len(reason.strip()) <= 1000:
            raise CoreError("Extension requires priority, 1-24 hours and a bounded reason")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self._ready(case)
            row = self._row(case,job)
            self._validate(row)
            if row["status"] in TERMINAL or row["status"] == "running":
                raise CoreError("Recovery session cannot be extended in this state")
            deadline = max(row["deadline"],time.time()) + hours*3600
            if deadline - row["started"] > 30*86400:
                raise CoreError("Recovery cumulative time window exceeded")
            state = "pending" if row["status"] == "deadline" else row["status"]
            self.db.execute("UPDATE recovery_sessions SET deadline=?,status=? WHERE id=?", (deadline,state,job))
            self._event(case,"recovery_session_extended",{"session":job,"deadline":deadline,"status":state,"priority":True,"reason":reason.strip()})
        return self.get(case,job)

    def _stop(self,case,job,token):
        try:
            self._ready(case)
            row = self._row(case,job)
            return (row["status"] != "running" or row["token"] != token or
                    row["lease_until"] <= time.time() or row["deadline"] <= time.time())
        except CoreError:
            return True

    def work(self,case,job,*,max_attempts=20,max_seconds=30):
        if type(max_attempts) is not int or not 1 <= max_attempts <= 1000 or not _number(max_seconds,.1,300):
            raise CoreError("Invalid recovery worker slice")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self._row(case,job)
            self._validate(row)
            if row["status"] != "succeeded" and (row["status"] != "running" or row["lease_until"] <= time.time()):
                self._cleanup(row)
            self._ready(case)
            if row["status"] in TERMINAL or row["status"] == "paused":
                return self._public(row)
            if row["status"] == "running" and row["lease_until"] > time.time():
                raise CoreError("Recovery worker already holds a live lease")
            if row["deadline"] <= time.time():
                self.db.execute("UPDATE recovery_sessions SET status='deadline',token=NULL,lease_until=0 WHERE id=?", (job,))
                self._event(case,"recovery_session_checkpoint",{"session":job,"status":"deadline","attempts":row["attempts"]})
                return self.get(case,job)
            self._cleanup(row)
            token = uuid4().hex
            self.db.execute("UPDATE recovery_sessions SET status='running',token=?,lease_until=? WHERE id=?",
                            (token,time.time()+max_seconds+30,job))
            self._event(case,"recovery_session_claimed",{"session":job})
        scratch, published_path = None, None
        stop_at = time.monotonic()+max_seconds
        try:
            artifact,_ = verified_result(self.core,case,row["task_id"])
            values,commitment = self._material(case,row["material_path"],self._secret(job))
            if not hmac.compare_digest(commitment,row["material_commitment"]) or len(values) != row["total_candidates"]:
                raise CoreError("Recovery candidate material changed")
            output_folder = storage_root(self.core.home/"cases"/case/"recovered")
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                if self._stop(case,job,token):
                    return self.get(case,job)
                stage_root = storage_root(self.core.home/"recovery-staging")
                stage_folder = storage_root(stage_root/(job+"-"+token))
            completed = 0
            while row["cursor"] < len(values) and completed < max_attempts:
                if self._stop(case,job,token) or time.monotonic() >= stop_at:
                    break
                value = values[row["cursor"]]
                candidate = bytes.fromhex(value.decode("ascii")) if row["mode"] == "ccaes1" else value
                scratch = stage_folder/"result.pending"
                request = {"mode":row["mode"],"source":artifact["copy"],"candidate":candidate.hex(),"output":str(scratch),"source_sha256":artifact["sha256"]}
                remaining = min(stop_at-time.monotonic(),row["deadline"]-time.time(),self.core.timeout)
                if remaining <= 0:
                    break
                try:
                    response = run_bounded([sys.executable,"-I",str(Path(__file__).with_name("recovery_trial.py"))],
                                       encoded(request),cwd=output_folder,timeout=remaining,max_output=4096,
                                           should_stop=lambda:self._stop(case,job,token))
                except CoreError:
                    if self._stop(case,job,token):
                        break
                    with self.db:
                        self.db.execute("BEGIN IMMEDIATE")
                        self._ready(case)
                        current = self._row(case,job)
                        self._validate(current)
                        if self._stop(case,job,token):
                            break
                        row["attempts"] += 1
                        row["status"] = "resource_limited"
                        self.db.execute("UPDATE recovery_sessions SET status='resource_limited',attempts=? WHERE id=?", (row["attempts"],job))
                        self._progress(row)
                    break
                result = json.loads(response["stdout"])
                if type(result.get("matched")) is not bool or any(k not in
                    ("matched","authenticated","sha256","size","algorithm","private_material_validated") for k in result):
                    raise CoreError("Invalid recovery trial response")
                published = None
                if result["matched"]:
                    if row["mode"] == "ccaes1":
                        if result.get("authenticated") is not True or type(result.get("size")) is not int:
                            raise CoreError("Recovery authentication missing")
                        with local_path(scratch).open("rb") as handle:
                            plain = handle.read(8*1024*1024+1)
                        if len(plain) != result["size"] or hashlib.sha256(plain).hexdigest() != result.get("sha256"):
                            raise CoreError("Recovery output integrity failed")
                        published = {k:result[k] for k in ("authenticated","sha256","size","algorithm")}
                        published_path = output_folder/(job+"-"+token+".recovered")
                        published["output"] = str(published_path)
                    else:
                        if result.get("private_material_validated") is not True:
                            raise CoreError("Private key validation missing")
                        published = {"private_material_validated":True,"algorithm":result["algorithm"]}
                if published_path is not None:
                    with self.db:
                        self.db.execute("BEGIN IMMEDIATE")
                        if self._stop(case,job,token):
                            break
                        self._ready(case)
                        self._event(case,"recovery_session_publication_reserved",{"session":job,"output":str(published_path)})
                with self.db:
                    self.db.execute("BEGIN IMMEDIATE")
                    current = self._row(case,job)
                    if self._stop(case,job,token):
                        break
                    self._ready(case)
                    self._validate(current)
                    verified_result(self.core,case,row["task_id"])
                    row["cursor"] += 1
                    row["attempts"] += 1
                    state = "succeeded" if published else "exhausted" if row["cursor"] == len(values) else "running"
                    payload = encoded(published) if published else None
                    self.db.execute("UPDATE recovery_sessions SET cursor=?,attempts=?,status=?,result=? WHERE id=?",
                                    (row["cursor"],row["attempts"],state,payload,job))
                    row.update(status=state,result=payload)
                    if published_path is not None:
                        os.replace(scratch,published_path)
                    self._progress(row)
                completed += 1
                if published:
                    scratch, published_path = None, None
                    break
                scratch.unlink(missing_ok=True)
                scratch = None
                if state == "exhausted":
                    break
        finally:
            if scratch is not None:
                scratch.unlink(missing_ok=True)
            if published_path is not None:
                # An interrupt can occur just after SQLite commits. Preserve a committed output.
                durable = self._row(case,job)
                if durable["status"] != "succeeded" or not durable["result"] or json.loads(durable["result"]).get("output") != str(published_path):
                    published_path.unlink(missing_ok=True)
            # Remove the claim directory even on normal completion. A stopped
            # orphan cannot recreate a file after this directory disappears.
            stage_dir = self.core.home/"recovery-staging"/(job+"-"+token)
            if stage_dir.exists():
                local_path(stage_dir,directory=True).rmdir()
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                current = self._row(case,job)
                if current["token"] == token:
                    state = current["status"]
                    if state == "running":
                        state = ("cancelled" if self.core.get(case)["state"] == "CANCELADO" else
                                 "deadline" if current["deadline"] <= time.time() else "pending")
                    self.db.execute("UPDATE recovery_sessions SET status=?,token=NULL,lease_until=0 WHERE id=?", (state,job))
                    self._event(case,"recovery_session_checkpoint",{"session":job,"status":state,"attempts":current["attempts"]})
        return self.get(case,job)
