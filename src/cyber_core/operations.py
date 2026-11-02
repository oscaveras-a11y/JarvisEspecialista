"""Authorized inventories and reportable metadata; no evidence execution."""
import json
import hashlib
from uuid import uuid4
from cyber_core.analysis_process.limits import MAX_INPUT_BYTES
from cyber_core.errors import CoreError
from cyber_core.memory import audit, encoded, utc
from cyber_core.verification.artifacts import verified_result

def _read_bounded(handle, maximum):
    # handle.read(n) with a large explicit n asks the interpreter to
    # pre-allocate a buffer of that size up front — harmless at small scale,
    # but confirmed raising MemoryError for a multi-GiB maximum against a
    # modest real file, under the same RLIMIT_AS this value is bounded by.
    chunks = bytearray()
    while len(chunks) <= maximum:
        block = handle.read(min(1048576, maximum + 1 - len(chunks)))
        if not block:
            break
        chunks += block
    return bytes(chunks)

SCHEMA = """CREATE TABLE IF NOT EXISTS operation_results(
 id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES investigations(id),
 kind TEXT NOT NULL,data TEXT NOT NULL,created TEXT NOT NULL);"""

def ensure(core):
    if core.db.in_transaction:
        raise CoreError("Initialize operation results outside a transaction")
    core.db.execute(SCHEMA)
    core.db.commit()

def save_operation(core,case,kind,data,*,recovery=False,commit_guard=None):
    if commit_guard is not None and not callable(commit_guard):
        raise CoreError('Invalid operation commit guard')
    ensure(core)
    with core.db:
        core.db.execute("BEGIN IMMEDIATE")
        row = core.authorize(case,recovery=recovery)
        if row["paused"]:
            raise CoreError("Investigation is paused")
        if commit_guard is not None:
            commit_guard()
        identifier = uuid4().hex
        core.db.execute("INSERT INTO operation_results VALUES(?,?,?,?,?)",
                        (identifier,case,kind,encoded(data),utc()))
        from cyber_core.verification.artifacts import result_digest
        audit(core.db,case,"operation_result_committed",{"operation":identifier,"kind":kind,"result_digest":result_digest(data)})
    return {"id":identifier,"kind":kind,**data}

def saved_operations(core,case):
    core.get(case)
    if not core.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='operation_results'").fetchone():
        return []
    output = []
    from cyber_core.verification.artifacts import result_digest
    if not core.verify_audit(case):
        raise CoreError("Audit integrity failed")
    anchors = {}
    for row in core.db.execute("SELECT data FROM audit WHERE case_id=? AND event='operation_result_committed'",(case,)):
        event = json.loads(row["data"])
        anchors[event["operation"]] = event
    for row in core.db.execute("SELECT * FROM operation_results WHERE case_id=? ORDER BY rowid",(case,)):
        data = json.loads(row["data"])
        anchor = anchors.get(row["id"],{})
        if anchor.get("kind") != row["kind"] or anchor.get("result_digest") != result_digest(data):
            raise CoreError("Operation result differs from audited metadata")
        output.append({"id":row["id"],"kind":row["kind"],**data})
    return output

def _acquire(core,case,path,maximum):
    row = core.authorize(case)
    if row["paused"]:
        raise CoreError("Investigation is paused")
    source = core.authorize(case,path)
    # The 64 MiB floor-style ceiling here used to block ANY caller from ever
    # acquiring more than that, regardless of core.max_bytes — real firmware
    # over 5 GiB (confirmed with a real OpenWrt image) needs more. Bounded by
    # the same MAX_INPUT_BYTES ceiling as core.max_bytes itself, so this never
    # allows more than the operator already explicitly configured.
    if type(maximum) is not int or not 1 <= maximum <= min(core.max_bytes,MAX_INPUT_BYTES):
        raise CoreError("Invalid inventory byte limit")
    with source.open("rb") as handle:
        if handle.seek(0,2) > maximum:
            raise CoreError("Inventory input exceeds byte limit")
    task = core.enqueue(case,source)
    core.run_one(case,task_id=task)
    result,_ = verified_result(core,case,task)
    with open(result["copy"],"rb") as handle:
        raw = _read_bounded(handle, maximum)
    if len(raw) > maximum or len(raw) != result["size"] or hashlib.sha256(raw).hexdigest() != result["sha256"]:
        raise CoreError("Inventory copy changed or exceeds byte limit")
    return raw,result

def inventory_disk(core,case,path,*,max_bytes=16777216,max_partitions=256,sector_size=512):
    from cyber_core.forensics.disk import inspect_disk_image
    raw,evidence = _acquire(core,case,path,max_bytes)
    try:
        result = inspect_disk_image(raw,max_bytes=max_bytes,max_partitions=max_partitions,sector_size=sector_size)
    except ValueError:
        raise CoreError("Invalid disk image or inventory limits") from None
    return save_operation(core,case,"disk_inventory",{"evidence":evidence,"inventory":result})

def inventory_pcap(core,case,path,*,max_bytes=16777216,max_packets=256):
    from cyber_core.protocols_pcap import inspect_pcap
    raw,evidence = _acquire(core,case,path,max_bytes)
    try:
        result = inspect_pcap(raw,max_bytes=max_bytes,max_packets=max_packets)
    except ValueError:
        raise CoreError("Invalid PCAP or inventory limits") from None
    return save_operation(core,case,"pcap_inventory",{"evidence":evidence,"inventory":result})
