"""Private Linux CLI runtime. Caller must supervise the whole process tree."""
import hashlib
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
from cyber_core.errors import CoreError

TOOLS = ("hashcat","john","qpdf","openssl","die","unblob")
ENV_NAMES = {tool:"CYBER_"+tool.upper()+"_EXECUTABLE" for tool in TOOLS}
MODES = {"qpdf-pdf":"qpdf", "openssl-pkcs12":"openssl", 
         "hashcat-sha256":"hashcat", "john-sha256":"john",
         "john-zip":"john", "hashcat-zip-aes":"hashcat", "john-rar5":"john"}
VALIDATION = {mode: text for mode,text in (
    ("qpdf-pdf","QPDF password and decrypted PDF structure verified"),
    ("openssl-pkcs12","OpenSSL PKCS12 password and key/certificate structure verified"),
    ("hashcat-sha256","Hashcat single SHA256 candidate independently verified"),
    ("john-sha256","John Jumbo single SHA256 candidate independently verified"),
    ("john-rar5","John Jumbo and native RAR5 password-check verifier; payload integrity not verified"),
    ("john-zip","John Jumbo ZIP candidate and archive integrity independently verified"),
    ("hashcat-zip-aes","Hashcat WinZip AES candidate and archive integrity independently verified"))}
SIGNATURES = {"qpdf-pdf":(b"%PDF-",), "openssl-pkcs12":(b"0",),
              "hashcat-sha256":None,"john-sha256":None,
              "john-rar5":(b"Rar!\x1a\x07\x01\x00",), "john-zip":(b"PK\x03\x04",), "hashcat-zip-aes":(b"PK\x03\x04",)}

def executable(value):
    if not isinstance(value,str) or not value or not Path(value).is_absolute():
        raise CoreError("External tool requires an absolute trusted executable")
    # John Jumbo selects zip2john by argv[0]; resolving the final symlink
    # changes the program's operation. Resolve only its parent directory.
    supplied = Path(value)
    path = supplied.parent.resolve() / supplied.name
    resolved = path.resolve()
    if not path.is_file() or not os.access(path,os.X_OK) or any(p.suffix.lower() in (".cmd",".bat",".sh",".ps1") for p in (path, resolved)):
        raise CoreError("External tool executable unavailable")
    return str(path)

def external_configuration(tool):
    if tool not in TOOLS:
        raise CoreError("Unknown external tool")
    if sys.platform != "linux":
        raise CoreError("External recovery tools currently require Linux")
    config = {"executable":executable(os.environ.get(ENV_NAMES[tool]))}
    converter = os.environ.get("CYBER_ZIP2JOHN_EXECUTABLE")
    if tool in ("john","hashcat") and converter:
        config["converter"] = executable(converter)
    rar_converter = os.environ.get("CYBER_RAR2JOHN_EXECUTABLE")
    if tool == "john" and rar_converter:
        config["rar_converter"] = executable(rar_converter)
    return config

def tool_inventory():
    output = {}
    for tool in TOOLS:
        try:
            external_configuration(tool)
        except CoreError:
            output[tool] = {"available":False,"reason":"Linux and explicitly configured absolute executable required"}
        else:
            output[tool] = {"available":True,"readiness":"configured; real execution/version checked per operation"}
    return output

def binary_digest(path):
    value = hashlib.sha256()
    count = 0
    with open(executable(path),"rb") as stream:
        while block := stream.read(65536):
            count += len(block)
            if count > 256*1024*1024:
                raise CoreError("External executable inventory limit")
            value.update(block)
    return value.hexdigest()

def scratch_limit(root):
    total,count = 0,0
    for item in root.rglob("*"):
        count += 1
        if count > 1024 or item.is_symlink():
            raise CoreError("External scratch entry limit")
        if item.is_file():
            try:
                size = item.stat().st_size
            except FileNotFoundError:
                # A tool may remove/rename its own temporary file after is_file().
                # Missing files consume no current scratch bytes; all other I/O
                # errors, entry counts, symlinks and size violations still fail.
                continue
            total += size
            if total > 32*1024*1024:
                raise CoreError("External scratch byte limit")

class Runner:
    def __init__(self, root, timeout):
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0 < timeout <= 3600:
            raise CoreError("Invalid external timeout")
        self.root = Path(root)
        self.deadline = time.monotonic()+timeout
        home = self.root/"home"
        home.mkdir()
        self.env = {"PATH":"/usr/bin:/bin","HOME":str(home),"TMPDIR":str(self.root),
                    "LANG":"C.UTF-8","LC_ALL":"C.UTF-8","OMP_NUM_THREADS":"2","POCL_MAX_PTHREAD_COUNT":"2"}
    def run(self, command, *, data=b"", allowed=(0,), output_limit=262144):
        if sys.platform != "linux":
            raise CoreError("External tools require Linux")
        command = [str(part) for part in command]
        command[0] = executable(command[0])
        if not all("\x00" not in part for part in command):
            raise CoreError("Invalid external argv")
        remaining = self.deadline-time.monotonic()
        if remaining <= 0:
            raise CoreError("External shared timeout")
        launcher = Path(__file__).parent/"reverse_engineering"/"_limit_exec.py"
        process = subprocess.Popen([sys.executable,"-I",str(launcher),str(remaining),*command],
            cwd=self.root,env=self.env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            shell=False,close_fds=True)
        buffers = [bytearray(),bytearray()]
        exceeded = threading.Event()
        lock = threading.Lock()
        def consume(stream,index):
            try:
                while block := stream.read(4096):
                    with lock:
                        if sum(map(len,buffers))+len(block)>output_limit:
                            exceeded.set()
                            return
                        buffers[index].extend(block)
            except (OSError,ValueError):
                pass
        def feed():
            try:
                process.stdin.write(data)
                process.stdin.close()
            except (OSError,ValueError):
                pass
        threads = [threading.Thread(target=consume,args=(process.stdout,0),daemon=True),
                   threading.Thread(target=consume,args=(process.stderr,1),daemon=True),
                   threading.Thread(target=feed,daemon=True)]
        for thread in threads: thread.start()
        try:
            while process.poll() is None:
                if exceeded.is_set() or time.monotonic()>=self.deadline:
                    raise CoreError("External output or time limit exceeded")
                scratch_limit(self.root)
                time.sleep(.02)
            for thread in threads: thread.join(timeout=1)
            if exceeded.is_set() or any(thread.is_alive() for thread in threads):
                raise CoreError("External output or stream limit exceeded")
            scratch_limit(self.root)
            if time.monotonic()>=self.deadline or process.returncode not in allowed:
                raise CoreError("External tool execution failed")
            return process.returncode,bytes(buffers[0]),bytes(buffers[1])
        finally:
            if process.poll() is None: process.kill()
            process.wait(timeout=3)
            for stream in (process.stdin,process.stdout,process.stderr):
                if not stream.closed: stream.close()

def version(runner,tool,path):
    args = {"hashcat":["--version"],"john":["--list=build-info"],"qpdf":["--version"],
            "openssl":["version"],"die":["--version"],"unblob":["--version"]}[tool]
    _,stdout,stderr = runner.run([path,*args])
    match = re.search(rb"(?<![0-9.])\d+(?:\.\d+){1,3}(?![0-9.])",stdout+stderr)
    if not match:
        raise CoreError("External tool version not recognized")
    return match.group().decode("ascii")
