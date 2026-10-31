"""Runner-only diagnostics using freshly generated synthetic material."""
import hashlib
import os
from pathlib import Path
import tempfile
from cyber_core.external_tool_runtime import Runner, external_configuration

def main():
    import pyzipper
    with tempfile.TemporaryDirectory(prefix="synthetic-probe-") as folder:
        root = Path(folder)
        password = b"synthetic-probe-2026"
        words = root / "words"
        words.write_bytes(password + b"\n")
        source = root / "source.zip"
        with pyzipper.AESZipFile(source, "w", encryption=pyzipper.WZ_AES) as archive:
            archive.setpassword(password)
            archive.writestr("synthetic.txt", b"synthetic diagnostic only")
        hashes = root / "hashes"
        hashes.write_text(hashlib.sha256(password).hexdigest() + "\n")
        zip_config = external_configuration("john")
        converted = __import__("subprocess").run([zip_config["converter"], str(source)], capture_output=True, timeout=10,
            env={"PATH": "/usr/bin:/bin", "HOME": str(root), "LANG": "C.UTF-8"})
        print("zip2john exit", converted.returncode, "zip2 marker", b"$zip2$" in converted.stdout)
        import re
        matches = re.findall(rb"\$zip2\$[^\r\n]*?\$/zip2\$", converted.stdout)
        zip_hash = root / "zip-hash"
        zip_hash.write_bytes((matches[0] if matches else b"") + b"\n")
        probes = {
            "hashcat-sha256": [external_configuration("hashcat")["executable"], "--quiet",
                "--potfile-disable", "--logfile-disable", "--restore-disable", "-a", "0", "-m", "1400",
                "--outfile", str(root / "hashcat-result"), "--outfile-format", "2", str(hashes), str(words)],
            "john-zip": [zip_config["executable"], "--format=ZIP", "--wordlist=" + str(words),
                         "--pot=" + str(root / "probe.pot"), "--session=" + str(root / "session"), str(zip_hash)]}
        for name, command in probes.items():
            work = root / name
            work.mkdir()
            runner = Runner(work, 90)
            try:
                code, out, err = runner.run(command, allowed=tuple(range(256)))
                diagnostic = (out + err).decode("utf-8", errors="replace")
                diagnostic = diagnostic.replace(str(root), "<synthetic-scratch>").replace(password.decode(), "<synthetic-candidate>")
                # Input is synthetic. Do not print converter content, passwords or arbitrary environment.
                print(name, "exit", code, "diagnostic", diagnostic[:4000])
            except Exception as exc:
                print(name, "sanitized failure", type(exc).__name__)

if __name__ == "__main__":
    main()
