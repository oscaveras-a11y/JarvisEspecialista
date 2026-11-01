"""Resolve only the reviewed capacity/long-timeout overlap in disposable CI.

Never updates a branch; refuse any other conflict or constructor contract.
"""
from pathlib import Path
import subprocess
import tempfile

path = 'src/cyber_core/service.py'
def git(*args):
    return subprocess.check_output(['git', *args], text=True, encoding='utf-8')

unmerged = git('diff', '--name-only', '--diff-filter=U').splitlines()
if unmerged != [path]:
    raise SystemExit('Unreviewed combination conflict; refusing resolution')

base, ours, theirs = [git('show', f':{stage}:{path}') for stage in (1, 2, 3)]
old = 'if not 1 <= max_bytes <= 256 * 1024 * 1024 or not 0 < timeout <= '
new = 'if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_INPUT_BYTES or type(timeout) not in (int, float) or not 0 < timeout <= '
if base.count(old + '3600:') != 1 or ours.count(new + '3600:') != 1 or theirs.count(old + 'self.MAX_TIMEOUT:') != 1:
    raise SystemExit('Unreviewed capacity/timeout constructor; refusing resolution')
# Apply the exact capacity delta to both sides of the common ancestor. The
# remaining merge then retains the candidate long-timeout/configuration changes.
base = base.replace(old, new)
theirs = theirs.replace(old, new)
with tempfile.TemporaryDirectory() as directory:
    paths = [Path(directory) / name for name in ('ours', 'base', 'theirs')]
    for target, content in zip(paths, (ours, base, theirs)):
        target.write_text(content, encoding='utf-8')
    merged = subprocess.run(['git', 'merge-file', '-p', *map(str, paths)],
                            capture_output=True, text=True, encoding='utf-8')
    if merged.returncode:
        raise SystemExit('Additional service conflict; refusing resolution')
    if new + 'self.MAX_TIMEOUT:' not in merged.stdout:
        raise SystemExit('Combined contract missing')
    Path(path).write_text(merged.stdout, encoding='utf-8')
subprocess.run(['git', 'add', '--', path], check=True)
print('Resolved reviewed capacity/long-timeout overlap only; combined suite must pass.')
