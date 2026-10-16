"""Optional CLI diagnostics. Evidence is never automatically sent to agents."""
import importlib.metadata
import platform
import shutil
import sqlite3
import sys


def doctor():
    return {'platform': platform.platform(), 'python': sys.version, 'sqlite': sqlite3.sqlite_version,
            'cryptography': importlib.metadata.version('cryptography'),
            'git': shutil.which('git'),
            'agents': {name: {'executable': shutil.which(name), 'available': shutil.which(name) is not None,
                              'authentication': 'not checked'} for name in ('codex', 'claude')},
            'limitations': ['CLI discovery does not verify authentication',
                            'Claude is optional', 'No forensic or reverse engineering suites installed by this command']}
