"""Read-only CLI discovery; never authenticates or calls a provider."""
import importlib.metadata
import platform
import shutil
import sqlite3
import sys

from cyber_core.agents.runner import CodexAdapter, ClaudeAdapter, AgentResourceError

def doctor():
    agents = {}
    for adapter in (CodexAdapter(), ClaudeAdapter()):
        try:
            adapter.check_available()
            available = True
        except AgentResourceError:
            available = False
        agents[adapter.name] = {'executable': adapter.executable, 'available': available,
                                'authentication': 'not checked'}
    return {'platform': platform.platform(), 'python': sys.version, 'sqlite': sqlite3.sqlite_version,
            'cryptography': importlib.metadata.version('cryptography'), 'git': shutil.which('git'),
            'agents': agents,
            'limitations': ['Executable discovery does not verify authentication or provider access',
                            'Claude is optional', 'No forensic or reverse engineering suites installed by this command']}
