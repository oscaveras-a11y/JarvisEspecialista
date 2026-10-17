"""Item 14 'politica de acesso a rede': the analysis child that parses
untrusted evidence must not be able to open a socket. Runs in a fresh
subprocess rather than patching the shared test process's socket module.
"""
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = str(Path(__file__).resolve().parents[1] / 'src')


class NetworkGuardTests(unittest.TestCase):
    def test_block_network_rejects_socket_creation(self):
        script = (
            "import sys; sys.path.insert(0, " + repr(ROOT) + ")\n"
            "from cyber_core.analysis_process.network_guard import block_network, NetworkBlocked\n"
            "block_network()\n"
            "import socket\n"
            "try:\n"
            "    socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "    print('UNBLOCKED')\n"
            "except NetworkBlocked:\n"
            "    print('BLOCKED')\n"
        )
        result = subprocess.run([sys.executable, '-I', '-c', script], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.stdout.strip(), 'BLOCKED', result.stderr)

    def test_block_network_rejects_create_connection_and_dns(self):
        script = (
            "import sys; sys.path.insert(0, " + repr(ROOT) + ")\n"
            "from cyber_core.analysis_process.network_guard import block_network, NetworkBlocked\n"
            "block_network()\n"
            "import socket\n"
            "blocked = 0\n"
            "for call in (lambda: socket.create_connection(('127.0.0.1', 80)),\n"
            "             lambda: socket.getaddrinfo('localhost', 80),\n"
            "             lambda: socket.gethostbyname('localhost')):\n"
            "    try:\n"
            "        call()\n"
            "    except NetworkBlocked:\n"
            "        blocked += 1\n"
            "print(blocked)\n"
        )
        result = subprocess.run([sys.executable, '-I', '-c', script], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.stdout.strip(), '3', result.stderr)

    def test_analysis_child_process_has_network_blocked(self):
        # The exact entry point child.py uses: block before any analysis
        # import, so even a bug in trusted analysis code can't reach a socket.
        script = (
            "import sys; sys.path.insert(0, " + repr(ROOT) + ")\n"
            "from cyber_core.analysis_process.network_guard import block_network\n"
            "block_network()\n"
            "from cyber_core.reverse_engineering import analyze\n"
            "import socket\n"
            "try:\n"
            "    socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "    print('UNBLOCKED')\n"
            "except OSError:\n"
            "    print('BLOCKED')\n"
        )
        result = subprocess.run([sys.executable, '-I', '-c', script], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.stdout.strip(), 'BLOCKED', result.stderr)


if __name__ == '__main__':
    unittest.main()
