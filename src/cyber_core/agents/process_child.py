"""Trusted stdin-gated launcher; containment attaches before the CLI can start."""
import json
import subprocess
import sys

def main():
    try:
        payload = json.loads(sys.stdin.buffer.readline(65537))
        command, prompt = payload['command'], payload['prompt']
        if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
            return 125
        if not isinstance(prompt, str):
            return 125
        child = subprocess.Popen(command, stdin=subprocess.PIPE, shell=False, close_fds=True)
        child.communicate(prompt.encode('utf-8'))
        return child.returncode if child.returncode >= 0 else 125
    except (OSError, ValueError, KeyError, TypeError):
        # Never expose provider errors, commands, paths or environment values.
        return 125

if __name__ == '__main__':
    raise SystemExit(main())
