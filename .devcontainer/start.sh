#!/usr/bin/env bash
set -euo pipefail
[[ "${CODESPACES:-}" == true ]] || { echo "Abra pelo GitHub Codespaces."; exit 1; }
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
state_root="$HOME/.cyber-core-beta"
tools_root="${CYBER_TOOLS_ROOT:-$HOME/.cyber-core-tools}"
mkdir -p "$state_root"
chmod 700 "$state_root"
export CYBER_GHIDRA_HOME="$tools_root/ghidra_12.1.4_PUBLIC"
export CYBER_BINWALK="$tools_root/binwalk/bin/binwalk"
if python -c 'import json,urllib.request; assert json.load(urllib.request.urlopen("http://127.0.0.1:8765/api/health",timeout=2))["service"]=="cyber-core"' 2>/dev/null; then
  echo "CYBER CORE: http://127.0.0.1:8765"
  exit 0
fi
nohup python -m cyber_core.web_server --home "$state_root" --web-root "$repo_root/web" > "$state_root/server.log" 2>&1 < /dev/null &
for attempt in {1..60}; do
  if python -c 'import json,urllib.request; assert json.load(urllib.request.urlopen("http://127.0.0.1:8765/api/health",timeout=2))["service"]=="cyber-core"' 2>/dev/null; then
    echo "CYBER CORE: http://127.0.0.1:8765"
    echo "Abra a porta 8765 em PORTS, mantendo a visibilidade Private."
    exit 0
  fi
  sleep 1
done
echo "O painel não iniciou. Consulte $state_root/server.log no Codespace." >&2
exit 1
