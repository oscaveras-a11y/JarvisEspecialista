#!/usr/bin/env bash
set -euo pipefail
if [[ "${CODESPACES:-}" != true && "${GITHUB_ACTIONS:-}" != true ]]; then
  echo "Preparação permitida apenas no GitHub." >&2
  exit 1
fi
python -m pip install .
bash scripts/install-beta-tools.sh
