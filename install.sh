#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
step() { printf '\n%s\n' "$1"; }
if [[ "$(uname -s)" != Darwin ]]; then
  printf 'Este instalador e para Mac. No Windows use install.ps1.\n' >&2
  exit 1
fi
step 'Vou garantir Homebrew, Git, Node, Ollama e as bibliotecas de audio no Mac.'
if ! command -v brew >/dev/null; then
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi
if [[ -x /opt/homebrew/bin/brew ]]; then eval "$(/opt/homebrew/bin/brew shellenv)";
elif [[ -x /usr/local/bin/brew ]]; then eval "$(/usr/local/bin/brew shellenv)"; fi
brew install node git ollama portaudio espeak-ng
if ! node -e 'const v=process.versions.node.split(".").map(Number);process.exit(v[0]>22||(v[0]===22&&v[1]>=22)?0:1)'; then
  brew upgrade node
  node -e 'const v=process.versions.node.split(".").map(Number);process.exit(v[0]>22||(v[0]===22&&v[1]>=22)?0:1)'
fi
if ! command -v uv >/dev/null; then curl -LsSf https://astral.sh/uv/install.sh | sh; fi
export PATH="$HOME/.local/bin:$PATH"
step 'Vou iniciar o Ollama e trazer o codigo oficial fixado no submodulo jarvis.'
brew services start ollama
cd "$ROOT"
git submodule update --init --recursive
export OPENJARVIS_HOME="$ROOT/.state" DO_NOT_TRACK=1 JARVIS_SKIP_MODEL_PICK=1
export OPENJARVIS_NO_UPDATE_CHECK=1
cd "$ROOT/jarvis"
step 'Vou instalar desktop e voz com Python entre 3.10 e 3.13 escolhido pelo uv.'
uv sync --extra desktop --extra voice --no-dev
MODEL="${JARVIS_MODEL:-gemma4:e4b}"
if [[ -z "${JARVIS_MODEL:-}" && "$(sysctl -n hw.memsize)" -lt 17179869184 ]]; then
  MODEL=gemma4:e2b
  printf 'Menos de 16 GB de RAM: usando gemma4:e2b.\n'
fi
case "$MODEL" in gemma4:e4b|gemma4:e2b) ;; *) printf 'JARVIS_MODEL deve ser gemma4:e4b ou gemma4:e2b.\n' >&2; exit 1;; esac
for attempt in {1..30}; do
  if curl -fsS http://127.0.0.1:11434/api/tags >/dev/null; then break; fi
  sleep 1
done
step "Vou baixar o modelo local $MODEL."
ollama pull "$MODEL"
step 'Vou configurar perfil personal, voz brasileira pf_dora e reconhecimento em portugues.'
uv run --no-sync jarvis _bootstrap --write-config --engine ollama --model "$MODEL"
uv run --no-sync jarvis config set security.profile personal
uv run --no-sync jarvis config set speech.voice_id pf_dora
uv run --no-sync jarvis config set speech.language pt
uv run --no-sync jarvis config set speech.backend faster-whisper
uv run --no-sync jarvis config set speech.tts_backend kokoro
uv run --no-sync jarvis config set speech.device cpu
uv run --no-sync jarvis config set speech.compute_type int8
uv run --no-sync jarvis config set telemetry.enabled false
uv run --no-sync jarvis config set analytics.enabled false
uv run --no-sync jarvis config set agent.default_agent none
uv run --no-sync jarvis config set server.host 127.0.0.1
step 'Vou instalar e construir a interface web.'
(cd frontend && npx --yes --package=npm@11.19.0 npm ci && npx --yes --package=npm@11.19.0 npm run build)
step 'Vou executar o doctor e os testes de texto e voz.'
uv run --no-sync jarvis doctor
uv run --no-sync python ../voice/check_doctor.py
uv run --no-sync jarvis ask --engine ollama 'Em uma frase, quem e voce? Responda em portugues do Brasil.'
uv run --no-sync python ../voice/validate.py
step 'Vou disponibilizar o comando jarvis no PATH do usuario.'
chmod +x "$ROOT/bin/jarvis"
mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/jarvis" <<EOF
#!/usr/bin/env bash
exec "$ROOT/bin/jarvis" "\$@"
EOF
chmod +x "$HOME/.local/bin/jarvis"
printf 'Abra um terminal novo. Se necessario: export PATH="$HOME/.local/bin:$PATH"\n'
printf 'Comandos: jarvis, jarvis --listen ou jarvis --web.\n'
