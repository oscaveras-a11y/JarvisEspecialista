#!/usr/bin/env bash
# Pinned real backends, installed only in a remote disposable GitHub environment.
set -euo pipefail
if [[ "${CODESPACES:-}" != true && "${GITHUB_ACTIONS:-}" != true ]]; then
  echo "Instalação permitida apenas no GitHub." >&2
  exit 1
fi
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || { echo "Ferramentas reais requerem Linux x86_64."; exit 1; }
tools_root="${CYBER_TOOLS_ROOT:-$HOME/.cyber-core-tools}"
mkdir -p "$tools_root"
downloads="$(mktemp -d)"
trap 'rm -rf "$downloads"' EXIT
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends build-essential pkg-config curl unzip libfontconfig1-dev liblzma-dev libbz2-dev
if [[ ! -f "$tools_root/ghidra_12.1.4_PUBLIC/support/analyzeHeadless" ]]; then
  curl --fail --location --retry 3 --output "$downloads/ghidra.zip" https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip
  echo "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db  $downloads/ghidra.zip" | sha256sum --check
  unzip -q "$downloads/ghidra.zip" -d "$tools_root"
fi
if [[ ! -x "$tools_root/binwalk/bin/binwalk" ]]; then
  if ! command -v rustup >/dev/null 2>&1; then
    curl --fail --location --retry 3 --output "$downloads/rustup-init" https://static.rust-lang.org/rustup/archive/1.29.1/x86_64-unknown-linux-gnu/rustup-init
    echo "dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71  $downloads/rustup-init" | sha256sum --check
    chmod u+x "$downloads/rustup-init"
    "$downloads/rustup-init" -y --no-modify-path --profile minimal --default-toolchain 1.85.1
    export PATH="$HOME/.cargo/bin:$PATH"
  fi
  rustup toolchain install 1.85.1 --profile minimal
  curl --fail --location --retry 3 --output "$downloads/binwalk.crate" https://static.crates.io/crates/binwalk/binwalk-3.1.0.crate
  echo "99d5dc70f5021c55624f098adae4d1de9c1c07d000475664704b675aad7e0811  $downloads/binwalk.crate" | sha256sum --check
  tar -xf "$downloads/binwalk.crate" -C "$downloads"
  cargo +1.85.1 install --path "$downloads/binwalk-3.1.0" --locked --root "$tools_root/binwalk"
fi
echo "Ghidra e Binwalk preparados no ambiente remoto."
