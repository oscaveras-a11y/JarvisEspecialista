#!/usr/bin/env bash
# Pinned reverse-engineering backends on disposable GitHub Actions runners only.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && -n "${RUNNER_TEMP:-}" && -n "${GITHUB_ENV:-}" ]] || { echo "GitHub Actions runner required" >&2; exit 1; }
sudo apt-get update -qq
sudo apt-get install -y build-essential pkg-config libfontconfig1-dev liblzma-dev libbz2-dev
curl --fail --location --retry 3 --output "$RUNNER_TEMP/ghidra.zip" https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip
echo "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db  $RUNNER_TEMP/ghidra.zip" | sha256sum --check
unzip -q "$RUNNER_TEMP/ghidra.zip" -d "$RUNNER_TEMP"
echo "CYBER_GHIDRA_HOME=$RUNNER_TEMP/ghidra_12.1.4_PUBLIC" >> "$GITHUB_ENV"
curl --fail --location --retry 3 --output "$RUNNER_TEMP/binwalk.crate" https://static.crates.io/crates/binwalk/binwalk-3.1.0.crate
echo "99d5dc70f5021c55624f098adae4d1de9c1c07d000475664704b675aad7e0811  $RUNNER_TEMP/binwalk.crate" | sha256sum --check
mkdir "$RUNNER_TEMP/binwalk-source"
tar -xf "$RUNNER_TEMP/binwalk.crate" -C "$RUNNER_TEMP/binwalk-source"
rustup toolchain install 1.85.1 --profile minimal
cargo +1.85.1 install --path "$RUNNER_TEMP/binwalk-source/binwalk-3.1.0" --locked --root "$RUNNER_TEMP/binwalk"
echo "CYBER_BINWALK=$RUNNER_TEMP/binwalk/bin/binwalk" >> "$GITHUB_ENV"
