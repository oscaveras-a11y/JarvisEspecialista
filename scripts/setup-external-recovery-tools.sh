#!/usr/bin/env bash
# Executed only in a disposable GitHub Actions Ubuntu24.04 runner.
set -euo pipefail
root="$RUNNER_TEMP/cyber-external-tools"
mkdir -p "$root"
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends hashcat pocl-opencl-icd qpdf openssl build-essential libssl-dev zlib1g-dev pkg-config libgmp-dev libpcap-dev libbz2-dev libmagic1
curl --fail --location --retry 3 https://github.com/horsicq/DIE-engine/releases/download/3.10/die_3.10_Ubuntu_24.04_amd64.deb --output "$root/die.deb"
sudo apt-get install -y "$root/die.deb"
git clone --filter=blob:none https://github.com/openwall/john.git "$root/john"
git -C "$root/john" checkout --detach 5184bc0b8c105f8c5978b112e723d65b2de3e63e
(
  cd "$root/john/src"
  ./configure --disable-opencl
  make -sj2
)
python -m venv "$root/unblob"
"$root/unblob/bin/python" -m pip install 'unblob==26.6.4'
{
  echo "CYBER_HASHCAT_EXECUTABLE=$(command -v hashcat)"
  echo "CYBER_JOHN_EXECUTABLE=$root/john/run/john"
  echo "CYBER_ZIP2JOHN_EXECUTABLE=$root/john/run/zip2john"
  echo "CYBER_QPDF_EXECUTABLE=$(command -v qpdf)"
  echo "CYBER_OPENSSL_EXECUTABLE=$(command -v openssl)"
  echo "CYBER_DIE_EXECUTABLE=$(command -v diec)"
  echo "CYBER_UNBLOB_EXECUTABLE=$root/unblob/bin/unblob"
} >> "$GITHUB_ENV"
hashcat --version
"$root/john/run/john" --list=build-info
qpdf --version
openssl version
diec --version
"$root/unblob/bin/unblob" --version
