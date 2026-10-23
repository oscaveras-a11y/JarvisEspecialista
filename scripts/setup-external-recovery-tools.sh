#!/usr/bin/env bash
# Executed only in a disposable GitHub Actions Ubuntu24.04 runner.
set -euo pipefail
root="$RUNNER_TEMP/cyber-external-tools"
mkdir -p "$root"
sudo apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update -qq
sudo apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 install -y --no-install-recommends hashcat ocl-icd-libopencl1 pocl-opencl-icd clinfo qpdf openssl build-essential libssl-dev zlib1g-dev pkg-config libgmp-dev libpcap-dev libbz2-dev libmagic1
# The loader is separate from the POCL vendor runtime when recommends are disabled.
clinfo --list
hashcat --backend-info
curl --fail --location --connect-timeout 30 --max-time 180 --retry 2 https://github.com/horsicq/DIE-engine/releases/download/3.10/die_3.10_Ubuntu_24.04_amd64.deb --output "$root/die.deb"
sudo apt-get install -y "$root/die.deb"
timeout 180 git clone --filter=blob:none https://github.com/openwall/john.git "$root/john"
timeout 180 git -C "$root/john" checkout --detach 5184bc0b8c105f8c5978b112e723d65b2de3e63e
(
  cd "$root/john/src"
  ./configure --disable-opencl
  timeout 600 make -sj2
)
python -m venv "$root/unblob"
"$root/unblob/bin/python" -m pip install --timeout 30 --retries 2 'unblob==26.6.4'
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
