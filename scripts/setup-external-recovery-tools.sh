#!/usr/bin/env bash
# Executed only in a disposable GitHub Actions Ubuntu24.04 runner.
set -euo pipefail
root="$RUNNER_TEMP/cyber-external-tools"
mkdir -p "$root"
# Only the disposable Actions runner is changed. Its Azure HTTP mirror was
# transferring packages at tens of KiB/s; retain signed Ubuntu packages via HTTPS.
for source_list in /etc/apt/apt-mirrors*.txt /etc/apt/sources.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; do
  if [ -f "$source_list" ]; then
    sudo sed -i 's|http://azure.archive.ubuntu.com/ubuntu|https://archive.ubuntu.com/ubuntu|g' "$source_list"
  fi
done
sudo apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update -qq
sudo apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 install -y --no-install-recommends hashcat ocl-icd-libopencl1 pocl-opencl-icd clinfo qpdf openssl build-essential libssl-dev zlib1g-dev pkg-config libgmp-dev libpcap-dev libbz2-dev libmagic1 squashfs-tools e2fsprogs p7zip-full liblzo2-dev liblz4-dev libzstd-dev sleuthkit dosfstools mtools
# The loader is separate from the POCL vendor runtime when recommends are disabled.
clinfo --list
hashcat --backend-info
curl --fail --location --connect-timeout 30 --max-time 180 --retry 2 https://github.com/horsicq/DIE-engine/releases/download/3.10/die_3.10_Ubuntu_24.04_amd64.deb --output "$root/die.deb"
sudo apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 install -y --no-install-recommends "$root/die.deb"
timeout 180 git clone --filter=blob:none https://github.com/openwall/john.git "$root/john"
timeout 180 git -C "$root/john" checkout --detach 5184bc0b8c105f8c5978b112e723d65b2de3e63e
(
  cd "$root/john/src"
  ./configure --disable-opencl
  timeout 600 make -sj2
)
python -m venv "$root/unblob"
"$root/unblob/bin/python" -m pip install --timeout 30 --retries 2 'unblob==26.6.4'
python -m pip install --timeout 30 --retries 2 'semgrep==1.183.0' 'detect-secrets==1.5.0' 'pip-audit==2.10.1'

# sasquatch (onekey-sec fork of squashfs-tools' unsquashfs): unblob's own
# --show-external-dependencies names this as the extractor for vendor/OpenWrt-
# style SquashFS variants; without it, a real firmware's rootfs chunk is
# identified but never recursed into. Built from source and pinned to one
# commit; the plain system unsquashfs (already installed above) already
# handles the common SQUASHFS_V4_LE case and is tried first by sasquatch
# itself when invoked, so this is pure upside, never a regression if the
# build were ever to fail for an unrelated reason.
timeout 180 git clone --filter=blob:none https://github.com/onekey-sec/sasquatch.git "$root/sasquatch"
timeout 180 git -C "$root/sasquatch" checkout --detach b34aa5ef67068a2137ac04e2272915bd45388260
(
  cd "$root/sasquatch/squashfs-tools"
  timeout 300 make -sj2
  cp sasquatch "$root/sasquatch-le"
  make clean >/dev/null
  CFLAGS="-DFIX_BE" timeout 300 make -sj2
  cp sasquatch "$root/sasquatch-v4be"
)
sudo install -m 755 "$root/sasquatch-le" /usr/bin/sasquatch
sudo install -m 755 "$root/sasquatch-v4be" /usr/bin/sasquatch-v4be
# debugfs (e2fsprogs) ships in /usr/sbin, which Runner's own deliberately
# minimal PATH (/usr/bin:/bin) does not include; unblob needs it on PATH to
# recurse into an ext2/3/4 chunk (e.g. a real firmware's boot partition).
sudo install -m 755 "$(command -v debugfs)" /usr/bin/debugfs
{
  echo "CYBER_HASHCAT_EXECUTABLE=$(command -v hashcat)"
  echo "CYBER_JOHN_EXECUTABLE=$root/john/run/john"
  echo "CYBER_ZIP2JOHN_EXECUTABLE=$root/john/run/zip2john"
  echo "CYBER_RAR2JOHN_EXECUTABLE=$root/john/run/rar2john"
  echo "CYBER_QPDF_EXECUTABLE=$(command -v qpdf)"
  echo "CYBER_OPENSSL_EXECUTABLE=$(command -v openssl)"
  echo "CYBER_DIE_EXECUTABLE=$(command -v diec)"
  echo "CYBER_UNBLOB_EXECUTABLE=$root/unblob/bin/unblob"
  echo "CYBER_SEMGREP_EXECUTABLE=$(command -v semgrep)"
  echo "CYBER_SEMGREP_RULES_PATH=$(pwd)/config/semgrep-rules/python-security.yml"
  echo "CYBER_DETECT_SECRETS_EXECUTABLE=$(command -v detect-secrets)"
  echo "CYBER_PIP_AUDIT_EXECUTABLE=$(command -v pip-audit)"
  echo "CYBER_MMLS_EXECUTABLE=$(command -v mmls)"
  echo "CYBER_FLS_EXECUTABLE=$(command -v fls)"
  echo "CYBER_ICAT_EXECUTABLE=$(command -v icat)"
  echo "CYBER_FSSTAT_EXECUTABLE=$(command -v fsstat)"
} >> "$GITHUB_ENV"
hashcat --version
"$root/john/run/john" --list=build-info
qpdf --version
openssl version
diec --version
"$root/unblob/bin/unblob" --version
semgrep --version --disable-version-check
detect-secrets --version
pip-audit --version
sasquatch -version 2>&1 | head -1
sasquatch-v4be -version 2>&1 | head -1
debugfs -V 2>&1 | head -1
mmls -V
fls -V
icat -V
fsstat -V

if [[ "${CYBER_REQUIRE_RAR5:-0}" == 1 ]]; then
  sudo apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 install -y --no-install-recommends rar
  echo "CYBER_RAR_FIXTURE_EXECUTABLE=$(command -v rar)" >> "$GITHUB_ENV"
  # No customer data or secrets; RAR is only a fixture generator in this runner.
  rar | head -n 3 || true
fi
