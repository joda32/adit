#!/usr/bin/env bash
# Wrapper that enables OpenSSL's legacy provider (impacket's NTLM needs MD4,
# which OpenSSL 3 disables by default) and runs the given seed script.
#   ./run.sh seed.py      # introduce misconfigurations
#   ./run.sh revert.py    # undo them
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export OPENSSL_CONF="$HERE/openssl-legacy.cnf"
exec python3 "$HERE/${1:-seed.py}"
