#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROJECT_DIR}/.venv"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 was not found. Install python3 and python3-venv, then retry." >&2
    exit 1
fi

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    echo "Python 3.10 or newer is required." >&2
    exit 1
fi

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    python3 -m venv "${VENV_DIR}"
fi

if ! "${VENV_DIR}/bin/python" -c "import fastapi, uvicorn, websockets" >/dev/null 2>&1; then
    "${VENV_DIR}/bin/python" -m pip install -r "${PROJECT_DIR}/requirements.txt"
fi

export NETPLUS_GATEWAY_IP="${NETPLUS_GATEWAY_IP:-10.42.0.1}"
export NETPLUS_CLIENT_NETWORK="${NETPLUS_CLIENT_NETWORK:-10.42.0.0/24}"

echo "NetPlus dashboard: http://127.0.0.1:5000"
echo "Hotspot proxy:     ${NETPLUS_GATEWAY_IP}:8080"
echo "Client network:    ${NETPLUS_CLIENT_NETWORK}"
echo "Use Ctrl+C to stop NetPlus."
cd "${PROJECT_DIR}"
exec "${VENV_DIR}/bin/python" server.py
