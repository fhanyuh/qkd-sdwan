#!/usr/bin/env bash
# Cross-Platform Linux CLI Installer for QKD-SDWAN Endpoint Client
set -euo pipefail

PREFIX="/etc/qkd-sdwan"
if [[ "$(id -u)" -ne 0 ]]; then
  PREFIX="${HOME}/.local/share/qkd-sdwan-client"
fi
NODE_ID="edge-node-01"
OVERLAY_IP="10.200.0.10"
CONTROLLER_URL="http://127.0.0.1:8080"
JOIN_TOKEN=""
WG_PORT="51820"
QKD_PORT="52820"
INTERFACE_NAME="wg-qkd0"
NON_INTERACTIVE=0
EXPLICIT_FLAGS=0
EXPLICIT_IP=0

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Install the QKD-SDWAN Endpoint Client (portable .pyz bundle, CLI client console, and systemd unit).

Options:
  --prefix <dir>           Installation root prefix (default: ${PREFIX})
  --node-id <id>           Unique SD-WAN endpoint node ID (default: ${NODE_ID})
  --overlay-ip <ip>        WireGuard P2P overlay IPv4 address (default: ${OVERLAY_IP})
  --controller-url <url>   Central ML Controller URL (default: ${CONTROLLER_URL})
  --join-token <token>     Optional Controller Join Token for automatic token-based enrollment
  --wg-port <port>         WireGuard UDP listen port (default: ${WG_PORT})
  --qkd-port <port>        BB84 QKD TCP socket port (default: ${QKD_PORT})
  --interface <name>       WireGuard interface name (default: ${INTERFACE_NAME})
  --non-interactive        Run unattended without interactive CLI prompts
  -h, --help               Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      PREFIX="$2"
      EXPLICIT_FLAGS=1
      shift 2
      ;;
    --node-id)
      NODE_ID="$2"
      EXPLICIT_FLAGS=1
      shift 2
      ;;
    --overlay-ip)
      OVERLAY_IP="$2"
      EXPLICIT_FLAGS=1
      EXPLICIT_IP=1
      shift 2
      ;;
    --controller-url)
      CONTROLLER_URL="$2"
      EXPLICIT_FLAGS=1
      shift 2
      ;;
    --join-token)
      JOIN_TOKEN="$2"
      EXPLICIT_FLAGS=1
      shift 2
      ;;
    --wg-port)
      WG_PORT="$2"
      EXPLICIT_FLAGS=1
      shift 2
      ;;
    --qkd-port)
      QKD_PORT="$2"
      EXPLICIT_FLAGS=1
      shift 2
      ;;
    --interface)
      INTERFACE_NAME="$2"
      EXPLICIT_FLAGS=1
      shift 2
      ;;
    --non-interactive)
      NON_INTERACTIVE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[ERROR] Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "${NON_INTERACTIVE}" -eq 0 && "${EXPLICIT_FLAGS}" -eq 0 && -t 0 ]]; then
  echo "================================================================================"
  echo " QKD-SDWAN Endpoint Client -- Interactive Linux CLI Installer Wizard"
  echo "================================================================================"
  read -r -p "Installation directory [${PREFIX}]: " input_prefix
  PREFIX="${input_prefix:-${PREFIX}}"
  read -r -p "Endpoint Node ID [${NODE_ID}]: " input_id
  NODE_ID="${input_id:-${NODE_ID}}"
  read -r -p "Central Controller URL [${CONTROLLER_URL}]: " input_ctrl
  CONTROLLER_URL="${input_ctrl:-${CONTROLLER_URL}}"
  read -r -p "Enrollment Join Token (optional): " input_tok
  JOIN_TOKEN="${input_tok:-${JOIN_TOKEN}}"
  if [[ -z "${JOIN_TOKEN}" ]]; then
    read -r -p "Overlay IPv4 address [${OVERLAY_IP}]: " input_ip
    if [[ -n "${input_ip}" ]]; then
      OVERLAY_IP="${input_ip}"
      EXPLICIT_IP=1
    fi
  fi
  read -r -p "WireGuard UDP port [${WG_PORT}]: " input_wg
  WG_PORT="${input_wg:-${WG_PORT}}"
  read -r -p "BB84 QKD TCP port [${QKD_PORT}]: " input_qkd
  QKD_PORT="${input_qkd:-${QKD_PORT}}"
  echo "--------------------------------------------------------------------------------"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[1/4] Checking system prerequisites..."
if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 is required but not installed." >&2
  exit 1
fi

PYTHON_BIN="$(command -v python3)"
WG_MODE="USERSPACE_CRYPTO_WG"
if command -v wg >/dev/null 2>&1 && [[ "$(id -u)" -eq 0 ]]; then
  WG_MODE="KERNEL_WG"
fi
echo "      Python runtime : ${PYTHON_BIN}"
echo "      WireGuard mode : ${WG_MODE}"
if ! "${PYTHON_BIN}" -c "import cryptography" >/dev/null 2>&1; then
  echo "      Installing required Python package 'cryptography'..."
  "${PYTHON_BIN}" -m pip install --disable-pip-version-check --user cryptography || \
    "${PYTHON_BIN}" -m pip install --disable-pip-version-check --break-system-packages cryptography || \
    "${PYTHON_BIN}" -m pip install --disable-pip-version-check cryptography
fi

echo "[2/4] Creating endpoint directories under ${PREFIX}..."
mkdir -p "${PREFIX}/etc" "${PREFIX}/bin" "${PREFIX}/lib"

PYZ_SRC=""
if [[ -f "${SCRIPT_DIR}/qkd-sdwan-client.pyz" ]]; then
  PYZ_SRC="${SCRIPT_DIR}/qkd-sdwan-client.pyz"
elif [[ -f "${REPO_ROOT}/dist/qkd-sdwan-client.pyz" ]]; then
  PYZ_SRC="${REPO_ROOT}/dist/qkd-sdwan-client.pyz"
elif [[ -f "${REPO_ROOT}/scripts/build_installers.py" ]]; then
  "${PYTHON_BIN}" "${REPO_ROOT}/scripts/build_installers.py" >/dev/null
  PYZ_SRC="${REPO_ROOT}/dist/qkd-sdwan-client.pyz"
fi

PYZ_DEST="${PREFIX}/lib/qkd-sdwan-client.pyz"
if [[ -n "${PYZ_SRC}" && -f "${PYZ_SRC}" ]]; then
  cp -f "${PYZ_SRC}" "${PYZ_DEST}"
  chmod +x "${PYZ_DEST}"
fi

echo "[3/4] Configuring endpoint identity, WireGuard keypair, and Controller enrollment..."
export PYTHONPATH="${PYZ_DEST}:${REPO_ROOT}:${PYTHONPATH:-}"
CONFIG_PATH="${PREFIX}/etc/endpoint.json"

INIT_EXTRA_ARGS=()
if [[ "${EXPLICIT_IP}" -eq 1 ]]; then
  INIT_EXTRA_ARGS+=("--explicit-ip")
fi
"${PYTHON_BIN}" -m qkd_sdwan.client.agent init-config \
  --output "${CONFIG_PATH}" \
  --node-id "${NODE_ID}" \
  --overlay-ip "${OVERLAY_IP}" \
  --controller-url "${CONTROLLER_URL}" \
  --join-token "${JOIN_TOKEN}" \
  --wg-port "${WG_PORT}" \
  --qkd-port "${QKD_PORT}" \
  --interface "${INTERFACE_NAME}" \
  --backend-mode "${WG_MODE}" \
  "${INIT_EXTRA_ARGS[@]}"
chmod 600 "${CONFIG_PATH}"

echo "[4/4] Installing CLI wrappers (qkd-sdwan-client, qkd-sdwan-agent) and systemd service..."
CLIENT_BIN="${PREFIX}/bin/qkd-sdwan-client"
cat > "${CLIENT_BIN}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="${PYZ_DEST}:${REPO_ROOT}:\${PYTHONPATH:-}"
export QKD_SDWAN_CLIENT_CONFIG="${CONFIG_PATH}"
exec "${PYTHON_BIN}" -m qkd_sdwan.client.agent --config "${CONFIG_PATH}" "\$@"
EOF
chmod +x "${CLIENT_BIN}"

AGENT_BIN="${PREFIX}/bin/qkd-sdwan-agent"
cat > "${AGENT_BIN}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="${PYZ_DEST}:${REPO_ROOT}:\${PYTHONPATH:-}"
export QKD_SDWAN_CLIENT_CONFIG="${CONFIG_PATH}"
exec "${PYTHON_BIN}" -m qkd_sdwan.client.agent --config "${CONFIG_PATH}" "\$@"
EOF
chmod +x "${AGENT_BIN}"

SERVICE_PATH="${PREFIX}/qkd-sdwan-client.service"
cat > "${SERVICE_PATH}" <<EOF
[Unit]
Description=Distributed QKD-SDWAN Endpoint Agent (${NODE_ID})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment="PYTHONPATH=${PYZ_DEST}:${REPO_ROOT}"
ExecStart=${CLIENT_BIN} --config ${CONFIG_PATH}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

echo "[OK] QKD-SDWAN Endpoint Client installed successfully:"
echo "     Configuration : ${CONFIG_PATH}"
echo "     Portable Bundle: ${PYZ_DEST}"
echo "     Client CLI    : ${CLIENT_BIN}"
echo "     Agent Wrapper : ${AGENT_BIN}"
echo "     Systemd Unit  : ${SERVICE_PATH}"
