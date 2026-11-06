#!/usr/bin/env bash
# Cross-Platform Linux CLI Installer for QKD-SDWAN Central Controller
set -euo pipefail

PREFIX="/opt/qkd-sdwan-controller"
if [[ "$(id -u)" -ne 0 ]]; then
  PREFIX="${HOME}/.local/share/qkd-sdwan-controller"
fi
HOST="0.0.0.0"
PORT="8080"
SUBNET_PREFIX="10.200.0."
BOOTSTRAP_TOKEN=""
NON_INTERACTIVE=0
EXPLICIT_FLAGS=0

usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Install the QKD-SDWAN Central Controller (portable .pyz bundle, CLI Dashboard, token manager, and systemd unit).

Options:
  --prefix <path>            Installation root directory (default: ${PREFIX})
  --host <ip>                Controller HTTP bind address (default: ${HOST})
  --port <port>              Controller HTTP bind port (default: ${PORT})
  --subnet-prefix <prefix>   Overlay IPv4 /24 prefix (default: ${SUBNET_PREFIX})
  --bootstrap-token <token>  Initial Join Token for client auto-enrollment (auto-generated if omitted)
  --non-interactive          Run unattended without interactive CLI prompts
  -h, --help                 Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      PREFIX="$2"
      EXPLICIT_FLAGS=1
      shift 2
      ;;
    --host)
      HOST="$2"
      EXPLICIT_FLAGS=1
      shift 2
      ;;
    --port)
      PORT="$2"
      EXPLICIT_FLAGS=1
      shift 2
      ;;
    --subnet-prefix)
      SUBNET_PREFIX="$2"
      EXPLICIT_FLAGS=1
      shift 2
      ;;
    --bootstrap-token)
      BOOTSTRAP_TOKEN="$2"
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
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "${NON_INTERACTIVE}" -eq 0 && "${EXPLICIT_FLAGS}" -eq 0 && -t 0 ]]; then
  echo "================================================================================"
  echo " QKD-SDWAN Central Controller — Interactive Linux CLI Installer Wizard"
  echo "================================================================================"
  read -r -p "Installation directory [${PREFIX}]: " input_prefix
  PREFIX="${input_prefix:-${PREFIX}}"
  read -r -p "Controller bind host IP [${HOST}]: " input_host
  HOST="${input_host:-${HOST}}"
  read -r -p "Controller HTTP port [${PORT}]: " input_port
  PORT="${input_port:-${PORT}}"
  read -r -p "Overlay IPv4 /24 prefix [${SUBNET_PREFIX}]: " input_subnet
  SUBNET_PREFIX="${input_subnet:-${SUBNET_PREFIX}}"
  read -r -p "Bootstrap Join Token (leave blank to auto-generate): " input_token
  BOOTSTRAP_TOKEN="${input_token:-${BOOTSTRAP_TOKEN}}"
  echo "--------------------------------------------------------------------------------"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[1/4] Checking system prerequisites..."
if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is required but not found in PATH." >&2
  exit 1
fi
PYTHON_BIN="$(command -v python3)"
echo "      Python runtime : ${PYTHON_BIN}"
if ! "${PYTHON_BIN}" -c "import cryptography" >/dev/null 2>&1; then
  echo "      Installing required Python package 'cryptography'..."
  "${PYTHON_BIN}" -m pip install --disable-pip-version-check --user cryptography || \
    "${PYTHON_BIN}" -m pip install --disable-pip-version-check --break-system-packages cryptography || \
    "${PYTHON_BIN}" -m pip install --disable-pip-version-check cryptography
fi

echo "[2/4] Preparing controller directories under ${PREFIX}..."
mkdir -p "${PREFIX}/bin" "${PREFIX}/etc" "${PREFIX}/lib"

PYZ_SRC=""
if [[ -f "${SCRIPT_DIR}/qkd-sdwan-controller.pyz" ]]; then
  PYZ_SRC="${SCRIPT_DIR}/qkd-sdwan-controller.pyz"
elif [[ -f "${REPO_ROOT}/dist/qkd-sdwan-controller.pyz" ]]; then
  PYZ_SRC="${REPO_ROOT}/dist/qkd-sdwan-controller.pyz"
elif [[ -f "${REPO_ROOT}/scripts/build_installers.py" ]]; then
  "${PYTHON_BIN}" "${REPO_ROOT}/scripts/build_installers.py" >/dev/null
  PYZ_SRC="${REPO_ROOT}/dist/qkd-sdwan-controller.pyz"
fi

PYZ_DEST="${PREFIX}/lib/qkd-sdwan-controller.pyz"
if [[ -n "${PYZ_SRC}" && -f "${PYZ_SRC}" ]]; then
  cp -f "${PYZ_SRC}" "${PYZ_DEST}"
  chmod +x "${PYZ_DEST}"
fi

echo "[3/4] Generating cluster HMAC secret, bootstrap Join Token, and controller.json..."
export PYTHONPATH="${PYZ_DEST}:${REPO_ROOT}:${PYTHONPATH:-}"
CONFIG_PATH="${PREFIX}/etc/controller.json"
TOKEN_INFO="$("${PYTHON_BIN}" -m qkd_sdwan.controller.cli init-config \
  --output "${CONFIG_PATH}" \
  --host "${HOST}" \
  --port "${PORT}" \
  --subnet-prefix "${SUBNET_PREFIX}" \
  --bootstrap-token "${BOOTSTRAP_TOKEN}")"
chmod 600 "${CONFIG_PATH}"

echo "[4/4] Installing CLI wrappers (qkd-sdwan-controller, qkd-sdwan-ctl) and systemd service..."
CONTROLLER_BIN="${PREFIX}/bin/qkd-sdwan-controller"
cat > "${CONTROLLER_BIN}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="${PYZ_DEST}:${REPO_ROOT}:\${PYTHONPATH:-}"
export QKD_SDWAN_CONTROLLER_CONFIG="${CONFIG_PATH}"
exec "${PYTHON_BIN}" -m qkd_sdwan.controller.cli --config "${CONFIG_PATH}" "\$@"
EOF
chmod +x "${CONTROLLER_BIN}"

CTL_BIN="${PREFIX}/bin/qkd-sdwan-ctl"
cat > "${CTL_BIN}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="${PYZ_DEST}:${REPO_ROOT}:\${PYTHONPATH:-}"
export QKD_SDWAN_CONTROLLER_CONFIG="${CONFIG_PATH}"
exec "${PYTHON_BIN}" -m qkd_sdwan.controller.cli --config "${CONFIG_PATH}" "\$@"
EOF
chmod +x "${CTL_BIN}"

SERVICE_PATH="${PREFIX}/qkd-sdwan-controller.service"
cat > "${SERVICE_PATH}" <<EOF
[Unit]
Description=QKD-SDWAN Central Controller (BB84 QKD + Isolation Forest ML Routing)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${CONTROLLER_BIN} serve --config ${CONFIG_PATH}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

echo "[OK] QKD-SDWAN Central Controller installed successfully:"
echo "     Configuration       : ${CONFIG_PATH}"
echo "     Portable Bundle     : ${PYZ_DEST}"
echo "     Controller CLI      : ${CONTROLLER_BIN}"
echo "     Dashboard Command   : ${CONTROLLER_BIN} dashboard --controller-url http://127.0.0.1:${PORT}"
echo "     Bootstrap Join Token: ${TOKEN_INFO}"
