#!/usr/bin/env bash
# install.sh — one-command installer for StrongSwan Manager
#
# Usage:  sudo bash install.sh [--port PORT] [--host HOST]
#
# Requires: Debian/Ubuntu Linux, Python 3.9+, strongSwan installed.
# Tested on: Ubuntu 22.04 / 24.04 with StrongSwan 5.x / 6.x.

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }

# ── Root guard ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Please run as root:  sudo bash install.sh"

# ── Defaults / argument parsing ───────────────────────────────────────────────
BIND="0.0.0.0"
PORT=8000
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) PORT="$2"; shift 2 ;;
        --host) BIND="$2"; shift 2 ;;
        *) die "Unknown option: $1  (supported: --port N  --host IP)" ;;
    esac
done

# ── Paths ─────────────────────────────────────────────────────────────────────
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${INSTALL_DIR}/env"
PYTHON="${VENV}/bin/python"
PIP="${VENV}/bin/pip"
DAPHNE="${VENV}/bin/daphne"
MANAGE="${PYTHON} ${INSTALL_DIR}/manage.py"
SETTINGS="strongswan_manager.settings.production"
SERVICE_NAME="strongswan-manager"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

echo
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}   StrongSwan Manager — Installation${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo

# ── Step 1: Check Python ──────────────────────────────────────────────────────
info "Checking Python version..."
PY_BIN=$(command -v python3) || die "python3 not found. Install Python 3.9+."
PY_VER=$("${PY_BIN}" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MIN=$("${PY_BIN}" -c "import sys; print(0 if sys.version_info >= (3,9) else 1)")
[[ "${PY_MIN}" -eq 0 ]] || die "Python 3.9+ required (found ${PY_VER})."
PY_MINOR=$("${PY_BIN}" -c "import sys; print(sys.version_info.minor)")
ok "Python ${PY_VER}"

# ── Step 2: Ensure python3-venv is available ──────────────────────────────────
info "Checking python3-venv..."
if ! "${PY_BIN}" -c "import ensurepip" 2>/dev/null; then
    warn "python3-venv not found — installing via apt..."
    apt-get update -qq
    apt-get install -y -qq "python3.${PY_MINOR}-venv" \
        || apt-get install -y -qq python3-venv \
        || die "Could not install python3-venv. Run:  apt install python3-venv"
fi
ok "python3-venv available"

# ── Step 3: Create (or reuse) virtual environment ────────────────────────────
if [[ -d "${VENV}" && -x "${PYTHON}" ]]; then
    ok "Reusing existing virtual environment at ${VENV}"
else
    info "Creating virtual environment at ${VENV}..."
    "${PY_BIN}" -m venv "${VENV}" || die "Failed to create virtual environment."
    ok "Virtual environment created"
fi

# ── Step 4: Install Python dependencies ──────────────────────────────────────
info "Upgrading pip..."
"${PIP}" install --quiet --upgrade pip

info "Installing Python dependencies (this may take a minute)..."
"${PIP}" install --quiet -r "${INSTALL_DIR}/requirements.txt" \
    || die "pip install failed. Check network connectivity and ${INSTALL_DIR}/requirements.txt."
ok "Dependencies installed"

# ── Step 5: Run database migrations ──────────────────────────────────────────
info "Running database migrations..."
cd "${INSTALL_DIR}"
DJANGO_SETTINGS_MODULE="${SETTINGS}" ${MANAGE} migrate --run-syncdb \
    || die "Database migration failed."
ok "Migrations complete"

# ── Step 6: Collect static files ─────────────────────────────────────────────
info "Collecting static files..."
DJANGO_SETTINGS_MODULE="${SETTINGS}" ${MANAGE} collectstatic --noinput \
    || die "collectstatic failed."
ok "Static files collected"

# ── Step 7: Create admin user ─────────────────────────────────────────────────
info "Checking for existing admin users..."
USER_EXISTS=$(DJANGO_SETTINGS_MODULE="${SETTINGS}" ${MANAGE} shell \
    -c "from django.contrib.auth import get_user_model; \
        U=get_user_model(); print('yes' if U.objects.filter(is_superuser=True).exists() else 'no')" \
    2>/dev/null || echo "no")

if [[ "${USER_EXISTS}" == "yes" ]]; then
    ok "Admin user already exists — skipping."
else
    echo
    echo -e "${BOLD}Create an admin account for the web interface:${NC}"
    read -rp "  Username [admin]: " ADMIN_USER
    ADMIN_USER="${ADMIN_USER:-admin}"

    while true; do
        read -rsp "  Password: " ADMIN_PASS; echo
        [[ ${#ADMIN_PASS} -ge 8 ]] && break
        warn "Password must be at least 8 characters. Try again."
    done
    read -rsp "  Confirm password: " ADMIN_PASS2; echo
    [[ "${ADMIN_PASS}" == "${ADMIN_PASS2}" ]] || die "Passwords do not match."

    DJANGO_SETTINGS_MODULE="${SETTINGS}" ${MANAGE} shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
User.objects.create_superuser('${ADMIN_USER}', '', '${ADMIN_PASS}')
" || die "Failed to create admin user."
    ok "Admin user '${ADMIN_USER}' created"
fi

# ── Step 8: Import existing strongSwan configuration ─────────────────────────
if command -v swanctl >/dev/null 2>&1; then
    info "Importing existing strongSwan configuration..."
    if DJANGO_SETTINGS_MODULE="${SETTINGS}" ${MANAGE} import_strongswan_config 2>&1; then
        ok "StrongSwan configuration imported"
    else
        warn "Config import finished with warnings (non-fatal — tunnels can be added via the GUI)."
    fi
else
    warn "swanctl not found — skipping config import. Is strongSwan installed?"
fi

# ── Step 9: Install systemd service ──────────────────────────────────────────
info "Installing systemd service (${SERVICE_NAME})..."

cat > "${SERVICE_FILE}" << UNIT
[Unit]
Description=StrongSwan Manager web GUI
Documentation=https://github.com/strongswan/strongman
After=network.target strongswan-swanctl.service
Wants=strongswan-swanctl.service

[Service]
Type=simple
Environment=DJANGO_SETTINGS_MODULE=${SETTINGS}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${DAPHNE} -b ${BIND} -p ${PORT} strongswan_manager.asgi:application
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"
ok "Service '${SERVICE_NAME}' enabled and started"

# ── Step 10: Firewall hint ────────────────────────────────────────────────────
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    if ! ufw status | grep -q "${PORT}"; then
        warn "UFW is active. To allow access run:  ufw allow ${PORT}/tcp"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
# Use the source IP of the default route (the outward-facing interface).
# Falls back to hostname -I first result, then localhost.
PRIMARY_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' | head -1)
[[ -z "$PRIMARY_IP" ]] && PRIMARY_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[[ -z "$PRIMARY_IP" ]] && PRIMARY_IP="localhost"

echo
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}   Installation complete!${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo
echo -e "  Web UI:   ${BOLD}http://${PRIMARY_IP}:${PORT}${NC}"
if [[ "${USER_EXISTS}" != "yes" ]]; then
    echo -e "  Username: ${BOLD}${ADMIN_USER}${NC}"
fi
echo
echo "  Service management:"
echo "    systemctl status  ${SERVICE_NAME}"
echo "    systemctl restart ${SERVICE_NAME}"
echo "    journalctl -u ${SERVICE_NAME} -f"
echo
echo -e "${YELLOW}  Tip: Change your admin password via the web UI after first login.${NC}"
echo
