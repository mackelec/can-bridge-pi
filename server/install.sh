#!/bin/bash
#
# install.sh
#  - Install CAN bridge server components on a Raspberry Pi
#  - Copies scripts, installs systemd unit, bundles canip_peer.py
#  - Optionally sets hostname and ensures Avahi is running
#

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$REPO_DIR"
SERVICE_NAME="can-bridge.service"

log() {
  echo "[install] $*"
}

detect_user() {
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    echo "$SUDO_USER"
  else
    # Fallback if run as root without sudo
    echo "pi"
  fi
}

install_canip_peer() {
  local user home dir

  user="$(detect_user)"
  home="/home/${user}"
  dir="${home}/CAN_IP"

  log "Using user: ${user}"
  log "Creating CAN_IP directory at: ${dir}"
  mkdir -p "$dir"

  if [[ ! -f "${SERVER_DIR}/canip_peer.py" ]]; then
    log "ERROR: ${SERVER_DIR}/canip_peer.py not found."
    log "Please ensure canip_peer.py is present in the server directory."
    exit 1
  fi

  log "Copying canip_peer.py to ${dir}"
  cp "${SERVER_DIR}/canip_peer.py" "${dir}/canip_peer.py"
  chown -R "${user}:${user}" "$dir"
}

install_scripts() {
  log "Installing scripts to /usr/local/bin"

  cp "${SERVER_DIR}/can_usb_manage.sh" /usr/local/bin/can_usb_manage.sh
  cp "${SERVER_DIR}/can_bridge_manager.sh" /usr/local/bin/can_bridge_manager.sh

  chmod +x /usr/local/bin/can_usb_manage.sh
  chmod +x /usr/local/bin/can_bridge_manager.sh
}

install_service() {
  log "Installing systemd service ${SERVICE_NAME}"

  cp "${SERVER_DIR}/${SERVICE_NAME}" "/etc/systemd/system/${SERVICE_NAME}"
  systemctl daemon-reload

  log "Service installed. You can enable at boot with:"
  log "  sudo systemctl enable ${SERVICE_NAME}"
}

ensure_avahi() {
  log "Ensuring avahi-daemon is installed and running"
  if ! dpkg -s avahi-daemon >/dev/null 2>&1; then
    log "Installing avahi-daemon..."
    apt-get update
    apt-get install -y avahi-daemon
  fi
  systemctl enable --now avahi-daemon
}

maybe_set_hostname() {
  echo
  read -r -p "Do you want to set a network hostname for this CAN bridge Pi? [y/N]: " ans
  case "$ans" in
    y|Y)
      read -r -p "Enter hostname (letters, digits, hyphen; e.g. mgzs-can01): " newhost
      if [[ -z "$newhost" ]]; then
        log "No hostname entered; skipping hostname change."
        return
      fi
      log "Setting hostname to: ${newhost}"
      hostnamectl set-hostname "$newhost"
      ensure_avahi
      echo
      log "Hostname set. This Pi should be reachable as: ${newhost}.local"
      log "A reboot is recommended so all tools see the new name cleanly."
      ;;
    *)
      log "Leaving hostname unchanged."
      ;;
  esac
}

main() {
  if [[ "$EUID" -ne 0 ]]; then
    echo "Please run as root, e.g. with: sudo ./install.sh" >&2
    exit 1
  fi

  log "Starting CAN bridge Pi installation"

  install_canip_peer
  install_scripts
  install_service
  maybe_set_hostname

  echo
  log "Installation complete."
  echo
  echo "You can now control the bridge with:"
  echo "  sudo systemctl start can-bridge"
  echo "  sudo systemctl stop  can-bridge"
  echo "  sudo systemctl status can-bridge"
  echo
}

main "$@"

