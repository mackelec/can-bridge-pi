#!/bin/bash
#
# can_usb_manage.sh
#  - Manage USB→CAN adapters as SocketCAN interfaces can0..can3
#  - Stable mapping based on USB path, with optional bitrate setting
#
# Usage:
#   sudo can_usb_manage.sh start [bitrate]
#   sudo can_usb_manage.sh stop
#   sudo can_usb_manage.sh restart [bitrate]
#   sudo can_usb_manage.sh status
#

LOG_PREFIX="[can_usb_manage]"

log() {
  echo "${LOG_PREFIX} $*"
}

usage() {
  echo "Usage: $0 {start|stop|restart|status} [bitrate]" >&2
  exit 1
}

# Map known USB paths to preferred slot index
# Adjust/extend these if your hardware topology changes.
preferred_slot_for_path() {
  local path="$1"
  case "$path" in
    *1-1.5*) echo 0 ;;  # e.g. bottom-right port
    *1-1.3*) echo 1 ;;
    *1-1.2*) echo 2 ;;
    *1-1.1*) echo 3 ;;
    *)       echo -1 ;;
  esac
}

# Find all "net/can*" entries under USB devices
discover_usb_can() {
  find /sys/devices -path "*usb*/net/can*" 2>/dev/null | sort
}

stop_all_can() {
  log "Stopping (tearing down) all CAN interfaces"
  local dev
  while read -r dev _; do
    [[ -z "$dev" ]] && continue
    log "Bringing down $dev"
    ip link set "$dev" down 2>/dev/null || true
  done < <(ip -o link show type can)
}

configure_can_dev() {
  local dev="$1"
  local bitrate="$2"

  log "Configuring $dev at bitrate $bitrate"
  ip link set "$dev" down 2>/dev/null || true
  ip link set "$dev" type can bitrate "$bitrate" restart-ms 100 || true
  ip link set "$dev" up || true
}

start_can() {
  local bitrate="${1:-500000}"
  log "Starting CAN-USB with bitrate=${bitrate}"

  local entries path dev slot
  mapfile -t entries < <(discover_usb_can)

  if ((${#entries[@]} == 0)); then
    log "No USB CAN interfaces found."
    return 0
  fi

  stop_all_can

  declare -A dev_for_slot
  declare -A path_for_slot

  for sys_entry in "${entries[@]}"; do
    dev=$(basename "$sys_entry")
    path=$(dirname "$sys_entry")
    path=$(dirname "$path")
    slot=$(preferred_slot_for_path "$path")
    log "$dev is on USB path $path -> preferred slot $slot"

    if ((slot >= 0 && slot <= 3)); then
      dev_for_slot["$slot"]="$dev"
      path_for_slot["$slot"]="$path"
    else
      log "Ignoring $dev on unrecognised USB path $path"
    fi
  done

  declare -A renamed
  local i tmp
  for i in 0 1 2 3; do
    dev="${dev_for_slot[$i]:-}"
    [[ -z "$dev" ]] && continue

    if [[ "$dev" =~ ^can[0-9]+$ && "$dev" != "can${i}" ]]; then
      tmp="can${i}_old_$$"
      log "Renaming existing ${dev} -> ${tmp} to free the name"
      ip link set "$dev" down 2>/dev/null || true
      ip link set "$dev" name "$tmp" 2>/dev/null || true
      renamed["$dev"]="$tmp"
      dev="${tmp}"
      dev_for_slot["$i"]="$dev"
    fi
  done

  for i in 0 1 2 3; do
    dev="${dev_for_slot[$i]:-}"
    [[ -z "$dev" ]] && continue

    if [[ "$dev" != "can${i}" ]]; then
      log "Renaming ${dev} -> can${i}"
      ip link set "$dev" down 2>/dev/null || true
      ip link set "$dev" name "can${i}" 2>/dev/null || true
      dev="can${i}"
      dev_for_slot["$i"]="$dev"
    fi

    configure_can_dev "$dev" "$bitrate"
  done
}

status_can() {
  log "Current CAN interfaces:"
  ip -br link show type can || true
}

case "${1:-}" in
  start)
    shift
    start_can "$@"
    ;;
  stop)
    stop_all_can
    ;;
  restart)
    shift
    start_can "$@"
    ;;
  status)
    status_can
    ;;
  *)
    usage
    ;;
esac

