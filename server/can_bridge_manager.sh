#!/bin/bash
#
# can_bridge_manager.sh
#  - Start/stop CAN ↔ TCP bridges (canip_peer.py server) for can0..can3
#  - Uses can_usb_manage.sh to bring CAN interfaces up first
#
# Usage:
#   sudo can_bridge_manager.sh start
#   sudo can_bridge_manager.sh stop
#   sudo can_bridge_manager.sh restart
#   sudo can_bridge_manager.sh status
#

CANIP_DIR="/home/pi/CAN_IP"
CANIP_PY="${CANIP_DIR}/canip_peer.py"

BASE_PORT=3333      # can0 -> 3333, can1 -> 3334, ...
MAX_BRIDGES=4       # can0..can3
PID_DIR="/run/can-bridges"

log() {
  echo "[can_bridge] $*"
}

get_can_devs() {
  ip -o link show type can 2>/dev/null \
    | awk -F': ' '{print $2}' \
    | grep -E '^can[0-3]$' \
    | sort
}

ensure_pid_dir() {
  mkdir -p "$PID_DIR"
}

start_bridges() {
  log "Starting CAN↔TCP bridges..."

  # 1) Ensure CAN is configured and up (clean restart)
  if command -v can_usb_manage.sh >/dev/null 2>&1; then
    log "Calling can_usb_manage.sh restart..."
    /usr/local/bin/can_usb_manage.sh restart || true
  else
    log "Warning: can_usb_manage.sh not found, continuing anyway"
  fi

  ensure_pid_dir

  mapfile -t devs < <(get_can_devs)
  local count=${#devs[@]}

  if (( count == 0 )); then
    log "No CAN interfaces found; nothing to bridge."
    return 0
  fi

  log "Found CAN interfaces: ${devs[*]}"

  local i=0
  local dev port
  for dev in "${devs[@]}"; do
    if (( i >= MAX_BRIDGES )); then
      log "Reached MAX_BRIDGES=$MAX_BRIDGES; ignoring extra device $dev"
      continue
    fi
    port=$((BASE_PORT + i))
    log "Starting canip_peer server for $dev on TCP port $port"

    # Run the server as user 'pi' (or change to your preferred user)
    sudo -u pi bash -c "
      cd '$CANIP_DIR'
      nohup python3 '$CANIP_PY' server \
        --can '$dev' \
        --port '$port' \
        --log-level INFO \
        > /tmp/can_bridge_${dev}.log 2>&1 &
      echo \$!
    " > "$PID_DIR/can_bridge_${dev}.pid"

    ((i++))
  done

  log "Started $i bridge(s)."
}

stop_bridges() {
  log "Stopping CAN↔TCP bridges..."
  if [[ ! -d "$PID_DIR" ]]; then
    log "No PID directory; nothing to stop."
    return 0
  fi

  local pidfile pid
  for pidfile in "$PID_DIR"/can_bridge_*.pid; do
    [[ -e "$pidfile" ]] || continue
    pid=$(cat "$pidfile" 2>/dev/null || echo "")
    if [[ -n "$pid" ]]; then
      log "Killing PID $pid from $(basename "$pidfile")"
      kill "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  done
}

status_bridges() {
  log "Bridge PIDs in $PID_DIR:"
  if [[ -d "$PID_DIR" ]]; then
    ls -1 "$PID_DIR" 2>/dev/null || echo "  (none)"
  else
    echo "  (no PID directory)"
  fi
}

case "${1:-}" in
  start)
    start_bridges
    ;;
  stop)
    stop_bridges
    ;;
  restart)
    stop_bridges
    start_bridges
    ;;
  status)
    status_bridges
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}" >&2
    exit 1
    ;;
esac

