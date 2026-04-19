#!/usr/bin/env bash
#
# Fetch heap + goroutine pprof profiles from a remote nidhogg/Xray host
# and save them under ./<scope>/.
#
# Usage:
#   ./collect-pprof.sh HOST SSH_PORT LOGIN PASSWORD SCOPE
#
# Example:
#   ./collect-pprof.sh gateway.example.com 22 root 'hunter2' before-fix
#   ./collect-pprof.sh gateway.example.com 22 root 'hunter2' after-fix
#
# Then diff:
#   go tool pprof -diff_base before-fix/heap.pprof after-fix/heap.pprof
#
# Requires: sshpass (apt install sshpass / brew install hudochenkov/sshpass/sshpass)
#
# pprof is expected to listen on 127.0.0.1:${PPROF_PORT} on the remote host.
# Override the port via env var: PPROF_PORT=6061 ./collect-pprof.sh ...

set -euo pipefail

usage() {
    cat >&2 <<EOF
Usage: $0 HOST SSH_PORT LOGIN PASSWORD SCOPE

  HOST       Remote SSH host
  SSH_PORT   Remote SSH port (typically 22)
  LOGIN      SSH user
  PASSWORD   SSH password (consider SSH keys instead)
  SCOPE      Output directory name (created in current dir, files overwritten)

Env:
  PPROF_PORT       Remote pprof port (default 6060)
  PPROF_HOST       Remote pprof bind addr (default 127.0.0.1)
  HEAP_GC          If 1, request /heap?gc=1 to force GC before snapshot (default 0)
EOF
    exit 1
}

[[ $# -eq 5 ]] || usage

HOST=$1
SSH_PORT=$2
LOGIN=$3
PASSWORD=$4
SCOPE=$5

PPROF_PORT=${PPROF_PORT:-6060}
PPROF_HOST=${PPROF_HOST:-127.0.0.1}
HEAP_GC=${HEAP_GC:-0}

if ! command -v sshpass >/dev/null; then
    echo "error: sshpass not installed" >&2
    echo "  Debian/Ubuntu: apt install sshpass" >&2
    echo "  macOS:         brew install hudochenkov/sshpass/sshpass" >&2
    exit 1
fi

mkdir -p "$SCOPE"

# Quote the password so spaces/specials survive into sshpass; -o StrictHostKey
# disabled to avoid first-connect prompts. Adjust if you care.
ssh_remote() {
    sshpass -p "$PASSWORD" ssh \
        -p "$SSH_PORT" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "$LOGIN@$HOST" "$@"
}

heap_path="/debug/pprof/heap"
[[ "$HEAP_GC" = "1" ]] && heap_path="/debug/pprof/heap?gc=1"

echo "[$(date +%H:%M:%S)] fetching heap from $HOST (pprof $PPROF_HOST:$PPROF_PORT)"
ssh_remote "curl -sf 'http://$PPROF_HOST:$PPROF_PORT$heap_path'" > "$SCOPE/heap.pprof"

echo "[$(date +%H:%M:%S)] fetching goroutine"
ssh_remote "curl -sf 'http://$PPROF_HOST:$PPROF_PORT/debug/pprof/goroutine'" > "$SCOPE/goroutine.pprof"

echo
echo "saved:"
ls -lh "$SCOPE"/heap.pprof "$SCOPE"/goroutine.pprof

echo
echo "next steps:"
echo "  go tool pprof -top      $SCOPE/heap.pprof      | head -20"
echo "  go tool pprof -top      $SCOPE/goroutine.pprof | head -20"
echo "  go tool pprof -http=:8080 $SCOPE/heap.pprof    # interactive UI"
