#!/usr/bin/env bash
#
# Fetch a full set of pprof profiles (heap, goroutine, CPU, block, mutex)
# from a remote nidhogg/Xray host and save them under ./<scope>/.
#
# CPU profile takes CPU_SECONDS (default 30) — wall-clock time of script
# is at least that long. Block and mutex profiles require the process to
# have called runtime.SetBlockProfileRate / SetMutexProfileFraction
# (nidhogg-server and nidhogg-client do this in their main.go pprof block).
#
# Usage:
#   ./collect-pprof.sh HOST SSH_PORT LOGIN PASSWORD SCOPE
#
# Example:
#   ./collect-pprof.sh gateway.example.com 22 root 'hunter2' fresh
#   # ...wait several hours for degradation...
#   ./collect-pprof.sh gateway.example.com 22 root 'hunter2' degraded
#
# Then diff:
#   go tool pprof -diff_base fresh/heap.pprof     degraded/heap.pprof
#   go tool pprof -diff_base fresh/cpu.pprof      degraded/cpu.pprof
#   go tool pprof -diff_base fresh/block.pprof    degraded/block.pprof
#   go tool pprof -diff_base fresh/mutex.pprof    degraded/mutex.pprof
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
  CPU_SECONDS      CPU profile duration in seconds (default 30)
  SKIP_CPU         If 1, skip CPU profile (script runs faster) (default 0)
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
CPU_SECONDS=${CPU_SECONDS:-30}
SKIP_CPU=${SKIP_CPU:-0}

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

echo "[$(date +%H:%M:%S)] fetching block (lock-free if rate not set)"
ssh_remote "curl -sf 'http://$PPROF_HOST:$PPROF_PORT/debug/pprof/block'" > "$SCOPE/block.pprof"

echo "[$(date +%H:%M:%S)] fetching mutex (empty if fraction not set)"
ssh_remote "curl -sf 'http://$PPROF_HOST:$PPROF_PORT/debug/pprof/mutex'" > "$SCOPE/mutex.pprof"

if [[ "$SKIP_CPU" != "1" ]]; then
    echo "[$(date +%H:%M:%S)] sampling CPU for ${CPU_SECONDS}s (this is wall-clock blocking)"
    ssh_remote "curl -sf 'http://$PPROF_HOST:$PPROF_PORT/debug/pprof/profile?seconds=$CPU_SECONDS'" > "$SCOPE/cpu.pprof"
fi

echo
echo "saved:"
ls -lh "$SCOPE"/

echo
echo "next steps:"
echo "  go tool pprof -top      $SCOPE/heap.pprof      | head -20"
echo "  go tool pprof -top      $SCOPE/goroutine.pprof | head -20"
echo "  go tool pprof -top      $SCOPE/cpu.pprof       | head -20"
echo "  go tool pprof -top      $SCOPE/block.pprof     | head -20"
echo "  go tool pprof -top      $SCOPE/mutex.pprof     | head -20"
echo "  go tool pprof -http=:8080 $SCOPE/cpu.pprof     # interactive flamegraph"
echo
echo "diff vs another snapshot:"
echo "  go tool pprof -top -diff_base OTHER/cpu.pprof  $SCOPE/cpu.pprof | head -30"
