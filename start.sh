#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

export PORT="${PORT:-8090}"
export HOST="${HOST:-0.0.0.0}"

mkdir -p "$DIR/data" "$DIR/logs"
echo "🛡️ 正在启动 Cosmo Firewall (http://127.0.0.1:${PORT})..."
exec python3 "$DIR/server.py"
