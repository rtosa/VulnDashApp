#!/usr/bin/with-contenv bashio
set -e

if [ -f /data/options.json ]; then
  export HISTORY_YEARS="$(bashio::config 'history_years')"
  export SYNC_INTERVAL_HOURS="$(bashio::config 'sync_interval_hours')"
fi

export DATA_DIR="${DATA_DIR:-/data}"
export HOST="${HOST:-0.0.0.0}"
export PORT="${PORT:-8099}"
export HA_INGRESS="${HA_INGRESS:-0}"

exec python3 /app/server.py
