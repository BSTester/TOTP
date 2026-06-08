#!/bin/sh
set -e

DATA_DIR="${APP_DB_PATH:-/data/data.db}"
DATA_DIR="$(dirname "$DATA_DIR")"
KEY_FILE="${APP_MASTER_KEY_FILE:-/data/.master_key}"
KEY_DIR="$(dirname "$KEY_FILE")"

mkdir -p "$DATA_DIR" "$KEY_DIR"
chown -R appuser:appuser "$DATA_DIR" "$KEY_DIR"

exec gosu appuser "$@"
