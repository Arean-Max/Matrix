#!/usr/bin/env bash

set -euo pipefail

SERVER="${EH_SERVER:-https://127.0.0.1:8443}"
TOKEN_FILE="${EH_TOKEN_FILE:-/etc/eh/ehctl.token}"
CA="${EH_CA:-/etc/eh/tls/ca.pem}"
DEST="${1:-/var/backups/eh}"
KEEP="${EH_BACKUP_KEEP:-14}"

command -v ehctl >/dev/null || { echo "ehctl not found in PATH" >&2; exit 1; }
mkdir -p "$DEST"
chmod 700 "$DEST"

stamp="$(date -u +%Y%m%d-%H%M%S)"
out="$DEST/eh-$stamp.db"

args=(--server "$SERVER" --token-file "$TOKEN_FILE")
if [ -f "$CA" ]; then
    args+=(--ca "$CA")
fi

ehctl backup --out "$out" "${args[@]}"

find "$DEST" -maxdepth 1 -name 'eh-*.db' -type f | sort | head -n "-$KEEP" | xargs -r rm -f

echo "backup ok: $out (kept $KEEP)"
