#!/usr/bin/env bash

set -euo pipefail

SERVER="${EH_SERVER:-https://127.0.0.1:8443}"
TOKEN_FILE="${EH_TOKEN_FILE:-/etc/eh/ehctl.token}"
CA="${EH_CA:-/etc/eh/tls/ca.pem}"
DEST="${1:-/var/backups/eh}"
KEEP="${EH_BACKUP_KEEP:-14}"
if ! [[ "$KEEP" =~ ^[0-9]+$ ]] || [ "$KEEP" -lt 1 ]; then
    echo "EH_BACKUP_KEEP must be an integer >= 1" >&2
    exit 1
fi

command -v ehctl >/dev/null || { echo "ehctl not found in PATH" >&2; exit 1; }
command -v flock >/dev/null || { echo "flock not found in PATH" >&2; exit 1; }
mkdir -p "$DEST"
chmod 700 "$DEST"

exec 9>"$DEST/.backup.lock"
flock -n 9 || { echo "another backup is already running" >&2; exit 1; }

stamp="$(date -u +%Y%m%d-%H%M%S)-$$"
out="$DEST/eh-$stamp.db"

args=(--server "$SERVER" --token-file "$TOKEN_FILE")
if [ -f "$CA" ]; then
    args+=(--ca "$CA")
fi

ehctl backup --out "$out" "${args[@]}"

mapfile -t backups < <(find "$DEST" -maxdepth 1 -name 'eh-*.db' -type f | sort)
if [ "${#backups[@]}" -gt "$KEEP" ]; then
    remove=$(( ${#backups[@]} - KEEP ))
    printf '%s\0' "${backups[@]:0:$remove}" | xargs -0 -r rm -f --
fi

echo "backup ok: $out (kept $KEEP)"
