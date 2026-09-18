#!/usr/bin/env bash
# Event Horizon (Spec v12) — Encrypted Database Backup Automation
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/event-horizon}"
DB_FILE="${DB_FILE:-/var/lib/event-horizon/event_horizon.db}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_ARCHIVE="${BACKUP_DIR}/eh_backup_${TIMESTAMP}.enc"

mkdir -p "${BACKUP_DIR}"

if [[ ! -f "${DB_FILE}" ]]; then
    echo "[-] Database file not found at ${DB_FILE}"
    exit 1
fi

if [[ -z "${EH_BACKUP_KEY:-}" ]]; then
    echo "[-] EH_BACKUP_KEY environment variable is required for encryption"
    exit 1
fi

echo "[+] Starting encrypted backup of ${DB_FILE}..."

# Create compressed, encrypted archive using OpenSSL AES-256-GCM
tar -czf - -C "$(dirname "${DB_FILE}")" "$(basename "${DB_FILE}")" | \
    openssl enc -aes-256-gcm -salt -pbkdf2 -iter 100000 \
    -k "${EH_BACKUP_KEY}" -out "${BACKUP_ARCHIVE}"

# Verify backup integrity
if openssl enc -d -aes-256-gcm -pbkdf2 -iter 100000 -k "${EH_BACKUP_KEY}" -in "${BACKUP_ARCHIVE}" | tar -tzf - >/dev/null 2>&1; then
    echo "[+] Backup successfully verified: ${BACKUP_ARCHIVE} ($(du -h "${BACKUP_ARCHIVE}" | cut -f1))"
else
    echo "[-] Backup verification failed! Removing corrupted archive."
    rm -f "${BACKUP_ARCHIVE}"
    exit 1
fi

# Prune archives older than 30 days
find "${BACKUP_DIR}" -name "eh_backup_*.enc" -mtime +30 -delete
echo "[+] Backup cycle complete."
