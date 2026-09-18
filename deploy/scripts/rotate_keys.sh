#!/usr/bin/env bash
# Event Horizon (Spec v12) — Lease Token Signing Key Rotation Automation (Section 6)
set -euo pipefail

KEY_DIR="${KEY_DIR:-/etc/event-horizon/keys}"
ROTATION_LOG="${KEY_DIR}/rotation.log"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
NEW_KID="kid-${TIMESTAMP}"

mkdir -p "${KEY_DIR}"

echo "[+] Initiating key rotation for Lease Token signing key..."

# Generate new Ed25519 private key
NEW_PRIV="${KEY_DIR}/lease_sign_${NEW_KID}.pem"
NEW_PUB="${KEY_DIR}/lease_pub_${NEW_KID}.pem"

openssl genpkey -algorithm Ed25519 -out "${NEW_PRIV}"
openssl pkey -in "${NEW_PRIV}" -pubout -out "${NEW_PUB}"

chmod 600 "${NEW_PRIV}"
chmod 644 "${NEW_PUB}"

echo "[+] New key generated: ${NEW_KID}"
echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Rotated key to ${NEW_KID}" >> "${ROTATION_LOG}"

# Create/update active key symlink atomically
ln -sf "${NEW_PRIV}" "${KEY_DIR}/lease_sign_active.pem"
ln -sf "${NEW_PUB}" "${KEY_DIR}/lease_pub_active.pem"

echo "[+] Active key updated to ${NEW_KID}. Previous keys retained for grace period."
