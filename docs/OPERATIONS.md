# Event Horizon — Operations guide

Everything an operator does runs through `ehctl` (or the admin API it
wraps). This guide is the day-2 companion to `deploy/`.

Common flags on every command:

```
--server URL        admin endpoint, e.g. https://lic.example.com:8443
--token TOKEN       bearer token (or EHCTL_TOKEN)
--token-file FILE   file with the token (or ~/.ehctl/token)
--ca PEM            CA bundle when the server uses a private CA
--json              machine-readable output
```

## 1. Install

**systemd (recommended).** Follow `deploy/eh-server.service`:

```sh
useradd --system --home /var/lib/eh --shell /usr/sbin/nologin eh
install -d -o eh -g eh -m 700 /var/lib/eh /etc/eh/tls
install -m 644 deploy/eh-server.service /etc/systemd/system/
# config: cp deploy/config/server.example.yaml /etc/eh/server.yaml
systemctl daemon-reload && systemctl enable --now eh-server
```

**Docker.** See `deploy/docker-compose.yml`; the container includes an
`eh-server -health-check` probe and ships `eh-trustd` at
`/usr/local/bin/eh-trustd` with `EH_ATTESTATION_TRUSTD_PATH` preset.

**Isolated TPM verifier (systemd/custom installs).** Build the Rust daemon
and point the server at it:

```sh
cargo build --locked --release --manifest-path rust/Cargo.toml -p eh-trustd
install -o root -g root -m 755 rust/target/release/eh-trustd /usr/local/bin/eh-trustd
# /etc/eh/server.yaml
# attestation:
#   trustd_path: /usr/local/bin/eh-trustd
#   trustd_timeout_ms: 2000
```

`eh-server` spawns the daemon on startup, requires a successful `ping`, and
logs `attestation verifier backend=trustd path=...`. The path must be
absolute, so a stray `PATH` entry cannot be picked up. The daemon has no
sockets, no database and no keys, and starts with an empty environment: it
inherits neither `EH_MASTER_KEY` nor any other server secret. It reads one
JSON line per request on stdin and answers on stdout; every response carries
the internal protocol version, and a mismatch fails the request. A crash,
timeout or malformed response fails the attestation request closed; the next
request respawns it. Install the binary root-owned and not writable by the
service user: it decides whether quotes are valid. Leave `trustd_path` empty
for embedded mode (single binary, no child process). The unit file needs no
change: the child inherits the service sandbox. In the Docker image, run with
`EH_ATTESTATION_TRUSTD_PATH=` (empty) to force embedded mode.

**Master key.** Set `EH_MASTER_KEY` (64 hex chars) or
`EH_MASTER_KEY_FILE`. If neither is set and `<data_dir>/eh.db` does not exist,
the server generates `<data_dir>/master.key` (0600) on first start. If the
database exists but that key file is missing, startup fails instead of
silently minting a new key: restore the key or remove the database. Back the
key up **separately** from the database, to a place you trust. If the key is
lost, every license key becomes unverifiable (they exist only as HMACs).

## 2. Bootstrap

First start logs "no admin tokens exist; bootstrap credential written".
Consume it once:

```sh
ehctl init --bootstrap-file /var/lib/eh/bootstrap.token \
  --server https://127.0.0.1:8443 --ca /etc/eh/tls/ca.pem
```

This creates an `admin` token (written to `~/.ehctl/token` by default).
The bootstrap credential is accepted only until the first admin token is
created through the API; it is then disabled in-process and the file is
removed on the next start. If you revoke every admin token, restart the
server: with no active tokens it mints a new bootstrap credential. Create
narrower tokens for automation:

```sh
ehctl tokens create "monitoring" --role read
```

## 3. Licensing workflow

```sh
# Create a license; the key is printed exactly once — deliver it to the customer.
ehctl license create --customer "Acme GmbH" --note "Pilot Q4" \
    --channel webhook:https://ops.example.com/eh-hook --max-devices 2

# Inspect
ehctl license list --query acme
ehctl license show <license-id>
ehctl device list --license <license-id>

# Out-of-band activation code (when the client says exit code 2 / oob_required)
ehctl license oob <license-id>          # audited as oob.reveal
ehctl license unlock <license-id>       # clear the failed-attempt ladder

# Enforcement
ehctl license suspend <license-id> --reason "payment overdue"
ehctl license resume <license-id>        # suspended -> active only
ehctl license revoke <license-id> --reason "chargeback"   # terminal
ehctl device revoke <device-id>          # terminal for that binding
ehctl device release <device-id>         # allow a new binding (fresh OOB code)
ehctl license clear-resets <license-id>  # operator-only: wipe HWID reset counters
```

`license resume` is rejected once a license is `revoked`; create a new license
instead. `device release` also revokes the device's sessions, so a replacement
machine starts from a clean activation. A revoked device cannot re-activate
until an operator explicitly releases it.

**HWID resets.** For single-device licenses (`max_devices: 1`), replacing a
trusted device consumes one reset. Defaults: 30-day cooldown and three
automatic resets (`reset_hwid` in `server.yaml`). The client may call
`POST /api/v1/reset-hwid` to unbind everything and start a clean activation;
every path still requires a fresh OOB code. When the quota is exhausted the
license is suspended and `hwid.reset_quota` is audited. Resolve with
`ehctl license clear-resets <id>`, then
`ehctl license resume <id> --reason "verified hardware replacement"`.
Multi-device licenses are not quota-limited; each binding still needs OOB.

Webhook channel: the server POSTs JSON

```json
{"event":"oob.issued","license_id":"…","customer":"…","code":"12345678",
 "issued_at":1730000000,"expires_at":1730001800}
```

with `X-EH-Signature: hex(HMAC-SHA256(webhook_secret, body))`. Verify it.
Redirects are not followed; point the channel at the final HTTPS URL.
Manual channel: operators read codes with `ehctl license oob`; that endpoint
requires an `admin`-role token (read-only tokens are for monitoring).

Packages (vendor side):

```sh
eh-builder pack --id demo-core --name "Demo Core" --in app.bin
#   -> demo-core.ehpkg        (ship to customers, safe)
#   -> demo-core.provision.json (SECRET: the raw key; import once, then
#      delete or archive offline)
ehctl packages import demo-core.provision.json
ehctl packages list
ehctl packages revoke <package-id>
```

## 4. Backup and restore

Nightly, as root on the server host:

```sh
deploy/backup.sh /var/backups/eh      # wraps: ehctl backup --out FILE
```

`ehctl backup` asks the server for a consistent SQLite copy (`VACUUM INTO`)
and streams it down; it is safe while the server runs. The copy contains
field-**encrypted** secrets. Also back up, separately:

- the master key (`EH_MASTER_KEY` value or `<data_dir>/master.key`),
- `/etc/eh/tls` (listener cert/key, admin CA if mTLS),
- your config file.

**Restore drill** (do this once before you need it):

```sh
systemctl stop eh-server
cp /var/backups/eh/eh-<stamp>.db /var/lib/eh/eh.db
rm -f /var/lib/eh/eh.db-wal /var/lib/eh/eh.db-shm
# master key and TLS files must be the same ones
systemctl start eh-server
ehctl status          # expect your licenses/devices back
```

Sessions created after the backup no longer exist. Affected clients see
`unknown_session`, `lease_expired` or `ack_chain_broken` and the SDK
re-establishes a fresh session on its next call; no manual action is needed
unless the device was also revoked in the meantime.

**Lost admin tokens.** With the server stopped, any SQLite tool can reset
the token table; the next start mints a fresh bootstrap credential:

```sh
systemctl stop eh-server
sqlite3 /var/lib/eh/eh.db "DELETE FROM admin_tokens;"
systemctl start eh-server         # writes bootstrap.token again
```

**Lost master key.** Not recoverable. Delete `eh.db`, start fresh and
reissue every license — cryptographic verification of the old keys is gone
with the key. This is why the key backup is not optional.

## 5. Monitoring

- Liveness: `GET /api/v1/health` → `{"ok":true,"version":…}`; or
  `eh-server -health-check -config /etc/eh/server.yaml` (exit 0/1).
- Overview: `ehctl status` (version, uptime, counters).
- Audit trail: `ehctl audits --limit 50`, filter with `--action` (e.g.
  `oob.fail`, `session.clone_suspect`, `hwid.reset`, `hwid.reset_quota`,
  `backup.export`) or `--license`.
- Logs: structured `slog` text on stderr; rate-limit and auth events are
  logged without secrets. No metrics endpoint exists by design — `ehctl
  status`/`audits` are the interface.
- Failed admin authentication is audited as `auth.fail` with the peer address
  (never the token). Alert on bursts.
- Alerts worth having: `auth.fail` bursts, `oob.lock` entries,
  `session.clone_suspect` with `clone.action: suspend`, 5xx bursts,
  certificate expiry.
- Rate limits key on the TCP peer address; `X-Forwarded-For` is deliberately
  not trusted. Behind a reverse proxy every client shares one bucket, so
  either terminate TLS on the server or enforce limits at the proxy. Do not
  expose the server through a proxy that hides the peer address and expect
  the application limits to separate clients.

## 6. Upgrades

1. `deploy/backup.sh` first (the database schema migrates automatically on
   start; a copy is your rollback).
2. Replace the binary (or image tag) and restart.
3. `ehctl status` shows the new version; `ehctl audits --action server.start`
   records it.

Admin tokens created before the schema v2 migration are upgraded with a
lookup hash on their first successful request; no rotation is needed.
Downgrades are not supported once migrations ran.

Ended sessions are kept for audit correlation; rows accumulate slowly. With
the server stopped, you may prune sessions whose lease expired more than 90
days ago. Audits are never deleted by the server — archive or purge them
according to your retention policy (and remember that erasing a license does
not erase its audit rows).

## 7. Key and certificate rotation

- **Admin tokens**: `ehctl tokens create` new, switch automation, then
  `ehctl tokens revoke <old-id>`. Zero downtime.
- **TLS certificates**: replace files and restart the server (hot reload is
  not implemented on purpose — it is a one-line restart).
- **Trust daemon**: rebuild `eh-trustd`, replace the binary, restart the
  server. The embedded and Rust verifiers are interchangeable; the wire
  protocol does not change.
- **Package keys**: re-pack payloads with `eh-builder`; package ids are
  independent, old packages stay verifiable until revoked.
- **Master key**: **not rotatable in v2.** Rotating it would invalidate all
  license HMACs and field-encrypted values. Treat it as permanent; if it
  leaks, plan a migration to a new deployment and reissue licenses.

## 8. Troubleshooting

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| Client: `x509`/`certificate` error | server cert not trusted | ship `--ca ca.pem` to clients or use a public CA |
| Client exit code 2 / `oob_required` | new device needs a code | `ehctl license oob <id>`, re-run with `--code` |
| `code_locked` | too many wrong codes | wait for `retry_after_s`, or `ehctl license unlock` |
| `rate_limited` | per-IP/license limits | back off; limits are documented in PROTOCOL §3 |
| Client trust shows `tpm-quote` instead of `tpm-attested` | non-elevated Windows run (TBS blocks activation) or no activation bundle | expected; run elevated once to enroll, or accept the level |
| Client trust shows `ek-bound` | activation succeeded but no valid quote was sent (`attestation.mode` off, or TPM quote unavailable) | check `attestation.mode` and the client's TPM state |
| `attestation_failed` (mode `required`) | quote/AK mismatch, or machine without TPM | inspect `ehctl device list --license`; adjust `attestation.mode` |
| `lease_expired` | client offline past `lease_ttl + grace` | expected — the client must reach the server again |
| `ack_chain_broken` | cloned machine or telemetry lost | check `session.clone_suspect` audits; policy in `clone.action` |
| `session_revoked` | device revoked or session superseded | superseded: retry; revoked: `ehctl device release`, then activate with a fresh code |
| `reset_cooldown` | single-device license reset less than `reset_hwid.cooldown_days` ago | wait for `retry_after_s`; a support reset is `ehctl license clear-resets` + `resume` |
| `reset_quota` | all automatic HWID resets consumed; license is suspended | verify the hardware change, then `ehctl license clear-resets <id>` + `ehctl license resume <id> --reason ...` |
| `protocol_unsupported` | client omitted `X-EH-Protocol` or sent an unsupported version | upgrade the client; downgrade is intentionally unsupported |
| Startup fails with `attestation verifier: trustd: ...` | `attestation.trustd_path` is set but the binary is missing, not executable, or did not answer `ping` | fix the path/permissions; the server intentionally refuses to start rather than silently using another verifier |
| Attestations fail with `trustd:` in the log while `attestation.mode: required` | the daemon was killed/updated, timed out, or rejected a non-standard signature | check the server log for the daemon error; the request fails closed. Identity of the binary matters: rebuild from this tree, do not substitute another tool |
| Log says `backend=embedded` after configuring trustd | the path came from YAML/env but the server restarted without it, or the key is misspelled | check `EH_ATTESTATION_TRUSTD_PATH` and `attestation.trustd_path`; `KnownFields` rejects unknown YAML keys, so a typo fails startup |
| Client state lost or corrupt (`client.state`) | data dir wiped, DPAPI user changed, or copied from another machine | SDK drops the saved session and re-verifies online; keep the data dir for offline continuity |
| Server: `TLS handshake error` from Schannel/old clients | client TLS stack rejects the cert (private CA) | use the supplied CA or a chain clients trust |

## 9. Windows client deployment notes

The SDK builds to `eh_client.dll` (C ABI, header at
`rust/eh-client/include/eh_client.h`) plus `eh-demo.exe` for smoke tests.
Host requirements: Windows 10+/Server 2019+, TPM 2.0 for attestation
(optional — the SDK degrades to `unattested`), no admin rights required.
State lives under the caller-provided data dir, DPAPI-sealed.

Pin the server key for hostile networks:

```powershell
# SPKI SHA-256 of the server's leaf public key, hex:
eh-demo.exe ... --pin <sha256-of-spki>
```

Switching `--package-id` on a machine that still has a restored session is
handled automatically: the SDK drops the saved package and establishes a
fresh session, because package keys are only handed out at session
establishment (a note in the demo output explains it). With no `--package-id`
the saved session and payload are reused as before.
