# Event Horizon — Security notes

This document is for operators and auditors: what cryptography is used, what
properties you can rely on, how to harden a deployment, and how to handle
personal data.

## Reporting

Report vulnerabilities privately (do not open a public issue): contact the
maintainer of your distribution channel. Include version (`eh-server
-version`), a reproduction and impact. You should get an acknowledgement
within a few working days.

## Supported versions

Only the current major line (2.x) receives fixes. There is no v1 support;
v1 was deleted wholesale (see `docs/DECISIONS.md`).

## Cryptography inventory

No homebrew primitives. Everything is a standard construction from Go's
stdlib or `x/crypto`, RustCrypto or rustls.

| Purpose | Construction | Key |
|---------|--------------|-----|
| License key verification | HMAC-SHA256, constant-time compare | `HKDF-SHA256(master, info="eh/license-hmac/v1")` |
| Field encryption at rest (OOB codes, session secrets, package keys, channel) | AES-256-GCM, fresh random nonce per value | `HKDF-SHA256(master, info="eh/field/v1")` |
| OOB code storage / verification | HMAC-SHA256, constant-time compare | `HKDF-SHA256(master, info="eh/oob-code/v1")` |
| Session `vm_seed` | HMAC-SHA256 over the session id | `HKDF-SHA256(master, info="eh/vm-seed/v1")` (nothing stored) |
| Heartbeat proof of possession | Ed25519 over `EH-HB1\|session\|seq\|prev_ack` | session PoP key (private key never leaves the client) |
| Heartbeat ack chain | HMAC-SHA256, chained `ack_{n}` | session heartbeat secret (server-generated, delivered once) |
| Package key delivery | X25519 ECDH (client KEM ↔ server) → HKDF-SHA256(salt=session id, info="eh/pkg-wrap/v1") → XChaCha20-Poly1305, AAD=package id | ephemeral per response |
| `.ehpkg` payload | XChaCha20-Poly1305, AAD=package id; sha256 of the plaintext in the public header | random 32-byte `k_pkg` per package |
| Admin tokens | `eh_` + 24 random bytes hex; `argon2id` hash at rest | token itself shown once |
| Transport (server) | Go `crypto/tls` ≥ 1.2, listener cert; optional mTLS for admin API | X.509 |
| Transport (client) | `rustls` 0.23 (ring), `webpki-roots`; optional SPKI pin (SHA-256 of the leaf public key) | X.509 + pin |
| Randomness | `crypto/rand` (Go), `getrandom` (Rust) | OS CSPRNG |

Key derivation from the master key uses HKDF-SHA256 with fixed, purpose-
bound `info` strings (above). The strings are versioned; a change of
construction gets `/v2`, never a silent edit.

## What is guaranteed

- License keys are never stored in plaintext anywhere: only HMACs.
- A stolen database (including `ehctl backup` output) exposes metadata but
  not OOB codes, session secrets or package keys — those are
  field-encrypted, and the master key is not in the database.
- Challenge nonces are single-use; heartbeat sequences are monotonic and
  chained; retransmits are idempotent rather than rejected (no replay
  amplification).
- Attestation tiers are computed server-side from quote and activation proofs
  (`tpm-attested` > `tpm-quote` > `ek-bound` > `unattested`); the client
  cannot simply assert a level. The EK/AK are TOFU-enrolled and not
  certificate-backed, so a patched client can generate software keys and
  reach `tpm-attested`; the tier is telemetry, not a hardware boundary.
- Authentication failures are generic and timing-floored on the two
  unauthenticated endpoints.

## What is explicitly not

- Client-side secrecy against the machine's owner (see `THREAT_MODEL.md`
  A4). No obfuscation, no anti-debug, no whitebox crypto — v1 shipped
  theater here, v2 does not pretend.
- Protection against a malicious server operator: the admin plane is
  all-powerful by design.
- EK certificate validation (TOFU enrollment instead; ADR-008/019).

## Deployment hardening checklist

- [ ] TLS certificate from a real CA for the customer-facing hostname;
      private key readable only by the server user.
- [ ] If the admin API is reachable beyond localhost: enable mTLS
      (`tls.client_ca_file`) **and** keep bearer tokens; restrict the port
      with a firewall.
- [ ] Master key: prefer `EH_MASTER_KEY` from your secrets manager; a key
      file must be `0600` and excluded from untrusted backups. Losing the
      master key means no license key can ever be verified again.
- [ ] Data dir `0700`, database file owned by the service user only.
- [ ] Nightly `deploy/backup.sh` (or `ehctl backup`) + a tested restore
      procedure (`docs/OPERATIONS.md`), stored off-host.
- [ ] NTP time sync — leases, OOB TTLs and the audit trail all assume a
      sane server clock. Heartbeats tolerate client clock drift by design.
- [ ] `attestation.mode`: start `auto`, move to `required` for licenses
      that must have full TPM evidence (quote + activation). Know that
      non-elevated Windows clients cannot do activation (TBS blocks it) and
      will land `tpm-quote` under `auto`; `required` rejects them. Without
      a usable quote they land `unattested`.
- [ ] `clone.action: suspend` for high-value licenses.
- [ ] Keep `reset_hwid.enabled: true` for single-device licenses. Every
      displacement of a trusted device costs one reset; exhaustion suspends
      the license. Clear counters only after verifying the hardware change
      (`ehctl license clear-resets`), then resume.
- [ ] Protocol version is enforced (`X-EH-Protocol`); there is no downgrade
      path. Upgrade clients instead of widening the accepted range.
- [ ] Review `ehctl audits` after onboarding waves; alert on
      `oob.fail` ladders and `session.clone_suspect`.
- [ ] Keep `security.min_response_floor_ms` ≥ 100 in production.

## Personal data (GDPR/CCPA notes)

The server stores customer names/notes, device fingerprints (unsalted
SHA-256 hashes of machine identifiers, see `docs/PROTOCOL.md` §2), timestamps
and audit records. Practical checklist:

- [ ] Record the lawful basis (contract performance for licensing).
- [ ] Keep a processing register: these fields, the server location, the
      retention you chose.
- [ ] Honour erasure: `revoke`, stop the server, then delete the customer's
      rows with `sqlite3` (foreign keys on; delete `nonces` and `oob_state`
      explicitly, then the license, which cascades to devices, sessions and
      `oob_codes`):
      `PRAGMA foreign_keys=ON; DELETE FROM nonces WHERE license_id='…';
      DELETE FROM oob_state WHERE license_id='…';
      DELETE FROM licenses WHERE id='…';`
      There is no delete endpoint in v2. Audit rows keep the license
      identifier for the retention period you chose; purge them separately
      if erasure includes audit history.
- [ ] The client sends only the fingerprint hash and identifiers you pass;
      it contacts only your server. No telemetry exists to leak.
- [ ] Backups contain the same fields; apply the same retention to them.

## Verifying a build

```sh
go test ./... && go test -race ./...     # server
cd rust && cargo test                    # client and VM
go build ./cmd/... && cd rust && cargo build --release -p eh-client
```

Every cryptographic binding asserted above has a unit test; the HTTP flow
has an end-to-end integration test (`internal/api/api_test.go`); the client
was verified live against the server, including TPM quote and activation on
real hardware (Windows, TBS).
