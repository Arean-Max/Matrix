# Event Horizon — Client ↔ Server Protocol

Protocol version 1 (product `2.0.0`). This document is normative: both the Go
server (`internal/wire`, `internal/api`) and the Rust client (`eh-client`) are
implemented against it. When code and document disagree, one of them is a bug.

## 1. Transport and encoding

- All traffic is HTTPS (TLS 1.2+). The server refuses to start without TLS
  unless `security.dev_allow_http: true` is set explicitly (development only,
  loud warning at startup).
- The client SHOULD pin the server certificate SPKI (SHA-256) when
  `spki_pin` is configured, and MUST verify the chain otherwise.
- Bodies are JSON (UTF-8), `Content-Type: application/json`.
- Request body cap: 1 MiB; larger requests get `413`.
- Field naming: `snake_case`. Timestamps: unix seconds. `client_time_ms` is
  milliseconds.
- Hex is lowercase. Base64 is RFC 4648 standard with padding.
- TPM blobs on the wire are **content bytes** (struct bodies) without the
  outer `TPM2B` length prefix. Each side adds/removes prefixes at the TPM
  boundary. This rule applies to `ak_pub`, `attest`, `signature`,
  `enc_secret`, `id_object`.
- Client API root: `/api/v1`. Admin API root: `/admin/v1`.
- Every client API request except `GET /api/v1/health` MUST carry
  `X-EH-Protocol: 1`. Missing, non-integer or out-of-range values are
  rejected with `protocol_unsupported` before the body is decoded. There is
  no fallback and no legacy mode; version 1 is both the minimum and maximum.

## 2. Identifiers

### License key
`EH1-` + four groups of 5 characters from the Crockford base32 alphabet
(no `I`, `L`, `O`, `U`), e.g. `EH1-7Q2MA-9XRKC-4TTD8-PZ3WV`. 100 bits of
entropy, generated server-side. Case-insensitive input; dashes/spaces are
stripped before validation.

Server stores only `HMAC-SHA256(K_lic, canonical_key)` where
`K_lic = HKDF-SHA256(master_key, info="eh/license-hmac/v1")`. Raw keys never
touch the database.

### Session ID
32 lowercase hex characters (16 random bytes), server-generated at `/verify`.

### Device fingerprint (`fingerprint`)
Client-computed `SHA256("EH-FP1|" + machine_guid + "|" + computer_name + "|" + volume_serial_hex8)`, hex.
The hash is unsalted: the inputs are stable machine identifiers, not secrets.
It is used for correlation and rate limiting; the security binding is the TPM
identity (`ek_hash`), not the fingerprint.

### EK hash (`ek_hash`)
`SHA256(TPMT_PUBLIC content bytes of the EK)`, hex — computed from the
`TPM2_ReadPublic` result with the outer size prefix stripped. Stable per TPM
silicon.

### AK public key (`ak_pub`) and name (`ak_name`)
- `ak_pub`: raw `TPMT_PUBLIC` content bytes, base64.
- `ak_name`: hex of `nameAlg(2 bytes BE) || H_nameAlg(ak_pub content bytes)`,
  nameAlg = SHA-256 (`0x000B`). No size prefix is hashed (verified against
  real hardware). The server recomputes the name from `ak_pub` and rejects
  mismatches.

### Quote (`attest`, `signature`)
- `attest`: base64 of `TPMS_ATTEST` content bytes (from `TPM2B_ATTEST`,
  prefix stripped).
- `signature`: base64 of `TPMT_SIGNATURE` content bytes.
- The TPM signs the `TPMS_ATTEST` content bytes; the server verifies over
  exactly those bytes.

## 3. Client API

Error body (all non-2xx):

```json
{"error": {"code": "invalid_license", "message": "human-readable text"}}
```

Error codes: `invalid_request` (400), `protocol_unsupported` (400),
`invalid_license` (403), `license_unavailable` (403), `invalid_code` (403),
`code_locked` (429, body carries `retry_after_s`), `oob_expired` (410),
`oob_required` (409), `invalid_nonce` (409), `attestation_failed` (403),
`activation_failed` (403), `bad_signature` (403), `unknown_session` (403),
`lease_expired` (403), `session_revoked` (403), `ack_chain_broken` (409),
`reset_cooldown` (429, body carries `retry_after_s`), `reset_quota` (403),
`rate_limited` (429, body carries `retry_after_s`), `internal` (500).

The client treats `unknown_session`, `lease_expired`, `session_revoked` and
`ack_chain_broken` as session loss: it drops the local session and tries one
fresh `/verify`. A revoked device fails that `/verify` and the error surfaces.

Auth-shaped failures are deliberately generic (unknown vs suspended license,
unknown vs revoked session) and the server keeps a fixed minimum response
floor (~150 ms) on `/activate` and `/verify-oob` to flatten timing.

`GET /api/v1/health` is the unauthenticated liveness probe for container
orchestrators: `{"ok": true, "version": "2.0.0"}`. It exposes nothing beyond
the software version.

### 3.1 POST /api/v1/activate

```json
{"license_key": "EH1-...", "fingerprint": "hex64"}
```

Response 200:

```json
{"status": "ready", "oob_expires_at": 0}
```

or

```json
{"status": "oob_required", "oob_expires_at": 1730000000}
```

`ready` — the device is trusted; proceed to `/challenge`.
`oob_required` — a one-time code was issued (or is still pending) to the
license's out-of-band channel.

Limits: 5/min per IP, 6/hour per license. The same pending code is reused
within `oob.resend_interval_s` (default 60 s); resends do not mint new codes.

### 3.2 POST /api/v1/verify-oob

```json
{"license_key": "...", "fingerprint": "hex64", "code": "12345678"}
```

Response 200: `{"status": "ready"}`.

Errors: `invalid_code` with `details.attempts_remaining`; `code_locked` with
`retry_after_s`; `oob_expired`.

Lock ladder: 5 consecutive failures → 5 min lock; each further failure
doubles the lock up to 1 h; 10 failures → 24 h lock or admin unlock. Attempts
never reset by re-activation: a new code is only minted after the resend
interval, and the attempt counter persists per license+device (this closes the
v1 "activate to reset attempts" loop).

Limits: 5/min per IP, 6/hour per license.

### 3.3 POST /api/v1/challenge

```json
{
  "license_key": "...",
  "fingerprint": "hex64",
  "ek": {"ek_hash": "hex64|null", "ek_pub": "base64|null", "ak_pub": "base64|null", "ak_name": "hex|null"}
}
```

The device must already be trusted, otherwise `oob_required`.

Response 200:

```json
{
  "nonce": "hex64",
  "expires_at": 1730000000,
  "activation": {"enc_secret": "base64", "id_object": "base64"}
}
```

`activation` is present only when attestation is enabled and the `ek` bundle
is complete and self-consistent (`ek_pub` present, `ek_hash ==
SHA256(ek_pub)`, `ak_pub`/`ak_name` present with `ak_name` recomputing from
`ak_pub`). If the device is already EK-enrolled, `ek_hash` must match the
enrolled value (`attestation_failed` otherwise); a not-yet-enrolled device may
request activation — enrollment itself happens at `/verify` only after the
activation proof succeeds, so the EK identity is hardened by a hardware proof.
The server builds a `TPM2_MakeCredential` for a random 32-byte secret bound to
`ak_name` under `ek_pub`. The client must run `TPM2_ActivateCredential` and
prove possession of the secret in `/verify`. Otherwise `activation` is `null`.

Note (Windows): TBS blocks `TPM2_ActivateCredential` for non-elevated
processes (`TPM_E_COMMAND_BLOCKED`). Such clients fall back to `tpm-quote`
(quote without activation), or `unattested` when no usable quote is available;
documented upgrade paths are running elevated or using the Platform Crypto
Provider. This does not weaken the server: a client that cannot activate
simply gets the weaker trust level.

Client note: the SDK's EK/AK are deterministic endorsement-hierarchy
primaries (ADR-019), so `ek_hash` is stable across reboots and TPM clears;
`ek_pub` is not certificate-backed — EK authenticity rests on first-seen
enrollment (TOFU), software keys are indistinguishable from TPM keys at this
layer, and DRM-grade EK certificate validation is out of scope (ADR-008).

Nonce: 32 random bytes, single-use, TTL 120 s, bound to (license, fingerprint).
Global cap 10 000 pending nonces; an in-process janitor expires stale rows.

Limits: 30/min per IP, 12/min per device.

### 3.4 POST /api/v1/verify

```json
{
  "license_key": "...",
  "fingerprint": "hex64",
  "nonce": "hex64",
  "pop_pub": "base64(32B ed25519)",
  "kem_pub": "base64(32B x25519)",
  "package_id": "demo",
  "activation_hmac": "hex64|null",
  "quote": {
    "attest": "base64",
    "signature": "base64",
    "ak_pub": "base64",
    "ak_name": "hex",
    "ek_hash": "hex64|null"
  }
}
```

`quote` and `package_id` may be omitted. Response 200:

```json
{
  "status": "active",
  "session_id": "hex32",
  "lease_exp": 1730000000,
  "heartbeat_interval_s": 900,
  "offline_grace_s": 259200,
  "ack": "hex64",
  "server_time": 1730000000,
  "vm_seed": "hex64",
  "trust": "tpm-attested",
  "package": {"id": "demo", "sha256": "hex64", "kem_pub": "base64(32B)", "wrapped_key": "base64"}
}
```

`trust` is one of `tpm-attested`, `tpm-quote`, `ek-bound`, `unattested`.
The tiers are TOFU: EK/AK are client-supplied and not certificate-backed, so
the highest tier records a valid quote plus activation proof, not physical TPM
residency. See `THREAT_MODEL.md` A6.

Verification order (any failure returns the error, no partial success):

1. Nonce exists, matches license+fingerprint, is unused and unexpired;
   consumed atomically.
2. Device is trusted and its license is `active`.
3. Attestation (`attestation.mode` ≠ `off`, quote present):
   - Parse `TPMS_ATTEST`: magic `0xFF544347`, type `0x8018` (quote),
     `extraData` equals the nonce bytes.
   - `ak_name` equals the name recomputed from `ak_pub` (see §2).
   - AK attributes: `restricted=1`, `sign=1`, `fixedTPM=1`, `fixedParent=1`,
     `sensitiveDataOrigin=1`.
   - Signature verifies over the attest bytes under `ak_pub`. Supported
     signature formats: RSASSA-PKCS1v15-SHA256 (`0x0014/0x000B`),
     RSASSA-PSS-SHA256 (`0x0016/0x000B`), ECDSA-SHA256 (`0x0018/0x000B`).
   - `ek_hash`: required when the device is already EK-enrolled or when the
     nonce requested activation; it must match the enrolled EK and the EK the
     activation blob was built against. A not-yet-enrolled device is enrolled
     on first sight, but only when the activation proof below succeeded
     (`ek_hash` is not enrolled from a bare assertion).
   - If `attestation.expected_pcr_digest` is configured, the server compares
     the quoted PCR digest and selection; mismatch → `attestation_failed`.
   - `trust = tpm-attested` when both the quote and the activation proof
     verified in this request; `tpm-quote` when only the quote verified;
     `ek-bound` when only the activation proof verified (it still enrolls
     the EK); `unattested` otherwise. Quote-only is a distinct tier: the AK
     is proven, but the EK was not activation-bound in this request.
4. If an activation blob was issued for this nonce, `activation_hmac` must
   equal `HMAC-SHA256(secret, "EH-ACT1|" + nonce_hex)` where `nonce_hex` is
   the hex string from the challenge; failure → `activation_failed`. The
   nonce is consumed either way (single use).
5. `attestation.mode = required` and either no valid quote or no activation
   bundle → `attestation_failed`.
6. Other active sessions of this device are marked `superseded`
   (grace `security.supersede_grace_s`, default 300 s).
7. A session is created. `hb_secret` = 32 random bytes, stored encrypted;
   `ack0 = HMAC-SHA256(hb_secret, "EH-ACK1|" + session_id + "|0")`.
8. If `package_id` is present, it must name an active package; unknown or
   inactive packages fail with `invalid_request`. Validation and key wrapping
   happen before any device or session state is written, so a bad package
   leaves the device and its existing sessions untouched.
9. `vm_seed` = HKDF-free deterministic derivation:
   `HMAC-SHA256(K_vmseed, session_id)` where
   `K_vmseed = HKDF-SHA256(master_key, info="eh/vm-seed/v1")`. Nothing is
   stored: the seed can be recomputed from the session id alone.

Limits: 30/min per IP, 12/min per device. Any request with a valid nonce
consumes it, even if a later check fails (single use).

### 3.5 POST /api/v1/heartbeat

```json
{
  "session_id": "hex32",
  "seq": 17,
  "prev_ack": "hex64",
  "pop_sig": "base64(64B)",
  "client_time_ms": 1730000000123
}
```

Sign bytes (Ed25519 over the literal ASCII string):

```
EH-HB1|{session_id}|{seq}|{prev_ack}
```

Response 200:

```json
{"ack": "hex64", "lease_exp": 1730000000, "next_interval_s": 900, "server_time": 1730000000}
```

Ack chain:

```
ack_n = HMAC-SHA256(hb_secret, "EH-ACK1|" + session_id + "|" + seq + "|" + hex(SHA256(sign_bytes)))
```

Server rules:

- Normal: `seq == last_seq + 1 && prev_ack == last_ack` → issue `ack_n`.
- Retransmit: `seq == last_seq && prev_ack == prior_ack` → return the stored
  `last_ack`, no state change (idempotent response-loss recovery).
- Anything else → `ack_chain_broken` (audited; repeated → clone counter).
- `pop_sig` verified against the session's `pop_pub`.
- A superseded session is served within `supersede_grace_s`; its lease is
  capped at the end of that window. Outside it the request is rejected with
  `session_revoked` and a clone event is recorded (policy `clone.action`:
  `flag` by default, `suspend` optional); a `suspend` action suspends the
  license and revokes its sessions.
- `now > lease_exp` → `lease_expired` (checked after the supersede rule).

Limits: 1/10 s per session, 60/min per IP.

### 3.6 POST /api/v1/reset-hwid

Releases every trusted device of a license so that the machine (or its
replacement) must complete activation and a fresh OOB code again:

```json
{"license_key": "...", "fingerprint": "hex64-or-omitted"}
```

Response 200: `{"status": "released", "devices_released": 1}`. If no device is
trusted the call is a no-op and does not consume quota.

Policy for single-device licenses (`max_devices == 1`; multi-device licenses
are fleet-managed and are not quota-limited):

- A binding that displaces a trusted device counts as a reset, as does an
  explicit call that releases at least one trusted device. Re-binding the same
  fingerprint, or binding while a free slot exists, does not count.
- `reset_hwid.cooldown_days` (default 30) must elapse between resets:
  `reset_cooldown` with `retry_after_s`.
- `reset_hwid.lifetime_limit` (default 3) automatic resets: the next attempt
  returns `reset_quota` and suspends the license. An operator clears the
  counters with `ehctl license clear-resets <id>` and resumes it.
- The quota check, the counter increment and the device release run in one
  SQLite transaction, so parallel requests cannot exceed the limit.
- The endpoint never bypasses OOB: it only unbinds devices. The following
  `/activate` issues a code exactly like a first activation.
- `reset_hwid.enabled: false` disables quota accounting; devices are still
  released and the operation is audited.

Limits: 5/min per IP, 3/min per license. Every reset is audited as
`hwid.reset`; a quota hit adds `hwid.reset_quota` and suspends the license.

## 4. Package key wrapping

Server (at `/verify`): generate ephemeral X25519 keypair; `shared =
ECDH(eph_priv, kem_pub)`; `k = HKDF-SHA256(shared, salt=session_id_bytes,
info="eh/pkg-wrap/v1")`; `wrapped_key = base64( nonce24 || XChaCha20-Poly1305.Seal(k, key, aad=package_id) )`.

Client mirrors with its per-run KEM keypair. Package payload at rest is
`XChaCha20-Poly1305` with a 24-byte random nonce; the payload key is 32 random
bytes generated by `eh-builder` and delivered only through this wrap.

## 5. `.ehpkg` container and provisioning

Container layout: `EHPKG1\n` + one-line JSON header + `\n` + sealed bytes.
Sealed bytes are `nonce24 || XChaCha20-Poly1305.Seal(key, payload,
aad=package_id)` — the package id is authenticated, so a container cannot be
relabelled.

```json
{"version": 1, "id": "demo", "name": "Demo payload", "sha256": "hex64(plaintext)", "created_at": 1730000000, "builder": "eh-builder 2.0.0"}
```

`eh-builder` also writes a **provision file** (secret, never commit):

```json
{"version": 1, "id": "demo", "name": "Demo payload", "sha256": "hex64", "key": "base64(32B)"}
```

`ehctl packages import provision.json` uploads it to the server, which stores
the key encrypted with its field key. The client verifies `sha256` after
decryption in addition to AEAD integrity.

## 6. Admin API (summary)

Auth: `Authorization: Bearer eh_...` (argon2id-hashed at rest) or mTLS client
certificate from the configured admin CA. Both may be enabled; mTLS CN or
token name becomes the audit actor.

- `POST /admin/v1/licenses` — create; the response contains the license key
  **once**.
- `GET /admin/v1/licenses?query=&status=&limit=&offset=`,
  `GET /admin/v1/licenses/{id}`
- `POST /admin/v1/licenses/{id}/suspend|resume|revoke` `{"reason": "..."}`
- `GET /admin/v1/licenses/{id}/oob` — current pending code plaintext
  (audited `oob.reveal`)
- `POST /admin/v1/licenses/{id}/oob/unlock`
- `GET /admin/v1/devices?license_id=`, `POST /admin/v1/devices/{id}/revoke`,
  `POST /admin/v1/devices/{id}/release`
- `POST /admin/v1/packages` (import provision), `GET /admin/v1/packages`,
  `POST /admin/v1/packages/{id}/revoke`
- `GET /admin/v1/audits?limit=&before_id=&license_id=&action=`
- `POST /admin/v1/tokens` `{"name","role"}` (token shown once),
  `GET /admin/v1/tokens`, `POST /admin/v1/tokens/{id}/revoke`
- `GET /admin/v1/status`
- `GET /admin/v1/backup` — consistent database copy (SQLite `VACUUM INTO`),
  streamed as `application/vnd.sqlite3`; audited `backup.export`. Secrets
  inside stay field-encrypted; the master key is never part of it.

## 7. State machines (normative)

- **License**: `active ↔ suspended`, both → `revoked`; `revoked` is terminal
  and `resume` is rejected. Repeated transitions to the current state are
  no-ops. Non-`active` licenses are rejected on every client endpoint.
- **Device**: `trusted → released | revoked`. At most `max_devices` devices
  stay trusted (default 1): a successful OOB binding releases the least
  recently bound trusted devices beyond that limit, and released devices'
  sessions are revoked. `revoked` is terminal for activation; an operator
  must `release` it explicitly (audited, sessions revoked) before a new OOB
  binding succeeds. `released → trusted` happens through a fresh activation.
- **OOB code**: `pending → consumed | expired`; re-issue only after the resend
  interval and only while `pending`/`expired`. Issuing a new code immediately
  consumes any older pending code for the same license+device. The attempt
  ladder is kept in separate per-license+device state that survives
  re-activation; admin unlock clears it. Wrong-code attempts are incremented
  atomically in the store.
- **Session**: `active → superseded → ended`; `superseded` heartbeats are
  served inside the grace window, rejected after it.

## 8. Deliberate non-goals

- No plaintext HTTP in production; no telemetry uploads of any kind.
- No client-supplied trust is believed without a cryptographic proof under
  the keys the client presents; those keys are TOFU, not certificate-backed.
  Anything the client merely asserts (fingerprint, honeypot flag) is a hint.
- No key material on the wire except wrapped to the client's ephemeral KEM
  key.
- No anti-debug theater; tamper resistance is server-side enforcement plus
  encrypted payloads (see `THREAT_MODEL.md`).
