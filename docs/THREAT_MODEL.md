# Event Horizon — Threat model

Scope: a vendor ships a licensed Windows application; an operator runs the
Event Horizon server. This document states what the system defends against,
with what mechanism, and what risk remains. It is deliberately unflattering
where honesty requires it — v1 failed precisely because it pretended
otherwise.

## 1. Assets

| Asset | Where it lives | Consequence of compromise |
|-------|----------------|---------------------------|
| License keys (`EH1-…`) | customer machines, server HMACs only | unauthorized installations until revocation |
| Session material (PoP key, heartbeat secret, `vm_seed`) | client memory; server stores the public/derived halves | forged heartbeats / derived payload keys for that session |
| Package key (`k_pkg`) | server DB (field-encrypted), provision file; delivered wrapped per session | payload decryption for anyone holding the `.ehpkg` |
| OOB activation codes | server DB (field-encrypted), delivery channel | binding an attacker's device to a license |
| Admin tokens / mTLS keys | operator machines | full administrative control |
| Audit trail | server DB | loss of accountability after an incident |
| Master key | `EH_MASTER_KEY` / `<data_dir>/master.key` | total: all HMACs and field encryption |
| Device fingerprints | client machines, server DB | (low sensitivity; privacy note below) |

## 2. Adversaries and mitigations

### A1 — Casual sharing (same key, different machine)

*Mechanism.* `activate` binds a fingerprint to the license; a new device
needs an out-of-band code issued to the license's channel. `max_devices`
keeps at most N trusted devices: binding a new one releases the oldest.
Every binding, reveal and unlock is audited.

*Residual.* Sharing including the OOB channel (e.g. a shared mailbox) can't
be distinguished from the legitimate owner. That is a business problem;
`max_devices` bounds the damage.

### A2 — Same machine image run twice (clone)

*Mechanism.* Heartbeats carry a monotonic `seq` and the previous `ack`; the
server chains them (HMAC) and rejects replays and forks
(`ack_chain_broken`). Two live instances from one session show up as a clone
indicator; policy is `clone.action: flag | suspend`. Superseding sessions get
a grace window so a slow retransmit doesn't self-trigger.

*Residual.* An attacker who stops heartbeats entirely just runs offline —
bounded by `lease_exp + offline_grace_s` (advisory, see A4), then the server
would refuse renewed sessions only if it notices. A clone that never
reconnects is invisible; the lease is the backstop.

### A3 — Traffic interception / man in the middle

*Mechanism.* TLS 1.2+ is mandatory (plain HTTP only via the explicit
`security.dev_allow_http` development switch). The client can additionally
pin the server's SPKI hash (`--pin`), defeating a compromised local root
store. Challenge/verify responses are replay-protected by single-use nonces.

*Residual.* Attestation says "this TPM, running this software, produced this
quote" — it does not attest the OS. A rooted host can lie to itself, but it
cannot lie to the server about what the TPM signed.

### A4 — Local attacker on the client machine

This is the honest limit. Code that runs on an untrusted machine is
untrusted. Concretely:

- The client's memory holds session and package keys; anyone with
  administrative access can page, dump or instrument the process.
- The offline window (`lease_exp + offline_grace_s`) is enforced by client
  code; patching or a rolled-back clock extends it. The server, once
  reachable, remains the authority: heartbeats are monotonic and leases
  expire.
- `eh-core` (`EHVM1`) executes vendor bytecode with the session seed. It is
  a convenience for vendors to derive per-session material without writing
  their own scheme — **not** a security boundary. No bytecode obfuscation
  claims are made.
- DPAPI protects the at-rest state file against other users on the machine,
  not against the machine's owner.

*Residual.* Full compromise of the client yields that client's material for
that session. Mechanisms that limit the blast radius: per-session keys,
server-side revocation, and short leases.

### A5 — Piracy at scale (someone cracks the client once and ships a patch)

*Mechanism.* Server-side checks: revocation, device binding, OOB, leases,
attestation trust levels. A patched client still cannot make the server
bind unlimited devices, mint codes, or extend leases.

*Residual.* A patched client with its checks removed can run whatever it
holds offline for the grace window (and longer, if the attacker keeps it
offline forever). This is inherent to client-side enforcement.

### A6 — Attestation forgery

*Mechanism.* Quotes are verified against the claimed AK; the AK `name` must
be the hash of the AK public area, and the server binds activation to the
enrolled EK. Trust ladder: `tpm-attested` (activation
proof + quote), `tpm-quote` (quote only), `ek-bound` (activation proof only),
`unattested`. With `attestation.mode: required` only `tpm-attested` passes:
the request must carry both a valid quote and an activation bundle.

*Residual.* The EK is enrolled on first use (TOFU), and neither the EK nor the
AK is certificate-backed. The activation blob is encrypted to a client-supplied
EK public key, so a patched client can generate software EK/AK keys, decrypt
its own blob, sign the quote, and be recorded as `tpm-attested`. The tier says
which proofs the client produced, not that a physical TPM produced them. An
attacker who reaches the license before its owner can also enroll first; OOB
delivery out of band and `ek_hash` review raise the cost but do not close this.
DRM-grade enforcement requires EK certificate validation (out of scope).

### A7 — OOB code brute force

*Mechanism.* 8-digit codes (10^8 space), stored as constant-time HMACs,
attempts counted per license+device across reactivations with a ladder
(5 → 5 min, doubling, 1 h cap; 10 → 24 h or explicit unlock). Re-activation
does not reset attempts. Rate limits: 5/min per IP, 6/h per license; a
fixed response floor flattens timing.

*Residual.* A 10^8 space is fine only because of the attempt ladder — an
online attacker gets ~5 tries before minutes-long locks. Do not raise
`oob.max_attempts` without thinking.

### A8 — Stolen server database

*Mechanism.* Secrets are field-encrypted (AES-256-GCM under an HKDF subkey
of the master key); license keys exist only as HMACs; the master key is a
separate file (`0600`) or environment variable, not in the database, not in
backups taken with `ehctl backup`.

*Residual.* Metadata (customers, fingerprints, timestamps, audit trail) is
plaintext in the copy. The master key file on the same host must be
protected (root-only, exclude from host-wide backups you don't trust).

### A9 — Server compromise / malicious admin

The admin plane is fully privileged by design (create, revoke, reveal OOB
codes). Admin access is bearer tokens (`argon2id`-hashed at rest) and/or
mTLS; every mutation lands in the audit trail. No attempt is made to defend
against a malicious operator: they own the deployment.

### A10 — Denial of service

Body cap (1 MiB), strict Content-Type, header cap (16 KiB), read/write
timeouts, per-IP and per-endpoint rate limits, response floor on
unauthenticated endpoints. The server is single-tenant: one node, one
SQLite file, no upstream dependencies to amplify against.

### A11 — Supply chain

Small dependency sets, no cgo (pure-Go SQLite), `go.sum` pinned; the Rust
side pins `Cargo.lock` and avoids the system TLS stack surprises by vendoring
rustls/webpki-roots. Binaries are reproducible from source with the
documented toolchains.

## 3. Privacy

The system collects exactly what licensing needs: customer name/note, device
fingerprints (unsalted SHA-256 of `MachineGuid` + hostname + volume serial;
no other machine data), timestamps, and audit records. No telemetry, no crash
reports, no third-party endpoints.
Fingerprints are hashes: they identify a machine to the server, not a user
to the world, but treat them as personal data where GDPR applies (see
`docs/SECURITY.md` for the data-handling checklist).

## 4. Explicit non-goals

- Stopping a determined reverse engineer with full local control
  (`THREAT_MODEL.md` A4/A5).
- DRM-grade EK certificate validation (out of scope, ADR-008/019).
- Anti-debugging, code obfuscation, self-modifying payloads — deleted with
  v1, they were theater (ADR-011).
- Defending the server host itself: use OS hardening, firewalls and the
  supplied deploy artifacts.
