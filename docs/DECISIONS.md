# Event Horizon — Decision Log (ADRs)

Short records of the choices that shape this codebase, kept for the next
engineer who asks "why is it like this". Newest at the bottom.

## ADR-001 — Language split: Go server, Rust client, no C++
**Decision.** Server, CLIs and builder are Go; the Windows client SDK and the
protected runtime are Rust. The v1 C++ client and C++ LLVM passes are gone.
**Why.** Rust removes the entire memory-safety class of bugs from the
client — the component that faces hostile users — and unifies client and VM
in one toolchain, eliminating the v1 FFI boundary. Go is the right shape for
the server: one static binary, strong stdlib HTTP/crypto, easy ops.
**Alternatives.** C++ client kept: rejected (v1 audit found UB, stale stack
pointers, inverted tamper checks — a language whose failure mode is RCE is a
bad fit for a security product). Rust server: viable but doubles rewrite cost
for marginal gain; Go's stdlib crypto and ops story win here.

## ADR-002 — One Go module, one Rust workspace
**Decision.** `go.mod` at the root serves all three Go binaries; `rust/` is a
Cargo workspace with `eh-core` and `eh-client`.
**Why.** Shared `internal/` packages (wire, packaging) must not become copies;
separate modules would force version pinning inside one repo.

## ADR-003 — SQLite (modernc, no cgo) as the only store
**Decision.** SQLite in WAL mode via pure-Go `modernc.org/sqlite`.
**Why.** Correct transactions, single-file backups, zero-ops deployment;
`database/sql` keeps a Postgres migration realistic when needed (ADR seam).
**Alternatives.** JSON file rewritten per request (v1): rejected — data races,
full-file rewrite per write, corruption on crash. Postgres now: unnecessary
operational weight for a single-tenant server.

## ADR-004 — License key format and storage
**Decision.** `EH1-XXXXX-XXXXX-XXXXX-XXXXX` Crockford base32 (100 bits),
stored as HMAC-SHA256 under an HKDF subkey. No plaintext keys in the DB.
**Why.** Typed by humans, fixed by printers; 100 bits kills guessing;
HMAC-with-subkey prevents offline dictionary attacks on a stolen DB that
plain SHA-256 would allow.

## ADR-005 — Out-of-band activation codes
**Decision.** 8-digit codes (10^8 space), HMAC-verified in constant time,
encrypted at rest for audited admin reveal, lock ladder (5 fails → 5 min,
doubling to 1 h, 10 fails → admin), attempt counters that activation cannot
reset, delivery via webhook or manual retrieval.
**Why.** v1's 6-digit unsalted-SHA256 code stored in audit logs with a
reset-the-counter-by-activating loop was a free bypass. Every part here
closes one specific v1 finding.

## ADR-006 — Admin authentication
**Decision.** argon2id-hashed bearer tokens created via `ehctl tokens
create`, and/or mTLS against an admin CA. A SHA-256 lookup hash selects a
single row before the memory-hard verification; legacy rows are backfilled on
first successful use. Bootstrap token written once to
`data/bootstrap.token` (0600), disabled after the first API-created token.
Every admin action and failed admin authentication is audited.
**Why.** v1's "session header ≥32 chars" accepted anything. There is no
third mode; no fake checks. The lookup keeps unauthenticated requests from
multiplying Argon2 work across every stored token.

## ADR-007 — TLS is mandatory
**Decision.** The server refuses to start without certificates unless
`security.dev_allow_http: true`. `ehctl init` generates a local CA, server
cert and admin client cert so development uses real TLS too.
**Why.** v1 logged "TLS 1.3" while serving plaintext. A license server that
speaks plaintext leaks keys at the network layer.

## ADR-008 — TPM attestation design
**Decision.** Device identity = EK hash (TOFU-enrolled on first attestation).
Each session uses a fresh AK: the server builds `TPM2_MakeCredential` bound
to the AK name under the enrolled EK; the client runs
`TPM2_ActivateCredential` and proves secret possession; the quote is signed
by that AK over the server nonce. Modes: `auto` (downgrade + audit),
`required` (quote + activation), `off`. `google/go-tpm`'s `credactivation`
is used for the credential construction instead of hand-rolled TPM
marshaling.
**Why.** Fresh-AK-per-session is the only design that works with Windows TPMs
(no owner auth, no persistent keys). v1 fabricated every attestation field
and the server verified nothing; here the EK → AK → quote chain is
cryptographically verified and tested on hardware.
**Residual.** Neither key is certificate-rooted. A patched client can create
software EK/AK keys, decrypt its own activation blob and sign a quote, and the
server will record `tpm-attested`. The tier is meaningful against the shipped
SDK, not against an attacker who replaces it; see ADR-019 and THREAT_MODEL A6.
**Hardware findings (Windows 11 + Intel PTT, verified 2026-10).**
- Name convention: `name = nameAlg(2B BE) || H(content bytes)`, no size prefix
  — matches `go-tpm`'s `ObjectName`; both the EK and a loaded AK match the
  TPM-reported Name.
- The quote's `qualifiedSigner` is a digest over the whole parent chain and
  cannot be recomputed server-side (the parent names are unknown to the
  server). It is deliberately **not** checked: the signature under `ak_pub`,
  the recomputed name match, the nonce and the activation binding already pin
  the exact AK, and `fixedTPM`/`fixedParent` keep the AK inside one TPM.
- TBS blocks `TPM2_ActivateCredential` for non-elevated processes
  (`TPM_E_COMMAND_BLOCKED`, `0x80280400`); the same test passes elevated.
  Windows clients therefore land `tpm-quote` (quote without activation) unless
  they run elevated or use the Platform Crypto Provider
  (`NCryptVerifyClaim`) — documented upgrade path, not papered over.
**Alternatives.** Persistent AK: needs owner auth, blocked on many Windows
machines. Full EK certificate chain validation: valuable for enterprise, kept
as the documented upgrade path (require mode).

## ADR-009 — Heartbeat protocol
**Decision.** Ed25519 proof-of-possession over
`EH-HB1|session|seq|prev_ack` plus an HMAC ack chain
(`EH-ACK1|session|seq|sha256(sign_bytes)`), strict `seq == last+1`, one
retransmit window, server-side lease expiry enforcement.
**Why.** v1's "ack chain" was a client-side fabrication the server never
checked, and leases never expired. The new chain is cheap, replay-evident and
idempotent on response loss.

## ADR-010 — Package protection
**Decision.** `XChaCha20-Poly1305` payload encryption; key generated by
`eh-builder`, provisioned to the server once, wrapped per request via
ephemeral X25519 ECDH + HKDF to the client's per-run KEM key.
**Why.** Real authenticated encryption with real key transport. v1's
"white-box networks" had no decryption counterpart and lost the key entirely.

## ADR-011 — Removed components (and why)
- **LLVM passes** (MBA, symbolic explosion, pdata stego, dual-VM compiler):
  all four were broken (malformed IR, `sdiv 100,0` UB, semantics-destroying
  rewrites) or inert. Obfuscation that cannot compile is worse than none.
- **White-box crypto**: an XOR table network with no diffusion, mislabeled
  as Chow-Biryukov. Replaced by AEAD (ADR-010).
- **Telemetry/Ollama sentinel**: dead code with an SSRF-shaped future and an
  LLM prompt-injection surface; also telemetry contradicts the privacy goal.
- **Anti-debug theater** (cache sensor, chaff machine, .pdata stego, honeypot
  flag): EDR-hostile, ineffective, and the tamper check was inverted anyway.
  Replaced by nothing — see THREAT_MODEL for the honest position.

## ADR-012 — Client state and offline grace
**Decision.** Local state (fingerprint, session id, Ed25519 and KEM seeds,
ack/sequence, lease deadlines, VM seed, and the unwrapped package key) is
sealed with DPAPI in the current user's scope and replaced atomically. The
state is discarded when the fingerprint changes, and the package payload is
kept in memory only. Offline use is bounded by
`lease_exp + offline_grace_s`, both server-supplied at session establishment
and refreshed by heartbeats; there is no separate last-contact timestamp or
server-time anchoring.
**Why.** Restoring a session should not require a network round trip or a
second activation, and losing the state file should have an obvious, bounded
consequence. v1's grace period could never expire. Client-side clock
manipulation remains possible (see THREAT_MODEL); the server is authoritative
whenever it is reachable.

## ADR-013 — Protected runtime (eh-core)
**Decision.** A small, bounded stack interpreter: 16 memory slots of 32-byte
words (512 bytes), 16 opcodes (SHA-256, HMAC-SHA256, XOR, add, compare,
conditional jumps, input/output), a 1,000,000-step limit, and strict bounds
checks. Constants are 32-byte words; code is length-prefixed bytecode. The
assembler and the demo builder are the only producers.
**Why.** Obfuscation value is real only if the VM executes correctly; v1's
"dual ownership" was decorative and its C++/Rust implementations diverged.
Scope is documented honestly in THREAT_MODEL: the VM is a convenience for
per-session derivation, not a security boundary.

## ADR-014 — Modular monolith, not microservices
**Decision.** One server process; seams for splitting documented in
`ARCHITECTURE.md` §10.
**Why.** A single-tenant licensing server gains nothing from network splits;
it gains partial-failure modes, deployment complexity and latency. The user
requirement "separate the project into modules and services" is honored as
binaries + hard module boundaries, not as a distributed monolith.

## ADR-015 — Master key handling
**Decision.** 32-byte master key from `EH_MASTER_KEY` or a key file; subkeys
via HKDF with fixed info strings. No passphrases, no homebrew KDF.
**Why.** v1 used `sha256(passphrase)` — GPU-crackable — and its "PBKDF2 fix"
was dead code with a wrong iteration count. Key material is generated, never
guessed.

## ADR-016 — Client transport: WinHTTP, not a bundled TLS stack
*(Superseded by ADR-018.)*
**Decision.** The Rust client calls WinHTTP (via `windows-sys`) with
system certificate validation and optional SPKI pin extracted from the
server certificate handle; DPAPI for state.
**Why.** Windows-native TLS stack maintained by the OS, no extra crates,
no OpenSSL, and certificate-pin control at the API level. Fewer moving parts
in the trust chain.

## ADR-017 — No admin UI in v2
**Decision.** `ehctl` + documented admin API.
**Why.** Scope discipline; the API is the contract, a UI can come later
without touching the server.

## ADR-018 — Client transport: ureq + rustls (supersedes ADR-016)
**Decision.** The Rust client uses `ureq` 2.12 over `rustls` 0.23 (ring
provider, no process-wide provider needed) with `webpki-roots`; the optional
SPKI pin is enforced by a custom `ServerCertVerifier` that runs WebPKI
verification first and then compares SHA-256 of the leaf's
SubjectPublicKeyInfo. WinHTTP is not used; `windows-sys` remains for TBS and
DPAPI only.
**Why.** WinHTTP through `windows-sys` means manual session/handle juggling
and pin extraction from an opaque certificate handle; the rustls verifier
gives the pin check a testable seam
(`webpki::EndEntityCert::subject_public_key_info`). The whole request path
stays in memory-safe Rust with a reproducible build. "Use the OS stack and
hope" was the v1 school of thought; v2 prefers explicit, testable code.

## ADR-019 — TPM identity: endorsement-hierarchy primaries as EK/AK stand-ins
**Decision.** The client creates two primaries in the endorsement hierarchy:
an RSA-2048 storage primary as the EK stand-in (empty auth policy, so the
password session works) and an RSA-2048 restricted signing primary as the AK.
The server keeps treating `ek_pub` as an opaque TPMT_PUBLIC; the wire protocol
does not change.
**Why.** No Create/Load marshalling for persistent child keys, and both
objects are deterministic per TPM: `ek_hash` survives TPM clear, so enrolled
devices keep matching. The owner hierarchy was rejected (it dies on TPM
clear). The cost is honest and bounded: `ek_pub` carries no EK certificate,
so the authenticity of the EK is whatever first-seen enrollment grants (TOFU)
— see PROTOCOL §3.3 and ADR-008; DRM-grade EK certificate validation is out
of scope.

## ADR-020 — Spec v12 triage: adopted hardening vs rejected anti-reverse stack

**Context.** A vendor-side proposal ("Spec v12") asked for a C++20 Windows
client wrapped in eight anti-reverse layers (dual cellular-automata VM,
non-associative quasigroup MBA, white-box tables, `.pdata` exception
steganography, L1d cache-eviction sensing, chaff execution graphs, symbolic
path explosion, server-fed decoy constants), plus a list of protocol
hardening items. This ADR records what was adopted and what was rejected.

**Adopted (verifiable, testable, no new trust assumptions).**
- `X-EH-Protocol` negotiation with a single supported version, rejected
  before body decoding (`protocol_unsupported`, no fallback).
- HWID reset accounting: one reset per displaced trusted device on
  single-device licenses, 30-day cooldown, three lifetime resets, atomic
  check-increment-release in SQLite, suspension on exhaustion, admin
  `clear-resets`. OOB is still required for every re-bind.
- AK attribute policy (`restricted`, `sign`, `fixedTPM`, `fixedParent`,
  `sensitiveDataOrigin`) — already enforced by `internal/attestation`; for
  the primary-key design (ADR-019) this is the meaningful subset of the
  spec's CertifyCreation requirement.
- Deterministic clone detection with supersede grace and optional suspension
  — already implemented in `internal/licensing` (`session.clone_suspect`,
  `clone.action`).

**Rejected.**
- **C++20 client rewrite.** ADR-001 removed the v1 C++ runtime for memory
  safety and undefined behaviour; the client is the component that parses
  attacker-controlled TPM and package bytes. Rewriting it in C++ trades the
  project's strongest security property for no measurable benefit.
- **Eight-layer anti-reverse stack.** It is unverifiable by construction,
  and several layers contradict the project's EDR-compatibility goal:
  custom `.pdata` unwind handlers and non-canonical pointer faults are
  indistinguishable from malware heuristics; cache-latency thresholds fire
  under ordinary scheduler pressure; chaff execution silently corrupts
  customer output and makes support impossible; decoy constants require the
  server to keep a second, lying protocol. None of this changes the licence
  gating threat model: a determined owner can still dump a licensed process.
- **Client-side honeypot telemetry.** Hidden `honeypot_triggered` flags are
  attacker-controlled input and turn the admin panel into a disinformation
  channel. The server only accepts typed, server-verifiable signals today.
- **PoW on `/activate`.** Rate limits and the constant-time response floor
  already bound enumeration; PoW shifts cost to legitimate users and is
  trivially outsourced to GPUs. Not implemented; revisit only with evidence
  of a real enumeration campaign.
- **TCG event-log parsing, EK certificate chains (STRICT_ENTERPRISE),
  CRL/short-lived admin certificates, OS-keyring DB keys, signed lease
  tokens with `kid` rotation.** Valuable, but each is a protocol/ops project
  of its own. They are tracked as roadmap items in the audit report; the
  current honest boundary (TOFU, field-level encryption) is documented in
  `THREAT_MODEL.md` A6 and `PROTOCOL.md` §3.4.

**Consequences.** The attack surface stays small and reviewable; every new
control is covered by tests and audit records. The project does not claim
"unbreakable" client code and continues to describe itself as license gating
with economic friction, not DRM.
