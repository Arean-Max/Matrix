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
Cargo workspace with `eh-core` (VM), `eh-client` (SDK) and `eh-trustd`
(isolated TPM verifier).
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
create`, and/or mTLS against an admin CA. mTLS certificates are accepted only
when their CN is listed in `security.mtls_admin_cns`; a valid certificate from
the CA is not sufficient by itself. A SHA-256 lookup hash selects a single row
before the memory-hard verification; legacy rows are backfilled on first
successful use. Bootstrap token written once to `data/bootstrap.token` (0600),
disabled after the first API-created token and deleted immediately; a stale
file is removed on the next start. Every admin action and failed admin
authentication is audited, with `auth.fail` rows capped per source address.
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
