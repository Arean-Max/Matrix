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
