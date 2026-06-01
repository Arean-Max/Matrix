# Event Horizon

Self-hosted software licensing with TPM-assisted device attestation for
Windows applications. One Go server, one optional Rust trust daemon, one
operations CLI, one vendor-side packager, one Rust client SDK.

## Project Structure
- `cmd/`: Go binaries (server, operator CLI, builder)
- `internal/`: Server packages with explicit boundaries
- `rust/`: Client SDK and isolated trust verifier
