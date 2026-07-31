# Event Horizon

Self-hosted software licensing with TPM-assisted device attestation for
Windows applications.

## Components

| Path | What it is |
|------|------------|
| `cmd/eh-server` | HTTP API server: SQLite storage, licensing, OOB codes |
| `rust/eh-trustd` | isolated TPM quote verifier: parses untrusted TPM bytes |
| `internal/attestation` | TPM2 quote verification and MakeCredential |

## Attestation

Attestation is TOFU-anchored: the server verifies quote and activation proofs
under the EK/AK the client presents.
