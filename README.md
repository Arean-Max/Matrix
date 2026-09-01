# Event Horizon

Self-hosted software licensing with TPM-assisted device attestation for
Windows applications. One Go server, one optional Rust trust daemon, one
operations CLI, one vendor-side packager, one Rust client SDK.

## Components

| Path | What it is |
|------|------------|
| `cmd/eh-server` | HTTP API server: SQLite storage, licensing, OOB codes |
| `cmd/ehctl` | operator CLI: PKI bootstrap, licenses, devices, packages |
| `cmd/eh-builder` | vendor CLI: packages a payload into a sealed `.ehpkg` |
| `rust/eh-core` | `EHVM1` bytecode machine and assembler |
| `rust/eh-trustd` | isolated TPM quote verifier |
| `rust/eh-client` | Windows client SDK: TLS, TPM2/TBS, DPAPI state |

## Client Demo

```powershell
cd rust; cargo build --release -p eh-client
target\release\eh-demo.exe --server https://lic.example.com:8443
```
