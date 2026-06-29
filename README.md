# Event Horizon

Self-hosted software licensing with TPM-assisted device attestation for
Windows applications. One Go server, one optional Rust trust daemon, one
operations CLI, one vendor-side packager, one Rust client SDK.

## Components

| Path | What it is |
|------|------------|
| `cmd/eh-server` | HTTP API server: SQLite storage, licensing, OOB codes |
| `internal/store` | SQLite storage aggregate models |
| `internal/wire` | Wire protocol schemas |
| `internal/cryptox` | Key derivation and crypto primitives |

## Quickstart (server)

```sh
go build -o bin/eh-server ./cmd/eh-server
./bin/eh-server -config server.yaml
```
