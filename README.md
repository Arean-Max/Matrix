# Event Horizon

Self-hosted software licensing with TPM-assisted device attestation for
Windows applications. One Go server, one optional Rust trust daemon, one
operations CLI, one vendor-side packager, one Rust client SDK. No telemetry,
no third-party services, no phone-home beyond your own server.

This raises the cost of casual piracy and makes shared licenses traceable and
revocable. A determined attacker who controls the client machine can still get
past it; `docs/THREAT_MODEL.md` has the details. Attestation is TOFU-anchored:
the server verifies quote and activation proofs under the EK/AK the client
presents, but it does not validate EK certificates, so a patched client can
manufacture software keys and still reach the top tier. Treat the tier as a
signal, not as a hardware guarantee.

## Components

| Path | What it is |
|------|------------|
| `cmd/eh-server` | HTTP API server: SQLite storage, licensing, OOB codes, TPM attestation, janitor |
| `cmd/ehctl` | operator CLI: PKI bootstrap, licenses, devices, packages, audits, tokens, backup |
| `cmd/eh-builder` | vendor CLI: packages a payload into a sealed `.ehpkg` + provision request |
| `rust/eh-core` | `EHVM1` bytecode machine and assembler (see `docs/VM.md`) |
| `rust/eh-trustd` | isolated TPM quote verifier: parses untrusted TPM bytes, verifies signatures, holds no DB/keys/sockets |
| `rust/eh-client` | Windows client SDK: TLS, TPM2/TBS, DPAPI state, C ABI, demo binary |
| `internal/…` | server packages with hard module boundaries (see `docs/ARCHITECTURE.md`) |

## Quickstart (server)

Requirements: Go 1.27.3+ (the patch fixes GO-2026-6809 in `crypto/x509`), Rust 1.99+ only if you want the isolated verifier.

```sh
# 1. Build
mkdir -p bin
go build -o bin/eh-server ./cmd/eh-server
go build -o bin/ehctl ./cmd/ehctl
go build -o bin/eh-builder ./cmd/eh-builder
cargo build --release --manifest-path rust/Cargo.toml -p eh-trustd
export PATH="$PWD/bin:$PATH"

# 2. Configure (TLS is mandatory unless you set security.dev_allow_http)
cp deploy/config/server.example.yaml server.yaml   # edit tls.* and trustd_path
# the example enables /usr/local/bin/eh-trustd; point it at the absolute
# path of rust/target/release/eh-trustd, or delete the key for embedded mode
eh-server -config server.yaml
```

On the first start the server writes `<data_dir>/bootstrap.token` and logs
the path. Consume it once to create a real admin token; the server deletes the
file as soon as the first token exists:

```sh
ehctl init --bootstrap-file /var/lib/eh/bootstrap.token \
    --server https://127.0.0.1:8443 --ca /etc/eh/tls/ca.pem
```

Then create a license and (optionally) a package:

```sh
ehctl license create --customer "Acme" --channel manual
# -> prints the license key ONCE: EH1-XXXXX-XXXXX-XXXXX-XXXXX

eh-builder pack --id demo-core --name "Demo Core" --in app.bin
# -> demo-core.ehpkg (ship it) + demo-core.provision.json (SECRET)
ehctl packages import demo-core.provision.json
```

## Quickstart (Windows client demo)

Requirements: Rust 1.99+, Windows 10/11, TPM 2.0 for the full flow.

```powershell
cd rust; cargo build --release -p eh-client
target\release\eh-demo.exe --server https://lic.example.com:8443 `
    --license EH1-... --ca ca.pem --package-id demo-core `
    --package-file demo-core.ehpkg --heartbeats 3
```

`--no-tpm` skips attestation (device lands on the weakest trust level),
exit code 2 means an out-of-band activation code is required — reveal it
with `ehctl license oob <license-id>` and re-run with `--code`.

## Docs

| Document | Content |
|----------|---------|
| `docs/PROTOCOL.md` | normative wire protocol: client API, admin API, state machines |
| `docs/ARCHITECTURE.md` | module layout, runtime model, failure modes |
| `docs/DECISIONS.md` | ADR log — every "why not" is written down |
| `docs/VM.md` | EHVM1 bytecode format and ISA |
| `docs/THREAT_MODEL.md` | assets, adversaries, mitigations, residual risk |
| `docs/SECURITY.md` | crypto inventory, hardening checklist, reporting |
| `docs/OPERATIONS.md` | day-2 operations, backup/restore, troubleshooting |
| `deploy/` | Dockerfile, compose, systemd unit, backup script, config example |

## Tests

```sh
go test ./...            # server: unit + full HTTP integration
go test -race ./...      # same under the race detector (needs gcc)
cd rust && cargo test    # VM + client + trustd (crypto, http, state, tpm parsing)
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
