<p align="center">
  <a href="https://github.com/Arean-Max/Matrix">
    <img src="docs/banner.jpg" alt="Matrix banner" width="600">
  </a>
</p>

<p align="center">Self-hosted software licensing platform with TPM-assisted hardware attestation for Windows applications.</p>

<p align="center">
  <a href="https://github.com/Arean-Max/Matrix/releases"><img alt="Releases" src="https://img.shields.io/github/v/release/Arean-Max/Matrix?style=flat-square&color=emerald" /></a>
  <a href="LICENSE-MIT"><img alt="License" src="https://img.shields.io/badge/License-MIT%2FApache--2.0-blue?style=flat-square" /></a>
  <a href="https://microsoft.com/windows"><img alt="Platform" src="https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20%7C%20Linux%20(Server)-informational?style=flat-square" /></a>
  <a href="https://deepwiki.com/Arean-Max/Matrix"><img alt="Docs" src="https://img.shields.io/badge/Docs-DeepWiki-blueviolet?style=flat-square" /></a>
  <a href="https://gitdiagram.com/Arean-Max/Matrix"><img alt="Architecture" src="https://img.shields.io/badge/Diagram-GitDiagram-orange?style=flat-square" /></a>
</p>

<p align="center">
  <a href="https://github.com/Arean-Max/Matrix/releases">
    <img src="docs/preview.svg" alt="Matrix Architecture & Node Topology" width="300" />
  </a>
</p>

---

### Overview

**Matrix** (Event Horizon) is an autonomous, self-hosted software licensing and anti-tamper infrastructure designed specifically for Windows desktop applications. It couples hardware-bound TPM 2.0 device attestation with cryptographic runtime leases, out-of-band challenge activations, and sealed package provisioning.

Zero third-party telemetry, zero vendor lock-in, and zero external dependency calls beyond your self-hosted server cluster.

---

### Components

| Component | Stack | Purpose |
| :--- | :--- | :--- |
| `cmd/eh-server` | Go 1.27+ & SQLite | Core HTTP API: licensing engine, OOB verification, SQLite storage, background cleanup janitor |
| `cmd/ehctl` | Go CLI | Operator interface: PKI bootstrapping, license issuance, device lifecycle, package imports, backups |
| `cmd/eh-builder` | Go CLI | Vendor packager: transforms binaries into encrypted `.ehpkg` distributions and provisioning manifests |
| `rust/eh-core` | Rust | `EHVM1` bytecode virtual machine and assembler for execution protection (see [docs/VM.md](docs/VM.md)) |
| `rust/eh-trustd` | Rust (Isolated) | Sandboxed TPM quote verifier: parses raw hardware structures without DB, sockets, or secret access |
| `rust/eh-client` | Rust & C FFI | Windows client SDK: TLS, TPM2/TBS bindings, DPAPI machine storage, C ABI header, demo client |

---

### Quickstart

#### 1. Server Deployment

Prerequisites: Go 1.27.3+, Rust 1.99+ (for isolated verifier build).

```bash
# Build server binaries and tooling
mkdir -p bin
go build -o bin/eh-server ./cmd/eh-server
go build -o bin/ehctl ./cmd/ehctl
go build -o bin/eh-builder ./cmd/eh-builder
cargo build --release --manifest-path rust/Cargo.toml -p eh-trustd
export PATH="$PWD/bin:$PATH"

# Setup configuration (TLS mandatory by default)
cp deploy/config/server.example.yaml server.yaml
eh-server -config server.yaml
```

Consume the single-use bootstrap token generated at `<data_dir>/bootstrap.token` to create the master administrator credential:

```bash
ehctl init --bootstrap-file /var/lib/eh/bootstrap.token \
    --server https://127.0.0.1:8443 --ca /etc/eh/tls/ca.pem
```

#### 2. License Issuance & Package Sealing

```bash
# Generate a new customer license key
ehctl license create --customer "Acme Corp" --channel manual
# Output: EH1-XXXXX-XXXXX-XXXXX-XXXXX

# Seal binary payload into protected distribution package
eh-builder pack --id demo-core --name "Demo Core" --in app.bin
# Output: demo-core.ehpkg (public) + demo-core.provision.json (secret)
ehctl packages import demo-core.provision.json
```

#### 3. Client Validation (Windows)

Prerequisites: Windows 10/11, TPM 2.0 (optional fallback).

```powershell
cd rust; cargo build --release -p eh-client
target\release\eh-demo.exe --server https://lic.example.com:8443 `
    --license EH1-... --ca ca.pem --package-id demo-core `
    --package-file demo-core.ehpkg --heartbeats 3
```

---

### FAQ

#### How does TPM-assisted attestation work?
Client machines generate an Endorsement Key (EK) and Attestation Key (AK) directly inside their hardware TPM 2.0 chip. During session validation, the client submits a cryptographic quote over hardware PCR registers. The `eh-trustd` daemon verifies the cryptographic signature without needing access to private secrets.

#### Does Matrix phone home or track users?
No. Matrix is completely private and self-hosted. It does not communicate with external analytics, license clouds, or third-party identity providers. All network communication remains strictly between your clients and your own server instance.

#### Can client applications run without TPM 2.0 hardware?
Yes. Clients can specify `--no-tpm` to register under the software-only trust tier. In environments lacking TPM chips, licenses and cryptographic heartbeats are still enforced via out-of-band verification and standard DPAPI storage.

#### What happens if a device is offline?
Licenses support configurable lease windows. Client applications can continue operating for the duration of their active lease before requiring an online or out-of-band renewal.

---

### Documentation & Architecture

- [Protocol Specification](docs/PROTOCOL.md) — Normative wire protocol, endpoints, and client/admin state machines
- [Architecture Overview](docs/ARCHITECTURE.md) — Subsystem boundaries, failure modes, and threat boundaries
- [Architecture Decisions (ADR)](docs/DECISIONS.md) — Design rationales and trade-offs
- [VM Specification](docs/VM.md) — EHVM1 bytecode format and execution semantics
- [Threat Model](docs/THREAT_MODEL.md) — Threat landscape, residual risk, and hardware security assumptions
- [Security Hardening](docs/SECURITY.md) — Cryptographic inventory and reporting procedures
- [Operations Guide](docs/OPERATIONS.md) — Backup, restore, rotation, and day-2 operations

---

### Tests

```bash
go test ./...            # server: unit and HTTP integration test suite
go test -race ./...      # race detector suite (requires gcc)
cd rust && cargo test    # VM, client SDK, and trustd verifier suites
```

---

### License

Dual-licensed under either:
- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
