<p align="center"></p>
  <a href="https://github.com/Arean-Max/Matrix">
    <picture>
      <source srcset="docs/logo-dark.png" media="(prefers-color-scheme: dark)">
      <source srcset="docs/logo-light.png" media="(prefers-color-scheme: light)">
      <img src="docs/logo.png" alt="Matrix logo" width="560">
    </picture>
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
  <a href="README.md">English</a> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.zht.md">繁體中文</a> |
  <a href="README.ko.md">한국어</a> |
  <a href="README.de.md">Deutsch</a> |
  <a href="README.es.md">Español</a> |
  <a href="README.fr.md">Français</a> |
  <a href="README.it.md">Italiano</a> |
  <a href="README.da.md">Dansk</a> |
  <a href="README.ja.md">日本語</a> |
  <a href="README.pl.md">Polski</a> |
  <a href="README.ru.md">Русский</a> |
  <a href="README.bs.md">Bosanski</a> |
  <a href="README.ar.md">العربية</a> |
  <a href="README.no.md">Norsk</a> |
  <a href="README.br.md">Português (Brasil)</a> |
  <a href="README.th.md">ไทย</a> |
  <a href="README.tr.md">Türkçe</a> |
  <a href="README.uk.md">Українська</a> |
  <a href="README.bn.md">বাংলা</a> |
  <a href="README.gr.md">Ελληνικά</a> |
  <a href="README.vi.md">Tiếng Việt</a>
</p>

<p align="center">
  <a href="https://github.com/Arean-Max/Matrix/releases">
    <img src="docs/preview.svg" alt="Matrix Architecture & Node Topology" width="300" />
  </a>
</p>

---

### Oversigt

**Matrix** (Event Horizon) er en selvstændig, selvhostet softwarelicens- og anti-manipulationsinfrastruktur designet specifikt til Windows-desktopapplikationer. Det kobler hardware-bundet TPM 2.0-enhedsattestering med kryptografiske runtime-leasingkontrakter, out-of-band-udfordringsaktiveringer og forseglet pakkeklargøring.

Nul tredjeparts telemetri, nul leverandørlåsning og nul eksterne afhængighedsopkald ud over din selvhostede serverklynge.
---
### Komponenter

| Komponent | Stak | Formål |
| :--- | :--- | :--- |
| `cmd/eh-server` | Go 1.27+ & SQLite | Core HTTP API: licensmotor, OOB-verifikation, SQLite-lagring, oprydningsvagt i baggrunden |
| `cmd/ehctl` | Gå til CLI | Operatørgrænseflade: PKI-bootstrapping, licensudstedelse, enhedens livscyklus, pakkeimport, backups |
| `cmd/eh-builder` | Gå til CLI | Leverandørpakker: transformerer binære filer til krypterede `.ehpkg`-distributioner og klargøringsmanifester |
| `rust/eh-kerne` | Rust | `EHVM1` bytekode virtuel maskine og assembler til eksekveringsbeskyttelse (se [docs/VM.md](docs/VM.md)) |
| `rust/eh-trustd` | Rust (Isoleret) | Sandboxed TPM-citatverifikator: analyserer rå hardwarestrukturer uden DB, sockets eller hemmelig adgang |
| `rust/eh-klient` | Rust & C FFI | Windows-klient-SDK: TLS, TPM2/TBS-bindinger, DPAPI-maskinelagring, C ABI-header, demoklient |
---
### Hurtigstart

#### 1. Serverinstallation

Forudsætninger: Go 1.27.3+, Rust 1.99+ (til isoleret verifikatorbyggeri).

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

Brug engangs-bootstrap-tokenet, der er genereret ved `<data_dir>/bootstrap.token` for at oprette masteradministrator-legitimationsoplysningerne:

```bash
ehctl init --bootstrap-file /var/lib/eh/bootstrap.token \
    --server https://127.0.0.1:8443 --ca /etc/eh/tls/ca.pem
```

#### 2. Licensudstedelse og pakkeforsegling

```bash
# Generate a new customer license key
ehctl license create --customer "Acme Corp" --channel manual
# Output: EH1-XXXXX-XXXXX-XXXXX-XXXXX

# Seal binary payload into protected distribution package
eh-builder pack --id demo-core --name "Demo Core" --in app.bin
# Output: demo-core.ehpkg (public) + demo-core.provision.json (secret)
ehctl packages import demo-core.provision.json
```

#### 3. Klientvalidering (Windows)

Forudsætninger: Windows 10/11, TPM 2.0 (valgfri fallback).

___KODEBLOCK_3___
---
### FAQ

#### Hvordan fungerer TPM-assisteret attestation?
Klientmaskiner genererer en Endorsement Key (EK) og Attestation Key (AK) direkte inde i deres hardware TPM 2.0-chip. Under sessionsvalidering indsender klienten et kryptografisk tilbud over hardware PCR-registre. `eh-trustd`-dæmonen verificerer den kryptografiske signatur uden at skulle have adgang til private hemmeligheder.

#### Telefoner Matrix hjemme eller sporer brugere?
Nej. Matrix er helt privat og selv-hostet. Den kommunikerer ikke med eksterne analyser, licensskyer eller tredjeparts identitetsudbydere. Al netværkskommunikation forbliver strengt mellem dine klienter og din egen serverinstans.

#### Kan klientprogrammer køre uden TPM 2.0-hardware?
Ja. Klienter kan angive `--no-tpm` for at registrere sig under tillidsniveauet kun for software. I miljøer, der mangler TPM-chips, håndhæves licenser og kryptografiske hjerteslag stadig via out-of-band-verifikation og standard DPAPI-lagring.

#### Hvad sker der, hvis en enhed er offline?
Licenser understøtter konfigurerbare leasingvinduer. Klientapplikationer kan fortsætte med at fungere i løbet af deres aktive leasingaftale, før de kræver en online- eller out-of-band-fornyelse.
---
### Dokumentation og arkitektur

- [Protokolspecifikation](docs/PROTOCOL.md) - Normativ trådprotokol, endepunkter og klient-/adminstatsmaskiner
- [Arkitekturoversigt](docs/ARCHITECTURE.md) — Subsystemgrænser, fejltilstande og trusselsgrænser
- [Arkitekturbeslutninger (ADR)](docs/DECISIONS.md) — Designrationaler og afvejninger
- [VM-specifikation](docs/VM.md) — EHVM1-bytekodeformat og udførelsessemantik
- [Trusselsmodel](docs/THREAT_MODEL.md) - Trusselslandskab, resterende risiko og hardwaresikkerhedsantagelser
- [Security Hardening](docs/SECURITY.md) — Kryptografisk opgørelse og rapporteringsprocedurer
- [Operations Guide](docs/OPERATIONS.md) - Sikkerhedskopiering, gendannelse, rotation og dag-2 operationer
---
### Tester

```bash
go test ./...            # server: unit and HTTP integration test suite
go test -race ./...      # race detector suite (requires gcc)
cd rust && cargo test    # VM, client SDK, and trustd verifier suites
```
---
### Licens

Dobbeltlicenseret under enten:
- [Apache-licens, version 2.0](LICENSE-APACHE)
- [MIT-licens](LICENSE-MIT)

efter eget valg.