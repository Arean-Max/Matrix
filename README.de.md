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

### Übersicht

**Matrix** (Event Horizon) ist eine autonome, selbst gehostete Softwarelizenzierungs- und Manipulationsschutz-Infrastruktur, die speziell für Windows-Desktopanwendungen entwickelt wurde. Es verbindet die Hardware-gebundene TPM 2.0-Gerätebescheinigung mit kryptografischen Laufzeitmieten, Out-of-Band-Challenge-Aktivierungen und der Bereitstellung versiegelter Pakete.

Keine Telemetrie von Drittanbietern, keine Anbieterbindung und keine externen Abhängigkeitsaufrufe über Ihren selbst gehosteten Servercluster hinaus.
---
### Komponenten

| Komponente | Stapel | Zweck |
| :--- | :--- | :--- |
| `cmd/eh-server` | Go 1.27+ & SQLite | Kern-HTTP-API: Lizenzierungs-Engine, OOB-Überprüfung, SQLite-Speicher, Hintergrundbereinigung, Hausmeister |
| `cmd/ehctl` | Gehen Sie zu CLI | Bedienerschnittstelle: PKI-Bootstrapping, Lizenzausstellung, Gerätelebenszyklus, Paketimporte, Backups |
| `cmd/eh-builder` | Gehen Sie zu CLI | Anbieter-Packager: Wandelt Binärdateien in verschlüsselte „.ehpkg“-Verteilungen und Bereitstellungsmanifeste um |
| `rust/eh-core` | Rost | Virtuelle Maschine mit Bytecode „EHVM1“ und Assembler für den Ausführungsschutz (siehe [docs/VM.md](docs/VM.md)) |
| `rust/eh-trustd` | Rost (isoliert) | Sandboxed TPM Quote Verifier: Analysiert rohe Hardwarestrukturen ohne DB, Sockets oder geheimen Zugriff |
| `rust/eh-client` | Rust & C FFI | Windows-Client-SDK: TLS, TPM2/TBS-Bindungen, DPAPI-Maschinenspeicher, C-ABI-Header, Demo-Client |
---
### Schnellstart

#### 1. Serverbereitstellung

Voraussetzungen: Go 1.27.3+, Rust 1.99+ (für isolierten Verifier-Build).

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

Nutzen Sie das unter „<data_dir>/bootstrap.token“ generierte Einmal-Bootstrap-Token, um die Master-Administrator-Anmeldeinformationen zu erstellen:

```bash
ehctl init --bootstrap-file /var/lib/eh/bootstrap.token \
    --server https://127.0.0.1:8443 --ca /etc/eh/tls/ca.pem
```

#### 2. Lizenzausstellung und Paketversiegelung

```bash
# Generate a new customer license key
ehctl license create --customer "Acme Corp" --channel manual
# Output: EH1-XXXXX-XXXXX-XXXXX-XXXXX

# Seal binary payload into protected distribution package
eh-builder pack --id demo-core --name "Demo Core" --in app.bin
# Output: demo-core.ehpkg (public) + demo-core.provision.json (secret)
ehctl packages import demo-core.provision.json
```

#### 3. Client-Validierung (Windows)

Voraussetzungen: Windows 10/11, TPM 2.0 (optionaler Fallback).

```powershell
cd rust; cargo build --release -p eh-client
target\release\eh-demo.exe --server https://lic.example.com:8443 `
    --license EH1-... --ca ca.pem --package-id demo-core `
    --package-file demo-core.ehpkg --heartbeats 3
```
---
### FAQ

#### Wie funktioniert die TPM-gestützte Attestierung?
Client-Computer generieren einen Endorsement Key (EK) und einen Attestation Key (AK) direkt in ihrem Hardware-TPM 2.0-Chip. Während der Sitzungsvalidierung übermittelt der Client ein kryptografisches Angebot über Hardware-PCR-Register. Der „eh-trustd“-Daemon überprüft die kryptografische Signatur, ohne Zugriff auf private Geheimnisse zu benötigen.

#### Ruft Matrix Benutzer an oder verfolgt sie sie?
Nein. Matrix ist völlig privat und wird selbst gehostet. Es kommuniziert nicht mit externen Analysen, Lizenz-Clouds oder externen Identitätsanbietern. Die gesamte Netzwerkkommunikation bleibt ausschließlich zwischen Ihren Clients und Ihrer eigenen Serverinstanz.

#### Können Clientanwendungen ohne TPM 2.0-Hardware ausgeführt werden?
Ja. Clients können „--no-tpm“ angeben, um sich unter der Nur-Software-Vertrauensstufe zu registrieren. In Umgebungen ohne TPM-Chips werden Lizenzen und kryptografische Heartbeats immer noch über Out-of-Band-Verifizierung und Standard-DPAPI-Speicher durchgesetzt.

#### Was passiert, wenn ein Gerät offline ist?
Lizenzen unterstützen konfigurierbare Leasingfenster. Clientanwendungen können für die Dauer ihrer aktiven Lease weiter betrieben werden, bevor eine Online- oder Out-of-Band-Erneuerung erforderlich ist.
---
### Dokumentation & Architektur

- [Protokollspezifikation](docs/PROTOCOL.md) – Normatives Wire-Protokoll, Endpunkte und Client-/Administrator-Zustandsmaschinen
- [Architekturübersicht](docs/ARCHITECTURE.md) – Subsystemgrenzen, Fehlermodi und Bedrohungsgrenzen
- [Architecture Decisions (ADR)](docs/DECISIONS.md) – Designgründe und Kompromisse
– [VM-Spezifikation](docs/VM.md) – EHVM1-Bytecode-Format und Ausführungssemantik
– [Bedrohungsmodell](docs/THREAT_MODEL.md) – Bedrohungslandschaft, Restrisiko und Annahmen zur Hardwaresicherheit
- [Security Hardening](docs/SECURITY.md) – Kryptografische Inventarisierung und Berichtsverfahren
- [Betriebshandbuch](docs/OPERATIONS.md) – Sicherung, Wiederherstellung, Rotation und Tag-2-Vorgänge
---
### Tests

```bash
go test ./...            # server: unit and HTTP integration test suite
go test -race ./...      # race detector suite (requires gcc)
cd rust && cargo test    # VM, client SDK, and trustd verifier suites
```
---
### Lizenz

Doppellizenziert unter:
- [Apache-Lizenz, Version 2.0](LICENSE-APACHE)
- [MIT-Lizenz](LICENSE-MIT)

nach Ihrer Wahl.