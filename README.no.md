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

### Oversikt

**Matrix** (Event Horizon) er en autonom, selvdrevet programvarelisens- og anti-tulling-infrastruktur utviklet spesielt for Windows-skrivebordsapplikasjoner. Den kobler maskinvarebundet TPM 2.0-enhetsatestasjon med kryptografiske kjøretidsleieavtaler, aktiveringer utenfor båndet og klargjøring av forseglet pakke.

Null tredjeparts telemetri, null leverandørlåsing og null eksterne avhengighetsanrop utover din egenvertsbaserte serverklynge.
---
### Komponenter

| Komponent | Stabel | Formål |
| :--- | :--- | :--- |
| `cmd/eh-server` | Go 1.27+ og SQLite | Core HTTP API: lisensieringsmotor, OOB-verifisering, SQLite-lagring, vaktmester for bakgrunnsopprydding |
| `cmd/ehctl` | Gå til CLI | Operatørgrensesnitt: PKI-oppstart, lisensutstedelse, enhetslivssyklus, pakkeimport, sikkerhetskopiering |
| `cmd/eh-builder` | Gå til CLI | Leverandørpakker: transformerer binærfiler til krypterte `.ehpkg`-distribusjoner og klargjøringsmanifester |
| `rust/eh-core` | Rust | `EHVM1` bytekode virtuell maskin og assembler for kjøringsbeskyttelse (se [docs/VM.md](docs/VM.md)) |
| `rust/eh-trustd` | Rust (isolert) | Sandboxed TPM quote verifier: analyserer rå maskinvarestrukturer uten DB, sockets eller hemmelig tilgang |
| `rust/eh-klient` | Rust & C FFI | Windows-klient-SDK: TLS, TPM2/TBS-bindinger, DPAPI-maskinlagring, C ABI-header, demoklient |
---
### Hurtigstart

#### 1. Serverdistribusjon

Forutsetninger: Gå 1.27.3+, Rust 1.99+ (for isolert verifikatorbygg).

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

Bruk engangs-bootstrap-tokenet generert på `<data_dir>/bootstrap.token` for å opprette hovedadministratorlegitimasjonen:

___KODEBLOKK_1___

#### 2. Lisensutstedelse og pakkeforsegling

___KODEBLOKK_2___

#### 3. Klientvalidering (Windows)

Forutsetninger: Windows 10/11, TPM 2.0 (valgfritt reserve).

___KODEBLOKK_3___
---
### Vanlige spørsmål

#### Hvordan fungerer TPM-assistert attestasjon?
Klientmaskiner genererer en Endorsement Key (EK) og Attestation Key (AK) direkte inne i maskinvaren TPM 2.0-brikken. Under øktvalidering sender klienten et kryptografisk tilbud over maskinvare PCR-registre. `eh-trustd`-demonen verifiserer den kryptografiske signaturen uten å trenge tilgang til private hemmeligheter.

#### Ringer Matrix hjemme eller sporer brukere?
Nei. Matrix er helt privat og selvvert. Den kommuniserer ikke med eksterne analyser, lisensskyer eller tredjeparts identitetsleverandører. All nettverkskommunikasjon forblir strengt tatt mellom klientene dine og din egen serverinstans.

#### Kan klientapplikasjoner kjøre uten TPM 2.0-maskinvare?
Ja. Klienter kan spesifisere `--no-tpm` for å registrere seg under tillitsnivået kun for programvare. I miljøer som mangler TPM-brikker, blir lisenser og kryptografiske hjerteslag fortsatt håndhevet via out-of-band-verifisering og standard DPAPI-lagring.

#### Hva skjer hvis en enhet er frakoblet?
Lisenser støtter konfigurerbare leasevinduer. Klientapplikasjoner kan fortsette å fungere i løpet av den aktive leieavtalen før de krever en fornyelse online eller utenfor båndet.
---
### Dokumentasjon og arkitektur

– [Protocol Specification](docs/PROTOCOL.md) – Normativ ledningsprotokoll, endepunkter og klient-/adminstatusmaskiner
– [Architecture Overview](docs/ARCHITECTURE.md) – Subsystemgrenser, feilmoduser og trusselgrenser
– [Arkitekturbeslutninger (ADR)](docs/DECISIONS.md) – Designrasjonaler og avveininger
- [VM-spesifikasjon](docs/VM.md) — EHVM1-bytekodeformat og kjøringssemantikk
– [Trusselsmodell](docs/THREAT_MODEL.md) – Forutsetninger om trussellandskap, gjenværende risiko og maskinvaresikkerhet
– [Security Hardening](docs/SECURITY.md) – Kryptografisk inventar og rapporteringsprosedyrer
– [Operasjonsveiledning](docs/OPERATIONS.md) – Sikkerhetskopiering, gjenoppretting, rotasjon og dag 2 operasjoner
---
### Tester

___KODEBLOKK_4___
---
### Lisens

Dobbeltlisensiert under enten:
- [Apache-lisens, versjon 2.0](LISENS-APACHE)
- [MIT-lisens](LICENSE-MIT)

etter eget valg.