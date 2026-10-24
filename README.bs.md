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

### Pregled

**Matrix** (Event Horizon) je autonomna, samostalno hostirana softverska infrastruktura za licenciranje i zaštitu od neovlaštenog pristupa dizajnirana posebno za Windows desktop aplikacije. On spaja hardverski vezanu atestu TPM 2.0 uređaja sa kriptografskim zakupom vremena izvođenja, aktivacijama izvan opsega i obezbjeđivanjem zapečaćenih paketa.

Nula telemetrija treće strane, nula zaključavanja dobavljača i nula eksternih poziva zavisnosti izvan vašeg klastera servera koji sami hostujete.
---
### Komponente

| Komponenta | Stack | Svrha |
| :--- | :--- | :--- |
| `cmd/eh-server` | Go 1.27+ & SQLite | Core HTTP API: motor za licenciranje, OOB verifikacija, SQLite skladište, čuvar pozadine |
| `cmd/ehctl` | Idi CLI | Operatorski interfejs: PKI bootstrapping, izdavanje licence, životni ciklus uređaja, uvoz paketa, rezervne kopije |
| `cmd/eh-builder` | Idi CLI | Dobavljač paketa: transformiše binarne datoteke u šifrovane `.ehpkg` distribucije i manifeste obezbeđivanja |
| `rust/eh-core` | Rust | `EHVM1` bajt kod virtuelne mašine i asemblera za zaštitu od izvršenja (pogledajte [docs/VM.md](docs/VM.md)) |
| `rust/eh-trustd` | Rust (izolirano) | Sandboxed TPM verifikator citata: analizira sirove hardverske strukture bez DB-a, utičnica ili tajnog pristupa |
| `rust/eh-client` | Rust & C FFI | Windows klijent SDK: TLS, TPM2/TBS veze, DPAPI mašinsko skladište, C ABI zaglavlje, demo klijent |
---
### Brzi početak

#### 1. Postavljanje servera

Preduslovi: Go 1.27.3+, Rust 1.99+ (za izolovanu izgradnju verifikatora).

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

Iskoristite token za jednokratnu upotrebu generiran na `<data_dir>/bootstrap.token` da kreirate glavne administratorske vjerodajnice:

```bash
ehctl init --bootstrap-file /var/lib/eh/bootstrap.token \
    --server https://127.0.0.1:8443 --ca /etc/eh/tls/ca.pem
```

#### 2. Izdavanje licence i pečaćenje paketa

```bash
# Generate a new customer license key
ehctl license create --customer "Acme Corp" --channel manual
# Output: EH1-XXXXX-XXXXX-XXXXX-XXXXX

# Seal binary payload into protected distribution package
eh-builder pack --id demo-core --name "Demo Core" --in app.bin
# Output: demo-core.ehpkg (public) + demo-core.provision.json (secret)
ehctl packages import demo-core.provision.json
```

#### 3. Validacija klijenta (Windows)

Preduslovi: Windows 10/11, TPM 2.0 (opcioni rezervni).

```powershell
cd rust; cargo build --release -p eh-client
target\release\eh-demo.exe --server https://lic.example.com:8443 `
    --license EH1-... --ca ca.pem --package-id demo-core `
    --package-file demo-core.ehpkg --heartbeats 3
```
---
### FAQ

#### Kako funkcionira atestiranje uz pomoć TPM-a?
Klijentske mašine generišu ključ za potvrdu (EK) i ključ za potvrdu (AK) direktno unutar svog hardverskog TPM 2.0 čipa. Tokom validacije sesije, klijent šalje kriptografsku ponudu preko hardverskih PCR registara. Demon `eh-trustd` provjerava kriptografski potpis bez potrebe za pristupom privatnim tajnama.

#### Da li Matrix telefonira kući ili prati korisnike?
Ne. Matrix je potpuno privatan i samostalan. Ne komunicira sa eksternom analitikom, licencnim oblacima ili dobavljačima identiteta trećih strana. Sva mrežna komunikacija ostaje striktno između vaših klijenata i vaše vlastite instance servera.

#### Mogu li klijentske aplikacije raditi bez TPM 2.0 hardvera?
Da. Klijenti mogu specificirati `--no-tpm` za registraciju pod nivoom povjerenja samo za softver. U okruženjima u kojima nedostaju TPM čipovi, licence i kriptografski otkucaji srca se još uvijek primjenjuju putem vanpojasnih verifikacije i standardnog DPAPI skladištenja.

#### Šta se dešava ako je uređaj van mreže?
Licence podržavaju konfigurabilne prozore zakupa. Klijentske aplikacije mogu nastaviti s radom za vrijeme trajanja njihovog aktivnog zakupa prije nego što zahtijevaju online ili izvanpojasnu obnovu.
---
### Dokumentacija i arhitektura

- [Specifikacija protokola](docs/PROTOCOL.md) — Normativni žičani protokol, krajnje tačke i klijent/administrator stanja mašina
- [Pregled arhitekture](docs/ARCHITECTURE.md) — Granice podsistema, načini kvara i granice prijetnji
- [Odluke o arhitekturi (ADR)](docs/DECISIONS.md) — Obrazloženja dizajna i kompromisi
- [VM specifikacija](docs/VM.md) — EHVM1 format bajtkoda i semantika izvršenja
- [Model prijetnje](docs/THREAT_MODEL.md) — Krajolik prijetnji, preostali rizik i hardverske sigurnosne pretpostavke
- [Security Hardening](docs/SECURITY.md) — Kriptografski inventar i procedure izvještavanja
- [Vodič za operacije](docs/OPERATIONS.md) — Sigurnosno kopiranje, vraćanje, rotacija i operacije drugog dana
---
### Testovi

```bash
go test ./...            # server: unit and HTTP integration test suite
go test -race ./...      # race detector suite (requires gcc)
cd rust && cargo test    # VM, client SDK, and trustd verifier suites
```
---
### Licenca

Dvostruka licenca pod:
- [Apache licenca, verzija 2.0](LICENSE-APACHE)
- [MIT licenca](LICENSE-MIT)

po vašoj želji.