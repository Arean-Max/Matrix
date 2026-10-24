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

### Panoramica

**Matrix** (Event Horizon) è un'infrastruttura anti-manomissione e di gestione delle licenze software autonoma e self-hosted progettata specificamente per le applicazioni desktop Windows. Combina l'attestazione del dispositivo TPM 2.0 legata all'hardware con lease di runtime crittografici, attivazioni di verifica fuori banda e provisioning di pacchetti sigillati.

Zero telemetria di terze parti, zero vincoli al fornitore e zero chiamate di dipendenza esterna oltre il cluster di server self-hosted.
---
### Componenti

| Componente | Pila | Scopo |
| :--- | :--- | :--- |
| `cmd/eh-server` | Vai a 1.27+ e SQLite | API HTTP principale: motore di licenza, verifica OOB, archiviazione SQLite, pulizia in background |
| `cmd/ehctl` | Vai CLI | Interfaccia operatore: bootstrap PKI, emissione di licenze, ciclo di vita del dispositivo, importazioni di pacchetti, backup |
| `cmd/eh-builder` | Vai CLI | Packager del fornitore: trasforma i file binari in distribuzioni `.ehpkg` crittografate e manifesti di provisioning |
| `ruggine/eh-core` | Ruggine | Macchina virtuale e assemblatore bytecode `EHVM1` per la protezione dell'esecuzione (vedi [docs/VM.md](docs/VM.md)) |
| `ruggine/eh-trustd` | Ruggine (isolato) | Verificatore di quote TPM in modalità sandbox: analizza le strutture hardware grezze senza DB, socket o accesso segreto |
| `rust/eh-client` | Ruggine & C FFI | SDK client Windows: TLS, collegamenti TPM2/TBS, archiviazione macchina DPAPI, intestazione C ABI, client demo |
---
### Avvio rapido

#### 1. Distribuzione del server

Prerequisiti: Go 1.27.3+, Rust 1.99+ (per build di verificatori isolati).

___BLOCCOCODICE_0___

Utilizza il token bootstrap monouso generato in "<data_dir>/bootstrap.token" per creare le credenziali dell'amministratore principale:

___BLOCCOCODICE_1___

#### 2. Emissione di licenze e sigillatura del pacchetto

___BLOCCOCODICE_2___

#### 3. Convalida client (Windows)

Prerequisiti: Windows 10/11, TPM 2.0 (fallback opzionale).

___BLOCCOCODICE_3___
---
### Domande frequenti

#### Come funziona l'attestazione assistita da TPM?
Le macchine client generano una chiave di approvazione (EK) e una chiave di attestazione (AK) direttamente all'interno del chip hardware TPM 2.0. Durante la convalida della sessione, il client invia una quotazione crittografica sui registri PCR hardware. Il demone "eh-trustd" verifica la firma crittografica senza bisogno di accedere ai segreti privati.

#### Matrix telefona a casa o traccia gli utenti?
No. Matrix è completamente privato e ospitato autonomamente. Non comunica con analisi esterne, cloud di licenza o provider di identità di terze parti. Tutte le comunicazioni di rete rimangono strettamente tra i tuoi client e la tua istanza del server.

#### Le applicazioni client possono essere eseguite senza l'hardware TPM 2.0?
SÌ. I client possono specificare "--no-tpm" per registrarsi al livello di attendibilità solo software. Negli ambienti privi di chip TPM, le licenze e gli heartbeat crittografici vengono comunque applicati tramite verifica fuori banda e archiviazione DPAPI standard.

#### Cosa succede se un dispositivo è offline?
Le licenze supportano finestre di lease configurabili. Le applicazioni client possono continuare a funzionare per tutta la durata del contratto di locazione attivo prima di richiedere un rinnovo online o fuori banda.
---
### Documentazione e architettura

- [Specifica del protocollo](docs/PROTOCOL.md): protocollo cablato normativo, endpoint e macchine a stati client/amministratore
- [Panoramica dell'architettura](docs/ARCHITECTURE.md) - Confini del sottosistema, modalità di errore e limiti delle minacce
- [Architecture Decisions (ADR)](docs/DECISIONS.md) — Razionali di progettazione e compromessi
- [Specifica VM](docs/VM.md): formato bytecode EHVM1 e semantica di esecuzione
- [Modello delle minacce](docs/THREAT_MODEL.md): panorama delle minacce, rischio residuo e presupposti per la sicurezza dell'hardware
- [Potenziamento della sicurezza](docs/SECURITY.md) — Inventario crittografico e procedure di reporting
- [Guida operativa](docs/OPERAZIONI.md) - Operazioni di backup, ripristino, rotazione e day-2
---
### Test

___BLOCCOCODICE_4___
---
### Licenza

Doppia licenza con:
- [Licenza Apache, Versione 2.0](LICENZA-APACHE)
- [Licenza MIT](LICENZA-MIT)

a tua scelta.