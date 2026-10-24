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

### Aperçu

**Matrix** (Event Horizon) est une infrastructure de licence logicielle et anti-falsification autonome et auto-hébergée conçue spécifiquement pour les applications de bureau Windows. Il associe l'attestation de périphérique TPM 2.0 liée au matériel à des baux d'exécution cryptographiques, des activations de défi hors bande et un approvisionnement de packages scellés.

Zéro télémétrie tierce, zéro dépendance envers un fournisseur et zéro appel de dépendance externe au-delà de votre cluster de serveurs auto-hébergé.
---
### Composants

| Composant | Pile | Objectif |
| :--- | :--- | :--- |
| `cmd/eh-serveur` | Allez 1.27+ et SQLite | API HTTP de base : moteur de licence, vérification OOB, stockage SQLite, concierge de nettoyage en arrière-plan |
| `cmd/ehctl` | Aller à la CLI | Interface opérateur : amorçage PKI, délivrance de licences, cycle de vie des appareils, importations de packages, sauvegardes |
| `cmd/eh-builder` | Aller à la CLI | Packageur du fournisseur : transforme les binaires en distributions `.ehpkg` chiffrées et en manifestes de provisionnement |
| `rouille/eh-core` | Rouille | Machine virtuelle et assembleur de bytecode `EHVM1` pour la protection de l'exécution (voir [docs/VM.md](docs/VM.md)) |
| `rust/eh-trustd` | Rouille (isolé) | Vérificateur de devis TPM en bac à sable : analyse les structures matérielles brutes sans base de données, sockets ou accès secret |
| `rust/eh-client` | Rouille et C FFI | SDK client Windows : TLS, liaisons TPM2/TBS, stockage machine DPAPI, en-tête C ABI, client de démonstration |
---
### Démarrage rapide

#### 1. Déploiement du serveur

Prérequis : Go 1.27.3+, Rust 1.99+ (pour la version de vérificateur isolé).

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

Consommez le jeton d'amorçage à usage unique généré dans `<data_dir>/bootstrap.token` pour créer les informations d'identification de l'administrateur principal :

```bash
ehctl init --bootstrap-file /var/lib/eh/bootstrap.token \
    --server https://127.0.0.1:8443 --ca /etc/eh/tls/ca.pem
```

#### 2. Délivrance de la licence et scellement du colis

```bash
# Generate a new customer license key
ehctl license create --customer "Acme Corp" --channel manual
# Output: EH1-XXXXX-XXXXX-XXXXX-XXXXX

# Seal binary payload into protected distribution package
eh-builder pack --id demo-core --name "Demo Core" --in app.bin
# Output: demo-core.ehpkg (public) + demo-core.provision.json (secret)
ehctl packages import demo-core.provision.json
```

#### 3. Validation client (Windows)

Prérequis : Windows 10/11, TPM 2.0 (repli facultatif).

```powershell
cd rust; cargo build --release -p eh-client
target\release\eh-demo.exe --server https://lic.example.com:8443 `
    --license EH1-... --ca ca.pem --package-id demo-core `
    --package-file demo-core.ehpkg --heartbeats 3
```
---
###FAQ

#### Comment fonctionne l'attestation assistée par TPM ?
Les machines client génèrent une clé d'approbation (EK) et une clé d'attestation (AK) directement dans leur puce matérielle TPM 2.0. Lors de la validation de session, le client soumet un devis cryptographique sur les registres PCR matériels. Le démon `eh-trustd` vérifie la signature cryptographique sans avoir besoin d'accéder aux secrets privés.

#### Matrix téléphone-t-il à la maison ou suit-il les utilisateurs ?
Non, Matrix est entièrement privé et auto-hébergé. Il ne communique pas avec des analyses externes, des nuages ​​de licences ou des fournisseurs d'identité tiers. Toutes les communications réseau restent strictement entre vos clients et votre propre instance de serveur.

#### Les applications clientes peuvent-elles s'exécuter sans le matériel TPM 2.0 ?
Oui. Les clients peuvent spécifier « --no-tpm » pour s'inscrire sous le niveau de confiance réservé aux logiciels. Dans les environnements dépourvus de puces TPM, les licences et les battements de cœur cryptographiques sont toujours appliqués via une vérification hors bande et un stockage DPAPI standard.

#### Que se passe-t-il si un appareil est hors ligne ?
Les licences prennent en charge des fenêtres de bail configurables. Les applications clientes peuvent continuer à fonctionner pendant toute la durée de leur bail actif avant de nécessiter un renouvellement en ligne ou hors bande.
---
###Documentation et architecture

- [Spécification du protocole](docs/PROTOCOL.md) — Protocole filaire normatif, points de terminaison et machines à états client/administrateur
- [Présentation de l'architecture] (docs/ARCHITECTURE.md) — Limites des sous-systèmes, modes de défaillance et limites des menaces
- [Décisions architecturales (ADR)](docs/DECISIONS.md) — Justifications de conception et compromis
- [Spécification VM](docs/VM.md) — Format de bytecode EHVM1 et sémantique d'exécution
- [Modèle de menace](docs/THREAT_MODEL.md) — Paysage des menaces, risque résiduel et hypothèses de sécurité matérielle
- [Renforcement de la sécurité](docs/SECURITY.md) — Inventaire cryptographique et procédures de reporting
- [Guide des opérations](docs/OPERATIONS.md) — Opérations de sauvegarde, de restauration, de rotation et du deuxième jour
---
### Tests

```bash
go test ./...            # server: unit and HTTP integration test suite
go test -race ./...      # race detector suite (requires gcc)
cd rust && cargo test    # VM, client SDK, and trustd verifier suites
```
---
### Licence

Double licence sous :
- [Licence Apache, Version 2.0](LICENSE-APACHE)
- [Licence MIT](LICENCE-MIT)

à votre choix.