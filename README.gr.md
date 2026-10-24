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

### Επισκόπηση

Το **Matrix** (Event Horizon) είναι μια αυτόνομη, αυτο-φιλοξενούμενη υποδομή αδειοδότησης λογισμικού και κατά της παραβίασης που έχει σχεδιαστεί ειδικά για εφαρμογές επιτραπέζιου υπολογιστή Windows. Συνδυάζει βεβαίωση συσκευής TPM 2.0 συνδεδεμένη με υλικό με κρυπτογραφικές μισθώσεις χρόνου εκτέλεσης, ενεργοποιήσεις πρόκλησης εκτός ζώνης και παροχή σφραγισμένων πακέτων.

Μηδενική τηλεμετρία τρίτων, μηδενικό κλείδωμα προμηθευτή και μηδενικές κλήσεις εξωτερικής εξάρτησης πέρα ​​από το σύμπλεγμα διακομιστών που φιλοξενείτε μόνοι σας.
---
### Στοιχεία

| Εξάρτημα | Στοίβα | Σκοπός |
| :--- | :--- | :--- |
| "cmd/eh-server" | Go 1.27+ & SQLite | Core HTTP API: μηχανή αδειοδότησης, επαλήθευση OOB, αποθήκευση SQLite, θυρωρός καθαρισμού φόντου |
| `cmd/ehctl` | Πηγαίνετε CLI | Διεπαφή χειριστή: PKI bootstrapping, έκδοση άδειας, κύκλος ζωής συσκευής, εισαγωγές πακέτων, αντίγραφα ασφαλείας |
| `cmd/eh-builder` | Πηγαίνετε CLI | Προμηθευτής συσκευασίας: μετατρέπει τα δυαδικά αρχεία σε κρυπτογραφημένες διανομές «.ehpkg» και δηλώσεις παροχής |
| «σκουριάς/πυρήνας» | Σκουριά | «EHVM1» bytecode εικονική μηχανή και assembler για προστασία εκτέλεσης (βλ. [docs/VM.md](docs/VM.md)) |
| `rust/eh-trustd` | Σκουριά (Απομονωμένη) | Επαληθευτής προσφοράς TPM Sandboxed: αναλύει ακατέργαστες δομές υλικού χωρίς DB, υποδοχές ή μυστική πρόσβαση |
| «rust/eh-client» | Rust & C FFI | SDK προγράμματος-πελάτη Windows: TLS, δεσμεύσεις TPM2/TBS, αποθήκευση μηχανήματος DPAPI, κεφαλίδα C ABI, πρόγραμμα-πελάτης επίδειξης |
---
### Γρήγορη εκκίνηση

#### 1. Ανάπτυξη διακομιστή

Προϋποθέσεις: Go 1.27.3+, Rust 1.99+ (για μεμονωμένη κατασκευή επαληθευτή).

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

Καταναλώστε το διακριτικό εκκίνησης μιας χρήσης που δημιουργήθηκε στο `<data_dir>/bootstrap.token` για να δημιουργήσετε το διαπιστευτήριο κύριου διαχειριστή:

```bash
ehctl init --bootstrap-file /var/lib/eh/bootstrap.token \
    --server https://127.0.0.1:8443 --ca /etc/eh/tls/ca.pem
```

#### 2. Έκδοση Άδειας & Σφράγιση Πακέτων

```bash
# Generate a new customer license key
ehctl license create --customer "Acme Corp" --channel manual
# Output: EH1-XXXXX-XXXXX-XXXXX-XXXXX

# Seal binary payload into protected distribution package
eh-builder pack --id demo-core --name "Demo Core" --in app.bin
# Output: demo-core.ehpkg (public) + demo-core.provision.json (secret)
ehctl packages import demo-core.provision.json
```

#### 3. Επικύρωση πελάτη (Windows)

Προϋποθέσεις: Windows 10/11, TPM 2.0 (προαιρετικό εναλλακτικό).

```powershell
cd rust; cargo build --release -p eh-client
target\release\eh-demo.exe --server https://lic.example.com:8443 `
    --license EH1-... --ca ca.pem --package-id demo-core `
    --package-file demo-core.ehpkg --heartbeats 3
```
---
### Συχνές ερωτήσεις

#### Πώς λειτουργεί η βεβαίωση με τη βοήθεια TPM;
Οι μηχανές πελάτη δημιουργούν ένα κλειδί έγκρισης (EK) και ένα κλειδί βεβαίωσης (AK) απευθείας μέσα στο τσιπ TPM 2.0 του υλικού τους. Κατά την επικύρωση περιόδου λειτουργίας, ο πελάτης υποβάλλει μια κρυπτογραφική προσφορά μέσω καταχωρητών PCR υλικού. Ο δαίμονας «eh-trustd» επαληθεύει την κρυπτογραφική υπογραφή χωρίς να χρειάζεται πρόσβαση σε ιδιωτικά μυστικά.

#### Τηλέφωνο Matrix φιλοξενεί ή παρακολουθεί τους χρήστες;
Όχι. Το Matrix είναι εντελώς ιδιωτικό και αυτο-φιλοξενείται. Δεν επικοινωνεί με εξωτερικά αναλυτικά στοιχεία, cloud αδειών ή τρίτους παρόχους ταυτότητας. Όλη η δικτυακή επικοινωνία παραμένει αυστηρά μεταξύ των πελατών σας και του δικού σας διακομιστή.

#### Μπορούν οι εφαρμογές-πελάτες να εκτελούνται χωρίς υλικό TPM 2.0;
Ναί. Οι πελάτες μπορούν να καθορίσουν "--no-tpm" για εγγραφή στο επίπεδο εμπιστοσύνης μόνο για λογισμικό. Σε περιβάλλοντα που δεν διαθέτουν τσιπ TPM, οι άδειες και οι κρυπτογραφικοί παλμοί της καρδιάς εξακολουθούν να επιβάλλονται μέσω επαλήθευσης εκτός ζώνης και τυπικής αποθήκευσης DPAPI.

#### Τι συμβαίνει εάν μια συσκευή είναι εκτός σύνδεσης;
Οι άδειες χρήσης υποστηρίζουν παραμετροποιήσιμα παράθυρα μίσθωσης. Οι εφαρμογές πελατών μπορούν να συνεχίσουν να λειτουργούν για τη διάρκεια της ενεργού μίσθωσης προτού απαιτήσουν ανανέωση μέσω διαδικτύου ή εκτός ζώνης.
---
### Τεκμηρίωση & Αρχιτεκτονική

- [Προδιαγραφές πρωτοκόλλου](docs/PROTOCOL.md) — Κανονικό πρωτόκολλο καλωδίου, τερματικά σημεία και μηχανήματα κατάστασης πελάτη/διαχειριστή
- [Επισκόπηση Αρχιτεκτονικής](docs/ARCHITECTURE.md) — Όρια υποσυστήματος, τρόποι αποτυχίας και όρια απειλών
- [Αποφάσεις Αρχιτεκτονικής (ADR)](docs/DECISIONS.md) — Σκεπτικό σχεδιασμού και συμβιβασμούς
- [Προδιαγραφές VM](docs/VM.md) — Μορφή bytecode EHVM1 και σημασιολογία εκτέλεσης
- [Μοντέλο απειλής](docs/THREAT_MODEL.md) — Υποθέσεις για το τοπίο απειλών, τον υπολειπόμενο κίνδυνο και την ασφάλεια υλικού
- [Security Hardening](docs/SECURITY.md) — Κρυπτογραφικό απόθεμα και διαδικασίες αναφοράς
- [Οδηγός λειτουργιών](docs/OPERATIONS.md) — Δημιουργία αντιγράφων ασφαλείας, επαναφορά, περιστροφή και λειτουργίες ημέρας 2
---
### Δοκιμές

```bash
go test ./...            # server: unit and HTTP integration test suite
go test -race ./...      # race detector suite (requires gcc)
cd rust && cargo test    # VM, client SDK, and trustd verifier suites
```
---
### Άδεια

Με διπλή άδεια είτε:
- [Άδεια Apache, Έκδοση 2.0](LICENSE-APACHE)
- [Άδεια MIT](LICENSE-MIT)

κατά την επιλογή σας.