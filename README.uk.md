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

### Огляд

**Matrix** (Event Horizon) — це автономна інфраструктура ліцензування програмного забезпечення та захисту від несанкціонованого доступу, розроблена спеціально для настільних програм Windows. Він поєднує апаратну атестацію пристроїв TPM 2.0 з орендою криптографічного середовища виконання, активаціями викликів за межами каналу та наданням закритих пакетів.

Нуль сторонньої телеметрії, нуль блокування від постачальника та нуль викликів зовнішніх залежностей за межами кластера серверів, розміщених на вашому сервері.
---
### Компоненти

| Компонент | Стек | Призначення |
| :--- | :--- | :--- |
| `cmd/eh-сервер` | Go 1.27+ & SQLite | Основний HTTP API: система ліцензування, OOB перевірка, сховище SQLite, очищувач фону |
| `cmd/ehctl` | Go CLI | Інтерфейс оператора: завантаження PKI, видача ліцензії, життєвий цикл пристрою, імпорт пакетів, резервне копіювання |
| `cmd/eh-builder` | Go CLI | Пакетувальник постачальника: перетворює двійкові файли в зашифровані дистрибутиви `.ehpkg` і маніфести надання |
| `rust/eh-core` | Іржа | Віртуальна машина з байт-кодом `EHVM1` і асемблер для захисту від виконання (див. [docs/VM.md](docs/VM.md)) |
| `rust/eh-trustd` | Іржа (ізольована) | Перевірка цитат TPM ізольованого програмного середовища: аналізує необроблені апаратні структури без БД, сокетів або секретного доступу |
| `rust/eh-client` | Rust & C FFI | Windows client SDK: прив’язки TLS, TPM2/TBS, машинне сховище DPAPI, заголовок C ABI, демонстраційний клієнт |
---
### Швидкий старт

#### 1. Розгортання сервера

Попередні вимоги: Go 1.27.3+, Rust 1.99+ (для ізольованої збірки верифікатора).

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

Використайте одноразовий маркер початкового завантаження, згенерований у `<data_dir>/bootstrap.token`, щоб створити облікові дані головного адміністратора:

```bash
ehctl init --bootstrap-file /var/lib/eh/bootstrap.token \
    --server https://127.0.0.1:8443 --ca /etc/eh/tls/ca.pem
```

#### 2. Видача ліцензії та запечатування упаковки

```bash
# Generate a new customer license key
ehctl license create --customer "Acme Corp" --channel manual
# Output: EH1-XXXXX-XXXXX-XXXXX-XXXXX

# Seal binary payload into protected distribution package
eh-builder pack --id demo-core --name "Demo Core" --in app.bin
# Output: demo-core.ehpkg (public) + demo-core.provision.json (secret)
ehctl packages import demo-core.provision.json
```

#### 3. Перевірка клієнта (Windows)

Необхідні вимоги: Windows 10/11, TPM 2.0 (необов’язковий запасний варіант).

```powershell
cd rust; cargo build --release -p eh-client
target\release\eh-demo.exe --server https://lic.example.com:8443 `
    --license EH1-... --ca ca.pem --package-id demo-core `
    --package-file demo-core.ehpkg --heartbeats 3
```
---
### FAQ

#### Як працює атестація за допомогою TPM?
Клієнтські комп’ютери генерують ключ підтвердження (EK) і ключ атестації (AK) безпосередньо в апаратному чіпі TPM 2.0. Під час перевірки сеансу клієнт надсилає криптографічну ціну через апаратні регістри PCR. Демон `eh-trustd` перевіряє криптографічний підпис, не потребуючи доступу до приватних секретів.

#### Matrix дзвонить додому чи відстежує користувачів?
Ні. Matrix є повністю приватним і розміщується самостійно. Він не спілкується із зовнішньою аналітикою, хмарами ліцензій або сторонніми постачальниками ідентифікаційної інформації. Усі мережеві зв’язки зберігаються виключно між вашими клієнтами та вашим власним екземпляром сервера.

#### Чи можуть клієнтські програми працювати без апаратного забезпечення TPM 2.0?
так Клієнти можуть вказати `--no-tpm`, щоб зареєструватися на рівні довіри лише для програмного забезпечення. У середовищах без чіпів TPM ліцензії та криптографічні серцеві сигнали все ще застосовуються за допомогою позасмугової перевірки та стандартного сховища DPAPI.

#### Що станеться, якщо пристрій офлайн?
Ліцензії підтримують настроювані вікна оренди. Клієнтські додатки можуть продовжувати працювати протягом терміну їх активної оренди, перш ніж вимагатиме онлайнового або позасмугового поновлення.
---
### Документація та архітектура

- [Специфікація протоколу] (docs/PROTOCOL.md) — Нормативний протокол зв'язку, кінцеві точки та автомати стану клієнта/адміністратора
- [Огляд архітектури] (docs/ARCHITECTURE.md) — Межі підсистеми, режими збоїв і межі загроз
- [Архітектурні рішення (ADR)](docs/DECISIONS.md) — Обґрунтування дизайну та компроміси
- [Специфікація VM] (docs/VM.md) — формат байт-коду EHVM1 і семантика виконання
- [Модель загроз] (docs/THREAT_MODEL.md) — Ландшафт загроз, залишковий ризик і припущення щодо безпеки обладнання
- [Посилення безпеки](docs/SECURITY.md) — Криптографічна інвентаризація та процедури звітності
- [Посібник з операцій] (docs/OPERATIONS.md) — Резервне копіювання, відновлення, ротація та операції другого дня
---
### Тести

```bash
go test ./...            # server: unit and HTTP integration test suite
go test -race ./...      # race detector suite (requires gcc)
cd rust && cargo test    # VM, client SDK, and trustd verifier suites
```
---
### Ліцензія

Подвійна ліцензія:
- [Ліцензія Apache, версія 2.0](LICENSE-APACHE)
- [Ліцензія MIT](LICENSE-MIT)

на ваш вибір.