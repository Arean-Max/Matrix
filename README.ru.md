<p align="center">
  <a href="https://github.com/Arean-Max/Matrix">
    <picture>
      <source srcset="docs/logo-dark.png" media="(prefers-color-scheme: dark)">
      <source srcset="docs/logo-light.png" media="(prefers-color-scheme: light)">
      <img src="docs/logo.png" alt="Matrix logo" width="560">
    </picture>
  </a>
</p>

<p align="center">Автономная платформа лицензирования ПО с аппаратной аттестацией устройств через TPM для Windows-приложений.</p>

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

### Обзор

**Matrix** (Event Horizon) — автономная, полностью локальная система лицензирования и защиты от модификации для десктопных приложений Windows. Сочетает аппаратную аттестацию устройств на базе TPM 2.0, криптографические runtime-аренды, внеполосную активацию по кодам и распределение запечатанных пакетов.

Полное отсутствие телеметрии, зависимости от сторонних сервисов и внешних сетевых вызовов за пределами вашего собственного серверного кластера.

---

### Компоненты

| Компонент | Стек | Назначение |
| :--- | :--- | :--- |
| `cmd/eh-server` | Go 1.27+ и SQLite | Основной HTTP API: ядро лицензирования, OOB-коды, хранилище SQLite, фоновый джанитор |
| `cmd/ehctl` | Go CLI | Интерфейс оператора: бутстрап PKI, выпуск лицензий, жизненный цикл устройств, импорт пакетов, бэкапы |
| `cmd/eh-builder` | Go CLI | Упаковщик вендора: упаковка бинарников в зашифрованные `.ehpkg` пакеты и манифесты |
| `rust/eh-core` | Rust | Байткод-машина `EHVM1` и ассемблер для защиты исполняемого кода (см. [docs/VM.md](docs/VM.md)) |
| `rust/eh-trustd` | Rust (изолированный) | Изолированный верификатор TPM-квот: парсинг аппаратных структур без доступа к БД, сокетам и ключам |
| `rust/eh-client` | Rust и C FFI | Клиентский SDK для Windows: TLS, TPM2/TBS, безопасное хранилище DPAPI, заголовок C ABI, демо-клиент |

---

### Быстрый старт

#### 1. Развертывание сервера

Требования: Go 1.27.3+, Rust 1.99+ (для изолированного верификатора).

```bash
# Сборка серверных утилит
mkdir -p bin
go build -o bin/eh-server ./cmd/eh-server
go build -o bin/ehctl ./cmd/ehctl
go build -o bin/eh-builder ./cmd/eh-builder
cargo build --release --manifest-path rust/Cargo.toml -p eh-trustd
export PATH="$PWD/bin:$PATH"

# Конфигурация (TLS обязателен по умолчанию)
cp deploy/config/server.example.yaml server.yaml
eh-server -config server.yaml
```

Активируйте одноразовый bootstrap токен из `<data_dir>/bootstrap.token` для создания мастер-токена администратора:

```bash
ehctl init --bootstrap-file /var/lib/eh/bootstrap.token \
    --server https://127.0.0.1:8443 --ca /etc/eh/tls/ca.pem
```

#### 2. Выпуск лицензий и упаковка

```bash
# Создание лицензионного ключа
ehctl license create --customer "Acme Corp" --channel manual
# Вывод: EH1-XXXXX-XXXXX-XXXXX-XXXXX

# Упаковка бинарного модуля в защищенный пакет
eh-builder pack --id demo-core --name "Demo Core" --in app.bin
# Вывод: demo-core.ehpkg (публичный) + demo-core.provision.json (секретный)
ehctl packages import demo-core.provision.json
```

#### 3. Проверка клиента (Windows)

Требования: Windows 10/11, TPM 2.0 (доступен fallback).

```powershell
cd rust; cargo build --release -p eh-client
target\release\eh-demo.exe --server https://lic.example.com:8443 `
    --license EH1-... --ca ca.pem --package-id demo-core `
    --package-file demo-core.ehpkg --heartbeats 3
```

---

### FAQ

#### Как устроена аппаратная аттестация через TPM?
Клиент генерирует пару Endorsement Key (EK) и Attestation Key (AK) непосредственно внутри чипа TPM 2.0. При сессии валидации клиент предоставляет криптографическую квоту значений аппаратных регистров PCR. Демон `eh-trustd` проверяет цифровую подпись без прямого доступа к приватным ключам.

#### Содержит ли Matrix трекеры или телеметрию?
Нет. Matrix полностью автономен и защищен. Никакие данные не передаются сторонним провайдерам или облачным сервисам. Весь трафик изолирован между вашими приложениями и вашим сервером.

#### Можно ли работать без чипа TPM 2.0?
Да. Клиенты могут передавать флаг `--no-tpm` для работы на программном уровне доверия. В средах без TPM лицензии и криптографические проверки подтверждаются через OOB-коды и шифрование DPAPI.

#### Что происходит в оффлайн-режиме?
Лицензии поддерживают настраиваемый срок аренды (lease window). Приложение может работать автономно в течение действующей аренды до момента очередного обновления.

---

### Документация и архитектура

- [Спецификация протокола](docs/PROTOCOL.md) — Протокол клиент/серверного взаимодействия и стейт-машины
- [Архитектурный обзор](docs/ARCHITECTURE.md) — Модульные границы и топология отказоустойчивости
- [Журнал решений (ADR)](docs/DECISIONS.md) — Обоснование технического выбора
- [Спецификация виртуальной машины](docs/VM.md) — Байткод и семантика EHVM1
- [Модель угроз](docs/THREAT_MODEL.md) — Векторы атак и границы доверия
- [Безопасность и криптография](docs/SECURITY.md) — Инвентарь алгоритмов и политики отчетности
- [Руководство по эксплуатации](docs/OPERATIONS.md) — Ротация ключей, резервное копирование и траблшутинг

---

### Тестирование

```bash
go test ./...            # юнит-тесты и интеграционные HTTP-тесты сервера
go test -race ./...      # проверка гонок (требуется gcc)
cd rust && cargo test    # тесты VM, SDK клиента и verifier
```

---

### Лицензия

Двойная лицензия по вашему выбору:
- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)
