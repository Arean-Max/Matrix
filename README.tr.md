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

### Genel Bakış

**Matrix** (Event Horizon), Windows masaüstü uygulamaları için özel olarak tasarlanmış, özerk, kendi kendine barındırılan bir yazılım lisanslama ve kurcalamaya karşı koruma altyapısıdır. Donanıma bağlı TPM 2.0 cihaz doğrulamasını kriptografik çalışma zamanı kiralamaları, bant dışı sorgulama etkinleştirmeleri ve mühürlü paket provizyonuyla birleştirir.

Kendiniz tarafından barındırılan sunucu kümenizin ötesinde sıfır üçüncü taraf telemetrisi, sıfır satıcı bağımlılığı ve sıfır harici bağımlılık çağrısı.
---
### Bileşenler

| Bileşen | Yığın | Amaç |
| :--- | :--- | :--- |
| 'cmd/eh-sunucusu' | 1.27+ ve SQLite'a geçin | Çekirdek HTTP API: lisanslama motoru, OOB doğrulaması, SQLite depolama, arka plan temizleme hizmetlisi |
| 'cmd/ehctl' | CLI'ye git | Operatör arayüzü: PKI önyüklemesi, lisans verme, cihaz yaşam döngüsü, paket içe aktarma, yedeklemeler |
| 'cmd/eh-oluşturucu' | CLI'ye git | Satıcı paketleyicisi: ikili dosyaları şifrelenmiş `.ehpkg` dağıtımlarına ve sağlama bildirimlerine dönüştürür |
| 'pas/eh-çekirdek' | Pas | Yürütme koruması için 'EHVM1' bayt kodu sanal makinesi ve birleştirici (bkz. [docs/VM.md](docs/VM.md)) |
| 'pas/ah-güvenilir' | Pas (İzole) | Korumalı alana alınmış TPM fiyat teklifi doğrulayıcı: ham donanım yapılarını veritabanı, soketler veya gizli erişim olmadan ayrıştırır |
| 'pas/eh-istemci' | Pas ve C FFI | Windows istemci SDK'sı: TLS, TPM2/TBS bağlamaları, DPAPI makine depolaması, C ABI başlığı, demo istemcisi |
---
### Hızlı Başlangıç

#### 1. Sunucu Dağıtımı

Önkoşullar: 1.27.3+, Rust 1.99+ (izole edilmiş doğrulayıcı yapısı için).

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

Ana yönetici kimlik bilgisini oluşturmak için `<data_dir>/bootstrap.token` konumunda oluşturulan tek kullanımlık önyükleme belirtecini kullanın:

```bash
ehctl init --bootstrap-file /var/lib/eh/bootstrap.token \
    --server https://127.0.0.1:8443 --ca /etc/eh/tls/ca.pem
```

#### 2. Lisans Verme ve Paket Mühürleme

```bash
# Generate a new customer license key
ehctl license create --customer "Acme Corp" --channel manual
# Output: EH1-XXXXX-XXXXX-XXXXX-XXXXX

# Seal binary payload into protected distribution package
eh-builder pack --id demo-core --name "Demo Core" --in app.bin
# Output: demo-core.ehpkg (public) + demo-core.provision.json (secret)
ehctl packages import demo-core.provision.json
```

#### 3. İstemci Doğrulaması (Windows)

Önkoşullar: Windows 10/11, TPM 2.0 (isteğe bağlı yedek).

```powershell
cd rust; cargo build --release -p eh-client
target\release\eh-demo.exe --server https://lic.example.com:8443 `
    --license EH1-... --ca ca.pem --package-id demo-core `
    --package-file demo-core.ehpkg --heartbeats 3
```
---
### SSS

#### TPM destekli doğrulama nasıl çalışır?
İstemci makineleri, doğrudan donanım TPM 2.0 yongasının içinde bir Onay Anahtarı (EK) ve Onay Anahtarı (AK) oluşturur. Oturum doğrulaması sırasında müşteri, donanım PCR kayıtları üzerinden kriptografik bir fiyat teklifi gönderir. 'Eh-trustd' arka plan programı, özel sırlara erişime gerek kalmadan kriptografik imzayı doğrular.

#### Matrix kullanıcıları eve çağırıyor mu veya takip ediyor mu?
Hayır. Matrix tamamen özeldir ve kendi kendine barındırılır. Harici analizler, lisans bulutları veya üçüncü taraf kimlik sağlayıcılarıyla iletişim kurmaz. Tüm ağ iletişimi kesinlikle istemcileriniz ve kendi sunucu örneğiniz arasında kalır.

#### İstemci uygulamaları TPM 2.0 donanımı olmadan çalışabilir mi?
Evet. İstemciler, yalnızca yazılım güven katmanı altında kaydolmak için "--no-tpm" belirtebilirler. TPM çiplerinin bulunmadığı ortamlarda, lisanslar ve kriptografik kalp atışları hâlâ bant dışı doğrulama ve standart DPAPI depolama aracılığıyla zorunlu kılınıyor.

#### Bir cihaz çevrimdışıysa ne olur?
Lisanslar yapılandırılabilir kiralama pencerelerini destekler. İstemci uygulamaları, çevrimiçi veya bant dışı yenileme gerekmeden önce etkin kiralama süreleri boyunca çalışmaya devam edebilir.
---
### Dokümantasyon ve Mimari

- [Protokol Belirtimi](docs/PROTOCOL.md) — Normatif kablo protokolü, uç noktalar ve istemci/yönetici durumu makineleri
- [Mimariye Genel Bakış](docs/ARCHITECTURE.md) — Alt sistem sınırları, arıza modları ve tehdit sınırları
- [Mimarlık Kararları (ADR)](docs/DECISIONS.md) — Tasarım gerekçeleri ve ödünleşimler
- [VM Belirtimi](docs/VM.md) — EHVM1 bayt kodu formatı ve yürütme semantiği
- [Tehdit Modeli](docs/THREAT_MODEL.md) — Tehdit ortamı, artık risk ve donanım güvenliği varsayımları
- [Güvenlik Güçlendirmesi](docs/SECURITY.md) — Şifreleme envanteri ve raporlama prosedürleri
- [İşlem Kılavuzu](docs/OPERATIONS.md) — Yedekleme, geri yükleme, döndürme ve 2. gün işlemleri
---
### Testler

```bash
go test ./...            # server: unit and HTTP integration test suite
go test -race ./...      # race detector suite (requires gcc)
cd rust && cargo test    # VM, client SDK, and trustd verifier suites
```
---
### Lisans

Aşağıdakilerden herhangi biri kapsamında çift lisanslıdır:
- [Apache Lisansı, Sürüm 2.0](LİSANS-APACHE)
- [MIT Lisansı](LICENSE-MIT)

senin seçeneğin.