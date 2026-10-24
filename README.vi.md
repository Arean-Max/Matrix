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

### Tổng quan

**Matrix** (Event Horizon) là cơ sở hạ tầng chống giả mạo và cấp phép phần mềm tự lưu trữ, được thiết kế dành riêng cho các ứng dụng máy tính để bàn Windows. Nó kết hợp chứng thực thiết bị TPM 2.0 gắn với phần cứng với thời gian thuê mật mã, kích hoạt thử thách ngoài băng tần và cung cấp gói kín.

Không có dịch vụ đo từ xa của bên thứ ba, không có sự ràng buộc của nhà cung cấp và không có cuộc gọi phụ thuộc bên ngoài nào ngoài cụm máy chủ tự lưu trữ của bạn.
---
### Thành phần

| Thành phần | Ngăn xếp | Mục đích |
| :--- | :--- | :--- |
| `cmd/eh-server` | Lên phiên bản 1.27+ & SQLite | API HTTP lõi: công cụ cấp phép, xác minh OOB, lưu trữ SQLite, công cụ dọn dẹp nền |
| `cmd/ehctl` | Đi CLI | Giao diện vận hành: Khởi động PKI, cấp giấy phép, vòng đời thiết bị, nhập gói, sao lưu |
| `cmd/eh-builder` | Đi CLI | Trình đóng gói của nhà cung cấp: chuyển đổi các tệp nhị phân thành các bản phân phối `.ehpkg` được mã hóa và các bảng kê khai cung cấp |
| `Rỉ sét/eh-core` | rỉ sét | Trình biên dịch và máy ảo mã byte `EHVM1` để bảo vệ thực thi (xem [docs/VM.md](docs/VM.md)) |
| `Rỉ sét/eh-trustd` | Rust (Bị cô lập) | Trình xác minh trích dẫn TPM được đóng hộp cát: phân tích cấu trúc phần cứng thô không có DB, ổ cắm hoặc quyền truy cập bí mật |
| `Rỉ/eh-client` | Rust & C FFI | SDK máy khách Windows: TLS, liên kết TPM2/TBS, bộ lưu trữ máy DPAPI, tiêu đề C ABI, ứng dụng khách demo |
---
### Bắt đầu nhanh

#### 1. Triển khai máy chủ

Điều kiện tiên quyết: Go 1.27.3+, Rust 1.99+ (dành cho bản dựng trình xác minh bị cô lập).

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

Sử dụng mã thông báo khởi động sử dụng một lần được tạo tại `<data_dir>/bootstrap.token` để tạo thông tin xác thực quản trị viên chính:

```bash
ehctl init --bootstrap-file /var/lib/eh/bootstrap.token \
    --server https://127.0.0.1:8443 --ca /etc/eh/tls/ca.pem
```

#### 2. Cấp giấy phép & Niêm phong gói hàng

```bash
# Generate a new customer license key
ehctl license create --customer "Acme Corp" --channel manual
# Output: EH1-XXXXX-XXXXX-XXXXX-XXXXX

# Seal binary payload into protected distribution package
eh-builder pack --id demo-core --name "Demo Core" --in app.bin
# Output: demo-core.ehpkg (public) + demo-core.provision.json (secret)
ehctl packages import demo-core.provision.json
```

#### 3. Xác thực ứng dụng khách (Windows)

Điều kiện tiên quyết: Windows 10/11, TPM 2.0 (dự phòng tùy chọn).

```powershell
cd rust; cargo build --release -p eh-client
target\release\eh-demo.exe --server https://lic.example.com:8443 `
    --license EH1-... --ca ca.pem --package-id demo-core `
    --package-file demo-core.ehpkg --heartbeats 3
```
---
###Câu hỏi thường gặp

#### Chứng thực được hỗ trợ bởi TPM hoạt động như thế nào?
Máy khách tạo Khóa chứng thực (EK) và Khóa chứng thực (AK) trực tiếp bên trong chip TPM 2.0 phần cứng của chúng. Trong quá trình xác thực phiên, khách hàng gửi báo giá mật mã qua các thanh ghi PCR phần cứng. Daemon `eh-trustd` xác minh chữ ký mật mã mà không cần quyền truy cập vào bí mật riêng tư.

#### Matrix có gọi điện về nhà hoặc theo dõi người dùng không?
Không. Matrix hoàn toàn riêng tư và tự lưu trữ. Nó không giao tiếp với các phân tích bên ngoài, đám mây cấp phép hoặc nhà cung cấp danh tính bên thứ ba. Tất cả giao tiếp mạng vẫn được duy trì nghiêm ngặt giữa máy khách và phiên bản máy chủ của riêng bạn.

#### Ứng dụng khách có thể chạy mà không cần phần cứng TPM 2.0 không?
Đúng. Khách hàng có thể chỉ định `--no-tpm` để đăng ký theo cấp độ tin cậy chỉ dành cho phần mềm. Trong môi trường thiếu chip TPM, giấy phép và nhịp tim mật mã vẫn được thực thi thông qua xác minh ngoài băng tần và lưu trữ DPAPI tiêu chuẩn.

#### Điều gì xảy ra nếu thiết bị ngoại tuyến?
Giấy phép hỗ trợ các cửa sổ cho thuê có thể cấu hình. Các ứng dụng khách có thể tiếp tục hoạt động trong thời gian thuê đang hoạt động trước khi yêu cầu gia hạn trực tuyến hoặc ngoài băng tần.
---
### Tài liệu & Kiến trúc

- [Đặc tả giao thức](docs/PROTOCOL.md) — Giao thức dây tiêu chuẩn, điểm cuối và máy trạng thái máy khách/quản trị viên
- [Tổng quan về kiến trúc](docs/ARCHITECTURE.md) — Ranh giới hệ thống con, chế độ lỗi và ranh giới mối đe dọa
- [Quyết định về kiến trúc (ADR)](docs/DECISIONS.md) — Cơ sở lý luận về thiết kế và sự cân bằng
- [Đặc tả VM](docs/VM.md) — Định dạng mã byte EHVM1 và ngữ nghĩa thực thi
- [Mô hình mối đe dọa](docs/THREAT_MODEL.md) — Bối cảnh mối đe dọa, rủi ro còn sót lại và các giả định về bảo mật phần cứng
- [Tăng cường bảo mật](docs/SECURITY.md) — Quy trình báo cáo và kiểm kê mật mã
- [Hướng dẫn vận hành](docs/OPERATIONS.md) — Sao lưu, khôi phục, xoay vòng và các hoạt động ngày thứ 2
---
### Kiểm tra

```bash
go test ./...            # server: unit and HTTP integration test suite
go test -race ./...      # race detector suite (requires gcc)
cd rust && cargo test    # VM, client SDK, and trustd verifier suites
```
---
### Giấy phép

Được cấp phép kép theo:
- [Giấy phép Apache, Phiên bản 2.0](LICENSE-APACHE)
- [Giấy phép MIT](LICENSE-MIT)

theo lựa chọn của bạn.