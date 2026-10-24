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

### 概述

**Matrix** (Event Horizo​​n) 是一種自主、自架的軟體授權和防篡改基礎設施，專為 Windows 桌面應用程式設計。它將硬體綁定的 TPM 2.0 裝置證明與加密運行時租賃、帶外質詢啟動和密封包配置結合。

零第三方遙測、零供應商鎖定以及自託管伺服器叢集以外的零外部依賴呼叫。
---
### 元件

|組件|堆疊|目的|
| :--- | :--- | :--- |
| `cmd/eh-server` | Go 1.27+ 與 SQLite |核心 HTTP API：授權引擎、OOB 驗證、SQLite 儲存、後台清理管理員 |
| `cmd/ehctl` |前往 CLI |操作員介面：PKI 引導、許可證頒發、設備生命週期、套件導入、備份 |
| `cmd/eh-builder` |前往 CLI |供應商打包程式：將二進位轉換為加密的「.ehpkg」發行版和設定清單 |
| `rust/eh-core` |鐵鏽|用於執行保護的 `EHVM1` 字節碼虛擬機器和彙編器（請參閱 [docs/VM.md](docs/VM.md)）|
| `rust/eh-trustd` |鐵鏽（分離）|沙盒 TPM 引用驗證器：解析原始硬體結構，無需資料庫、套接字或秘密存取 |
| `rust/eh-client` | Rust 和 C FFI | Windows 用戶端 SDK：TLS、TPM2/TBS 綁定、DPAPI 機器儲存、C ABI 標頭、演示用戶端 |
---
### 快速入門

#### 1.伺服器部署

先修條件：Go 1.27.3+、Rust 1.99+（用於隔離驗證器建置）。

___程式碼區塊_0___

使用在`<data_dir>/bootstrap.token`產生的一次性引導令牌來建立主管理員憑證：

___程式碼區塊_1___

#### 2. 許可證核發與包裝密封

___程式碼區塊_2___

#### 3. 用戶端驗證 (Windows)

先修條件：Windows 10/11、TPM 2.0（可選回退）。

___程式碼區塊_3___
---
### 常見問題解答

#### TPM 輔助證明如何運作？
用戶端電腦直接在其硬體 TPM 2.0 晶片內產生認可金鑰 (EK) 和證明金鑰 (AK)。在會話驗證期間，用戶端透過硬體 PCR 暫存器提交加密引用。 「eh-trustd」守護程式無需存取私人秘密即可驗證加密簽章。

#### Matrix 會打電話回家或追蹤使用者嗎？
不會。 Matrix 是完全私有且自架的。它不會與外部分析、許可證雲或第三方身分提供者通訊。所有網路通訊都嚴格保留在您的用戶端和您自己的伺服器執行個體之間。

#### 用戶端應用程式可以在沒有 TPM 2.0 硬體的情況下運作嗎？
是的。用戶端可以指定「--no-tpm」在純軟體信任層下註冊。在缺乏 TPM 晶片的環境中，許可證和加密心跳仍然透過帶外驗證和標準 DPAPI 儲存來強制執行。

#### 如果裝置離線會發生什麼事？
許可證支援可配置的租賃視窗。在需要線上或帶外續訂之前，客戶端應用程式可以在其有效租用期限內繼續運作。
---
### 文檔和架構

- [協定規格](docs/PROTOCOL.md) — 規格線路協定、端點和客戶端/管理狀態機
- [架構概述](docs/ARCHITECTURE.md) — 子系統邊界、故障模式與威脅邊界
- [架構決策 (ADR)](docs/DECISIONS.md) — 設計原則與權衡
- [VM 規格](docs/VM.md) — EHVM1 字節碼格式與執行語意
- [威脅模型](docs/THREAT_MODEL.md) — 威脅格局、殘餘風險與硬體安全假設
- [安全強化](docs/SECURITY.md) — 加密清單與報告程序
- [操作指南](docs/OPERATIONS.md) — 備份、復原、輪替與day-2作業
---
### 測試

___程式碼區塊_4___
---
### 許可證

雙重許可：
- [Apache 許可證，版本 2.0](LICENSE-APACHE)
- [麻省理工學院許可證](LICENSE-MIT)

由您選擇。