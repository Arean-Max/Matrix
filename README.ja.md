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

### 概要

**Matrix** (Event Horizon) は、Windows デスクトップ アプリケーション向けに特別に設計された、自律的で自己ホスト型のソフトウェア ライセンスおよび改ざん防止インフラストラクチャです。これは、ハードウェアにバインドされた TPM 2.0 デバイス認証を、暗号化ランタイム リース、帯域外チャレンジのアクティブ化、および密閉されたパッケージ プロビジョニングと組み合わせます。

サードパーティのテレメトリ、ベンダー ロックイン、セルフホステッド サーバー クラスターを超えた外部依存関係の呼び出しはゼロです。
---
### コンポーネント

|コンポーネント |スタック |目的 |
| :--- | :--- | :--- |
| `cmd/eh-server` | Go 1.27+ と SQLite |コア HTTP API: ライセンス エンジン、OOB 検証、SQLite ストレージ、バックグラウンド クリーンアップ ジャニター |
| `cmd/ehctl` | CLIに行く |オペレーター インターフェイス: PKI ブートストラップ、ライセンス発行、デバイス ライフサイクル、パッケージ インポート、バックアップ |
| `cmd/eh-builder` | CLIに行く |ベンダー パッケージャー: バイナリを暗号化された `.ehpkg` ディストリビューションとプロビジョニング マニフェストに変換します。
| `rust/eh-core` |さび | `EHVM1` バイトコード仮想マシンと実行保護のためのアセンブラ ([docs/VM.md](docs/VM.md) を参照)
| `rust/eh-trustd` |錆（孤立） |サンドボックス化された TPM 見積検証ツール: DB、ソケット、またはシークレット アクセスを使用せずに生のハードウェア構造を解析します。
| `rust/eh-client` |錆びとC FFI | Windows クライアント SDK: TLS、TPM2/TBS バインディング、DPAPI マシン ストレージ、C ABI ヘッダー、デモ クライアント |
---
### クイックスタート

#### 1. サーバーの展開

前提条件: Go 1.27.3 以降、Rust 1.99 以降 (分離されたベリファイア ビルドの場合)。

___コードブロック_0___

`<data_dir>/bootstrap.token` で生成された 1 回限りのブートストラップ トークンを使用して、マスター管理者の資格情報を作成します。

___コードブロック_1___

#### 2. ライセンスの発行とパッケージの封印

___コードブロック_2___

#### 3. クライアントの検証 (Windows)

前提条件: Windows 10/11、TPM 2.0 (オプションのフォールバック)。

___コードブロック_3___
---
### よくある質問

#### TPM 支援による認証はどのように機能しますか?
クライアント マシンは、ハードウェア TPM 2.0 チップ内で直接承認キー (EK) と証明キー (AK) を生成します。セッション検証中に、クライアントはハードウェア PCR レジスタを介して暗号引用符を送信します。 「eh-trustd」デーモンは、秘密にアクセスすることなく暗号署名を検証します。

#### Matrix は自宅に電話をかけたり、ユーザーを追跡したりしますか?
いいえ、Matrix は完全にプライベートで自己ホスト型です。外部分析、ライセンス クラウド、またはサードパーティの ID プロバイダーとは通信しません。すべてのネットワーク通信は、クライアントと独自のサーバー インスタンスの間でのみ維持されます。

#### クライアント アプリケーションは TPM 2.0 ハードウェアなしで実行できますか?
はい。クライアントは「--no-tpm」を指定して、ソフトウェアのみの信頼層の下に登録できます。 TPM チップがない環境でも、ライセンスと暗号化ハートビートは帯域外検証と標準の DPAPI ストレージによって強制されます。

#### デバイスがオフラインの場合はどうなりますか?
ライセンスは、構成可能なリース期間をサポートします。クライアント アプリケーションは、オンラインまたは帯域外の更新が必要になるまで、アクティブなリース期間中動作を継続できます。
---
### ドキュメントとアーキテクチャ

- [プロトコル仕様](docs/PROTOCOL.md) — 標準的なワイヤ プロトコル、エンドポイント、およびクライアント/管理ステート マシン
- [アーキテクチャの概要](docs/ARCHITECTURE.md) — サブシステムの境界、障害モード、および脅威の境界
- [アーキテクチャの決定 (ADR)](docs/DECISIONS.md) — 設計の根拠とトレードオフ
- [VM 仕様](docs/VM.md) — EHVM1 バイトコード形式と実行セマンティクス
- [脅威モデル](docs/THREAT_MODEL.md) — 脅威の状況、残留リスク、およびハードウェア セキュリティの前提条件
- [セキュリティ強化](docs/SECURITY.md) — 暗号化インベントリとレポート手順
- [操作ガイド](docs/OPERATIONS.md) — バックアップ、復元、ローテーション、および 2 日目の操作
---
### テスト

___コードブロック_4___
---
### ライセンス

次のいずれかに基づくデュアル ライセンス:
- [Apache ライセンス、バージョン 2.0](LICENSE-APACHE)
- [MITライセンス](LICENSE-MIT)

あなたのオプションで。