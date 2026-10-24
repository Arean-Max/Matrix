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

**Matrix** (Event Horizon) 是一种自主、自托管的软件许可和防篡改基础设施，专为 Windows 桌面应用程序设计。它将硬件绑定的 TPM 2.0 设备证明与加密运行时租赁、带外质询激活和密封包配置结合起来。

零第三方遥测、零供应商锁定以及自托管服务器集群之外的零外部依赖调用。
---
### 组件

|组件|堆栈|目的|
| :--- | :--- | :--- |
| `cmd/eh-server` | Go 1.27+ 和 SQLite |核心 HTTP API：许可引擎、OOB 验证、SQLite 存储、后台清理管理员 |
| `cmd/ehctl` |转到 CLI |操作员界面：PKI 引导、许可证颁发、设备生命周期、包导入、备份 |
| `cmd/eh-builder` |转到 CLI |供应商打包程序：将二进制文件转换为加密的“.ehpkg”发行版和配置清单 |
| `rust/eh-core` |铁锈|用于执行保护的 `EHVM1` 字节码虚拟机和汇编器（请参阅 [docs/VM.md](docs/VM.md)）|
| `rust/eh-trustd` |铁锈（分离）|沙盒 TPM 引用验证器：解析原始硬件结构，无需数据库、套接字或秘密访问 |
| `rust/eh-client` | Rust 和 C FFI | Windows 客户端 SDK：TLS、TPM2/TBS 绑定、DPAPI 机器存储、C ABI 标头、演示客户端 |
---
### 快速入门

#### 1.服务器部署

先决条件：Go 1.27.3+、Rust 1.99+（用于隔离验证器构建）。

___代码块_0___

使用在`<data_dir>/bootstrap.token`生成的一次性引导令牌来创建主管理员凭据：

___代码块_1___

#### 2. 许可证颁发和包装密封

___代码块_2___

#### 3. 客户端验证 (Windows)

先决条件：Windows 10/11、TPM 2.0（可选回退）。

___代码块_3___
---
### 常见问题解答

#### TPM 辅助证明如何工作？
客户端计算机直接在其硬件 TPM 2.0 芯片内生成认可密钥 (EK) 和证明密钥 (AK)。在会话验证期间，客户端通过硬件 PCR 寄存器提交加密引用。 “eh-trustd”守护进程无需访问私人秘密即可验证加密签名。

#### Matrix 会打电话回家或跟踪用户吗？
不会。Matrix 是完全私有且自托管的。它不与外部分析、许可证云或第三方身份提供商进行通信。所有网络通信都严格保留在您的客户端和您自己的服务器实例之间。

#### 客户端应用程序可以在没有 TPM 2.0 硬件的情况下运行吗？
是的。客户端可以指定“--no-tpm”在纯软件信任层下注册。在缺乏 TPM 芯片的环境中，许可证和加密心跳仍然通过带外验证和标准 DPAPI 存储来强制执行。

#### 如果设备离线会发生什么？
许可证支持可配置的租赁窗口。在需要在线或带外续订之前，客户端应用程序可以在其有效租用期限内继续运行。
---
### 文档和架构

- [协议规范](docs/PROTOCOL.md) — 规范线路协议、端点和客户端/管理状态机
- [架构概述](docs/ARCHITECTURE.md) — 子系统边界、故障模式和威胁边界
- [架构决策 (ADR)](docs/DECISIONS.md) — 设计原理和权衡
- [VM 规范](docs/VM.md) — EHVM1 字节码格式和执行语义
- [威胁模型](docs/THREAT_MODEL.md) — 威胁格局、残余风险和硬件安全假设
- [安全强化](docs/SECURITY.md) — 加密清单和报告程序
- [操作指南](docs/OPERATIONS.md) — 备份、恢复、轮换和day-2操作
---
### 测试

___代码块_4___
---
### 许可证

双重许可：
- [Apache 许可证，版本 2.0](LICENSE-APACHE)
- [麻省理工学院许可证](LICENSE-MIT)

由您选择。