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

### Visão geral

**Matrix** (Event Horizon) é um licenciamento de software autônomo e auto-hospedado e uma infraestrutura anti-adulteração projetada especificamente para aplicativos de desktop do Windows. Ele combina atestado de dispositivo TPM 2.0 vinculado a hardware com concessões de tempo de execução criptográfico, ativações de desafio fora de banda e provisionamento de pacotes selados.

Zero telemetria de terceiros, zero dependência de fornecedor e zero chamadas de dependência externa além do seu cluster de servidores auto-hospedados.
---
### Componentes

| Componente | Pilha | Finalidade |
| :--- | :--- | :--- |
| `cmd/eh-servidor` | Vá 1.27+ e SQLite | API HTTP principal: mecanismo de licenciamento, verificação OOB, armazenamento SQLite, zelador de limpeza de fundo |
| `cmd/ehctl` | Vá CLI | Interface do operador: inicialização de PKI, emissão de licença, ciclo de vida do dispositivo, importação de pacotes, backups |
| `cmd/eh-builder` | Vá CLI | Empacotador de fornecedor: transforma binários em distribuições `.ehpkg` criptografadas e manifestos de provisionamento |
| `ferrugem/eh-core` | Ferrugem | Máquina virtual de bytecode `EHVM1` e assembler para proteção de execução (consulte [docs/VM.md](docs/VM.md)) |
| `ferrugem/eh-trustd` | Ferrugem (isolada) | Verificador de cotação TPM em sandbox: analisa estruturas de hardware brutas sem banco de dados, soquetes ou acesso secreto |
| `rust/eh-client` | Ferrugem e C FFI | SDK do cliente Windows: TLS, ligações TPM2/TBS, armazenamento de máquina DPAPI, cabeçalho C ABI, cliente de demonstração |
---
### Início rápido

#### 1. Implantação do servidor

Pré-requisitos: Vá 1.27.3+, Rust 1.99+ (para construção de verificador isolado).

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

Consuma o token de bootstrap de uso único gerado em `<data_dir>/bootstrap.token` para criar a credencial de administrador mestre:

```bash
ehctl init --bootstrap-file /var/lib/eh/bootstrap.token \
    --server https://127.0.0.1:8443 --ca /etc/eh/tls/ca.pem
```

#### 2. Emissão de licença e selagem de pacotes

```bash
# Generate a new customer license key
ehctl license create --customer "Acme Corp" --channel manual
# Output: EH1-XXXXX-XXXXX-XXXXX-XXXXX

# Seal binary payload into protected distribution package
eh-builder pack --id demo-core --name "Demo Core" --in app.bin
# Output: demo-core.ehpkg (public) + demo-core.provision.json (secret)
ehctl packages import demo-core.provision.json
```

#### 3. Validação do cliente (Windows)

Pré-requisitos: Windows 10/11, TPM 2.0 (substituição opcional).

```powershell
cd rust; cargo build --release -p eh-client
target\release\eh-demo.exe --server https://lic.example.com:8443 `
    --license EH1-... --ca ca.pem --package-id demo-core `
    --package-file demo-core.ehpkg --heartbeats 3
```
---
### Perguntas frequentes

#### Como funciona o atestado assistido por TPM?
As máquinas clientes geram uma chave de endosso (EK) e uma chave de atestado (AK) diretamente dentro de seu chip TPM 2.0 de hardware. Durante a validação da sessão, o cliente envia uma cotação criptográfica através de registros PCR de hardware. O daemon `eh-trustd` verifica a assinatura criptográfica sem precisar de acesso a segredos privados.

#### Matrix telefona para casa ou rastreia usuários?
Não. O Matrix é totalmente privado e auto-hospedado. Ele não se comunica com análises externas, nuvens de licenças ou provedores de identidade terceirizados. Toda a comunicação de rede permanece estritamente entre seus clientes e sua própria instância de servidor.

#### Os aplicativos cliente podem ser executados sem hardware TPM 2.0?
Sim. Os clientes podem especificar `--no-tpm` para se registrar no nível confiável somente de software. Em ambientes sem chips TPM, licenças e pulsações criptográficas ainda são aplicadas por meio de verificação fora de banda e armazenamento DPAPI padrão.

#### O que acontece se um dispositivo estiver off-line?
As licenças suportam janelas de concessão configuráveis. Os aplicativos clientes podem continuar operando durante sua locação ativa antes de exigir uma renovação on-line ou fora de banda.
---
### Documentação e Arquitetura

- [Especificação de protocolo](docs/PROTOCOL.md) — Protocolo de ligação normativo, endpoints e máquinas de estado cliente/administrador
- [Visão geral da arquitetura](docs/ARCHITECTURE.md) — Limites do subsistema, modos de falha e limites de ameaça
- [Decisões de Arquitetura (ADR)](docs/DECISÕES.md) — Justificativas de design e compensações
- [Especificação VM](docs/VM.md) — Formato de bytecode EHVM1 e semântica de execução
- [Modelo de ameaças](docs/THREAT_MODEL.md) — Cenário de ameaças, risco residual e suposições de segurança de hardware
- [Reforço de segurança](docs/SECURITY.md) — Inventário criptográfico e procedimentos de relatório
- [Guia de operações](docs/OPERATIONS.md) — Operações de backup, restauração, rotação e dia 2
---
### Testes

```bash
go test ./...            # server: unit and HTTP integration test suite
go test -race ./...      # race detector suite (requires gcc)
cd rust && cargo test    # VM, client SDK, and trustd verifier suites
```
---
### Licença

Licenciado duplamente em:
- [Licença Apache, Versão 2.0](LICENSE-APACHE)
- [Licença MIT](LICENSE-MIT)

a sua opção.