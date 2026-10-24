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

### Descripción general

**Matrix** (Event Horizon) es una infraestructura antimanipulación y licencia de software autónoma y autohospedada diseñada específicamente para aplicaciones de escritorio de Windows. Combina la certificación de dispositivos TPM 2.0 vinculada al hardware con arrendamientos de tiempo de ejecución criptográfico, activaciones de desafío fuera de banda y aprovisionamiento de paquetes sellados.

Cero telemetría de terceros, cero dependencia de proveedores y cero llamadas de dependencia externa más allá de su clúster de servidores autohospedado.
---
### Componentes

| Componente | Pila | Propósito |
| :--- | :--- | :--- |
| `cmd/eh-servidor` | Vaya a 1.27+ y SQLite | API HTTP principal: motor de licencias, verificación OOB, almacenamiento SQLite, conserje de limpieza en segundo plano |
| `cmd/ehctl` | Ir CLI | Interfaz del operador: arranque de PKI, emisión de licencias, ciclo de vida del dispositivo, importaciones de paquetes, copias de seguridad |
| `cmd/eh-constructor` | Ir CLI | Empaquetador de proveedores: transforma archivos binarios en distribuciones cifradas `.ehpkg` y manifiestos de aprovisionamiento |
| `óxido/eh-núcleo` | Óxido | Máquina virtual de código de bytes `EHVM1` y ensamblador para protección de ejecución (consulte [docs/VM.md](docs/VM.md)) |
| `rust/eh-trustd` | Óxido (aislado) | Verificador de cotizaciones de TPM en espacio aislado: analiza estructuras de hardware sin formato sin base de datos, sockets ni acceso secreto |
| `rust/eh-cliente` | Óxido y C FFI | SDK de cliente de Windows: TLS, enlaces TPM2/TBS, almacenamiento de máquina DPAPI, encabezado C ABI, cliente de demostración |
---
### Inicio rápido

#### 1. Implementación del servidor

Requisitos previos: Go 1.27.3+, Rust 1.99+ (para compilación de verificador aislado).

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

Consuma el token de arranque de un solo uso generado en `<data_dir>/bootstrap.token` para crear la credencial de administrador maestro:

```bash
ehctl init --bootstrap-file /var/lib/eh/bootstrap.token \
    --server https://127.0.0.1:8443 --ca /etc/eh/tls/ca.pem
```

#### 2. Emisión de licencias y sellado de paquetes

```bash
# Generate a new customer license key
ehctl license create --customer "Acme Corp" --channel manual
# Output: EH1-XXXXX-XXXXX-XXXXX-XXXXX

# Seal binary payload into protected distribution package
eh-builder pack --id demo-core --name "Demo Core" --in app.bin
# Output: demo-core.ehpkg (public) + demo-core.provision.json (secret)
ehctl packages import demo-core.provision.json
```

#### 3. Validación del cliente (Windows)

Requisitos previos: Windows 10/11, TPM 2.0 (reserva opcional).

```powershell
cd rust; cargo build --release -p eh-client
target\release\eh-demo.exe --server https://lic.example.com:8443 `
    --license EH1-... --ca ca.pem --package-id demo-core `
    --package-file demo-core.ehpkg --heartbeats 3
```
---
### Preguntas frecuentes

#### ¿Cómo funciona la certificación asistida por TPM?
Las máquinas cliente generan una clave de respaldo (EK) y una clave de atestación (AK) directamente dentro de su chip TPM 2.0 de hardware. Durante la validación de la sesión, el cliente envía una cotización criptográfica a través de registros PCR de hardware. El demonio `eh-trustd` verifica la firma criptográfica sin necesidad de acceder a secretos privados.

#### ¿Matrix llama a casa o rastrea a los usuarios?
No. Matrix es completamente privado y autohospedado. No se comunica con análisis externos, nubes de licencias ni proveedores de identidad de terceros. Toda la comunicación de red se mantiene estrictamente entre sus clientes y su propia instancia de servidor.

#### ¿Se pueden ejecutar las aplicaciones cliente sin hardware TPM 2.0?
Sí. Los clientes pueden especificar `--no-tpm` para registrarse en el nivel de confianza de solo software. En entornos que carecen de chips TPM, las licencias y los latidos criptográficos aún se aplican mediante verificación fuera de banda y almacenamiento DPAPI estándar.

#### ¿Qué sucede si un dispositivo está desconectado?
Las licencias admiten ventanas de arrendamiento configurables. Las aplicaciones de los clientes pueden continuar funcionando mientras dure su arrendamiento activo antes de requerir una renovación en línea o fuera de banda.
---
### Documentación y arquitectura

- [Especificación de protocolo](docs/PROTOCOL.md): protocolo de conexión normativo, puntos finales y máquinas de estado de cliente/administrador
- [Descripción general de la arquitectura] (docs/ARCHITECTURE.md): límites del subsistema, modos de falla y límites de amenazas
- [Decisiones de arquitectura (ADR)](docs/DECISIONS.md) — Justificaciones del diseño y compensaciones
- [Especificación de VM] (docs/VM.md): formato de código de bytes EHVM1 y semántica de ejecución
- [Modelo de amenazas](docs/THREAT_MODEL.md): panorama de amenazas, riesgo residual y supuestos de seguridad del hardware
- [Reforzamiento de la seguridad](docs/SECURITY.md) — Inventario criptográfico y procedimientos de generación de informes
- [Guía de operaciones](docs/OPERACIONES.md): copia de seguridad, restauración, rotación y operaciones del día 2
---
### Pruebas

```bash
go test ./...            # server: unit and HTTP integration test suite
go test -race ./...      # race detector suite (requires gcc)
cd rust && cargo test    # VM, client SDK, and trustd verifier suites
```
---
### Licencia

Con doble licencia bajo:
- [Licencia Apache, Versión 2.0](LICENCIA-APACHE)
- [Licencia MIT](LICENCIA-MIT)

a tu elección.