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

### 개요

**매트릭스**(Event Horizon)는 Windows 데스크톱 애플리케이션용으로 특별히 설계된 자율적, 자체 호스팅 소프트웨어 라이선스 및 변조 방지 인프라입니다. 하드웨어 바인딩된 TPM 2.0 장치 증명을 암호화 런타임 임대, 대역 외 챌린지 활성화 및 봉인된 패키지 프로비저닝과 결합합니다.

타사 원격 측정, 공급업체 종속 및 자체 호스팅 서버 클러스터를 넘어서는 외부 종속성 호출이 없습니다.
---
### 구성 요소

| 구성요소 | 스택 | 목적 |
| :--- | :--- | :--- |
| `cmd/eh-서버` | Go 1.27+ 및 SQLite | 핵심 HTTP API: 라이센스 엔진, OOB 검증, SQLite 스토리지, 백그라운드 정리 관리인 |
| `cmd/ehctl` | CLI로 이동 | 운영자 인터페이스: PKI 부트스트래핑, 라이센스 발급, 장치 수명주기, 패키지 가져오기, 백업 |
| `cmd/eh-builder` | CLI로 이동 | 공급업체 패키저: 바이너리를 암호화된 `.ehpkg` 배포판 및 프로비저닝 매니페스트로 변환 |
| `녹/에-코어` | 녹 | 실행 보호를 위한 `EHVM1` 바이트코드 가상 머신 및 어셈블러([docs/VM.md](docs/VM.md) 참조) |
| `rust/eh-trustd` | 녹(격리됨) | 샌드박스 TPM 견적 검증기: DB, 소켓 또는 비밀 액세스 없이 원시 하드웨어 구조를 구문 분석합니다.
| `rust/eh-client` | 러스트 앤 C FFI | Windows 클라이언트 SDK: TLS, TPM2/TBS 바인딩, DPAPI 머신 스토리지, C ABI 헤더, 데모 클라이언트 |
---
### 빠른 시작

#### 1. 서버 배포

전제 조건: Go 1.27.3+, Rust 1.99+(격리된 검증 도구 빌드용)

____코드블록_0___

`<data_dir>/bootstrap.token`에서 생성된 일회용 부트스트랩 토큰을 사용하여 마스터 관리자 자격 증명을 만듭니다.

____코드블록_1___

#### 2. 라이선스 발급 및 패키지 봉인

____코드블록_2___

#### 3. 클라이언트 유효성 검사(Windows)

전제 조건: Windows 10/11, TPM 2.0(선택적 대체).

____코드블록_3___
---
### FAQ

#### TPM 지원 증명은 어떻게 작동하나요?
클라이언트 컴퓨터는 하드웨어 TPM 2.0 칩 내에서 직접 EK(인증 키) 및 AK(증명 키)를 생성합니다. 세션 유효성 검사 중에 클라이언트는 하드웨어 PCR 레지스터를 통해 암호화 견적을 제출합니다. 'eh-trustd' 데몬은 개인 비밀에 접근할 필요 없이 암호화 서명을 확인합니다.

#### Matrix는 집에 전화를 걸거나 사용자를 추적합니까?
아니요. Matrix는 완전히 비공개이며 자체 호스팅됩니다. 외부 분석, 라이센스 클라우드 또는 타사 ID 공급자와 통신하지 않습니다. 모든 네트워크 통신은 클라이언트와 자체 서버 인스턴스 간에 엄격하게 유지됩니다.

#### TPM 2.0 하드웨어 없이 클라이언트 애플리케이션을 실행할 수 있나요?
예. 클라이언트는 '--no-tpm'을 지정하여 소프트웨어 전용 신뢰 계층에 등록할 수 있습니다. TPM 칩이 없는 환경에서도 라이선스 및 암호화 하트비트는 대역 외 확인 및 표준 DPAPI 스토리지를 통해 계속 적용됩니다.

#### 기기가 오프라인이면 어떻게 되나요?
라이센스는 구성 가능한 임대 기간을 지원합니다. 클라이언트 애플리케이션은 온라인 또는 대역 외 갱신을 요구하기 전에 활성 임대 기간 동안 계속 작동할 수 있습니다.
---
### 문서 및 아키텍처

- [프로토콜 사양](docs/PROTOCOL.md) — 표준 유선 프로토콜, 엔드포인트 및 클라이언트/관리 상태 머신
- [아키텍처 개요](docs/ARCHITECTURE.md) — 하위 시스템 경계, 오류 모드 및 위협 경계
- [아키텍처 결정(ADR)](docs/DECISIONS.md) — 설계 이론적 근거 및 장단점
- [VM 사양](docs/VM.md) — EHVM1 바이트코드 형식 및 실행 의미
- [위협 모델](docs/THREAT_MODEL.md) — 위협 환경, 잔여 위험 및 하드웨어 보안 가정
- [보안 강화](docs/SECURITY.md) — 암호화 인벤토리 및 보고 절차
- [운영 가이드](docs/OPERATIONS.md) — 백업, 복원, 순환 및 2일 차 작업
---
### 테스트

____코드블록_4___
---
### 라이센스

다음 중 하나에 따라 이중 라이센스가 부여됩니다.
- [아파치 라이선스, 버전 2.0](LICENSE-APACHE)
- [MIT 라이선스](LICENSE-MIT)

귀하의 선택에 따라.