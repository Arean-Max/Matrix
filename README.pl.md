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

### Przegląd

**Matrix** (Event Horizon) to autonomiczna, hostowana samodzielnie infrastruktura licencjonowania oprogramowania i zapobiegania manipulacji, zaprojektowana specjalnie dla aplikacji komputerowych Windows. Łączy sprzętową atestację urządzeń TPM 2.0 z dzierżawą środowiska wykonawczego kryptografii, aktywacjami wyzwań poza pasmem i udostępnianiem zapieczętowanych pakietów.

Zero telemetrii innych firm, zero uzależnienia od dostawcy i zero wywołań zależności zewnętrznych poza klastrem serwerów hostowanym samodzielnie.
---
### Komponenty

| Składnik | Stos | Cel |
| :--- | :--- | :--- |
| `cmd/eh-serwer` | Przejdź na wersję 1.27+ i SQLite | Podstawowy interfejs API HTTP: silnik licencjonowania, weryfikacja OOB, pamięć SQLite, woźny czyszczenia tła |
| `cmd/ehctl` | Przejdź do interfejsu wiersza polecenia | Interfejs operatora: ładowanie PKI, wydawanie licencji, cykl życia urządzenia, import pakietów, kopie zapasowe |
| `cmd/eh-builder` | Przejdź do interfejsu wiersza polecenia | Narzędzie do pakowania dostawców: przekształca pliki binarne w zaszyfrowane dystrybucje `.ehpkg` i manifesty udostępniania |
| `rdza/rdzeń eh` | Rdza | Maszyna wirtualna z kodem bajtowym `EHVM1` i asembler do ochrony wykonania (patrz [docs/VM.md](docs/VM.md)) |
| `rdza/eh-trustd` | Rdza (pojedyncze) | Weryfikator ofert TPM w trybie piaskownicy: analizuje surowe struktury sprzętowe bez bazy danych, gniazd i tajnego dostępu |
| `rust/eh-klient` | Rust & C FFI | SDK klienta Windows: TLS, powiązania TPM2/TBS, pamięć maszynowa DPAPI, nagłówek C ABI, klient demonstracyjny |
---
### Szybki start

#### 1. Wdrożenie serwera

Wymagania wstępne: Przejdź na wersję 1.27.3+, Rust 1.99+ (dla wersji izolowanego weryfikatora).

___KODBLOK_0___

Wykorzystaj jednorazowy token ładowania początkowego wygenerowany w `<katalog_danych>/bootstrap.token`, aby utworzyć dane uwierzytelniające głównego administratora:

___KODBLOK_1___

#### 2. Wydanie licencji i zapieczętowanie paczki

___KODBLOK_2___

#### 3. Walidacja klienta (Windows)

Wymagania wstępne: Windows 10/11, TPM 2.0 (opcjonalny powrót).

___KODBLOK_3___
---
### Często zadawane pytania

#### Jak działa atest wspomagany przez moduł TPM?
Maszyny klienckie generują klucz potwierdzenia (EK) i klucz zaświadczenia (AK) bezpośrednio w swoim sprzętowym chipie TPM 2.0. Podczas sprawdzania sesji klient przesyła wycenę kryptograficzną za pośrednictwem sprzętowych rejestrów PCR. Demon `eh-trustd` weryfikuje podpis kryptograficzny bez konieczności dostępu do prywatnych sekretów.

#### Czy Matrix dzwoni do domu lub śledzi użytkowników?
Nie. Matrix jest całkowicie prywatny i hostowany samodzielnie. Nie komunikuje się z zewnętrznymi analitykami, chmurami licencji ani zewnętrznymi dostawcami tożsamości. Cała komunikacja sieciowa pozostaje wyłącznie pomiędzy Twoimi klientami a Twoją instancją serwera.

#### Czy aplikacje klienckie mogą działać bez sprzętu TPM 2.0?
Tak. Klienci mogą określić opcję „--no-tpm”, aby zarejestrować się w warstwie zaufania obejmującej tylko oprogramowanie. W środowiskach pozbawionych chipów TPM licencje i pulsy kryptograficzne są nadal wymuszane poprzez weryfikację poza pasmem i standardową pamięć masową DPAPI.

#### Co się stanie, jeśli urządzenie będzie offline?
Licencje obsługują konfigurowalne okna najmu. Aplikacje klienckie mogą nadal działać przez cały czas trwania aktywnej dzierżawy, zanim będą wymagały odnowienia online lub poza pasmem.
---
### Dokumentacja i architektura

- [Specyfikacja protokołu](docs/PROTOCOL.md) — Normatywny protokół przewodowy, punkty końcowe i maszyny stanu klient/administrator
- [Przegląd architektury](docs/ARCHITECTURE.md) — Granice podsystemów, tryby awarii i granice zagrożeń
- [Decyzje architektoniczne (ADR)](docs/DECISIONS.md) – Uzasadnienie projektu i kompromisy
- [Specyfikacja maszyny wirtualnej](docs/VM.md) — Format kodu bajtowego EHVM1 i semantyka wykonania
- [Model zagrożeń](docs/THREAT_MODEL.md) — Krajobraz zagrożeń, ryzyko szczątkowe i założenia dotyczące bezpieczeństwa sprzętu
- [Wzmocnienie bezpieczeństwa](docs/SECURITY.md) — Inwentaryzacja kryptograficzna i procedury raportowania
- [Podręcznik operacyjny](docs/OPERATIONS.md) — Tworzenie kopii zapasowych, przywracanie, rotacja i operacje dnia drugiego
---
### Testy

___KODBLOK_4___
---
### Licencja

Podwójna licencja na mocy:
- [Licencja Apache, wersja 2.0](LICENCJA-APACHE)
- [Licencja MIT](LICENCJA-MIT)

według własnego wyboru.