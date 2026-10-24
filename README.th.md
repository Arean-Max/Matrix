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

### ภาพรวม

**Matrix** (Event Horizon) คือซอฟต์แวร์ลิขสิทธิ์ซอฟต์แวร์ที่โฮสต์ด้วยตนเองและโครงสร้างพื้นฐานป้องกันการงัดแงะ ซึ่งออกแบบมาสำหรับแอปพลิเคชันเดสก์ท็อป Windows โดยเฉพาะ โดยจับคู่การรับรองอุปกรณ์ TPM 2.0 ที่เกี่ยวข้องกับฮาร์ดแวร์เข้ากับการเช่ารันไทม์แบบเข้ารหัส การเปิดใช้งานความท้าทายนอกแบนด์ และการจัดเตรียมแพ็คเกจแบบปิดผนึก

การวัดและส่งข้อมูลทางไกลของบุคคลที่สามเป็นศูนย์ การล็อคอินของผู้ขายเป็นศูนย์ และการเรียกการพึ่งพาภายนอกเป็นศูนย์นอกเหนือจากคลัสเตอร์เซิร์ฟเวอร์ที่โฮสต์เองของคุณ
---
### ส่วนประกอบ

| ส่วนประกอบ | สแต็ค | วัตถุประสงค์ |
| :--- | :--- | :--- |
| `cmd/eh-เซิร์ฟเวอร์` | ไป 1.27+ & SQLite | Core HTTP API: กลไกการออกใบอนุญาต, การตรวจสอบ OOB, ที่เก็บข้อมูล SQLite, ภารโรงล้างพื้นหลัง |
| `cmd/ehctl` | ไป CLI | อินเทอร์เฟซผู้ดำเนินการ: การบูต PKI, การออกใบอนุญาต, วงจรการใช้งานของอุปกรณ์, การนำเข้าแพ็คเกจ, การสำรองข้อมูล |
| `cmd/eh-builder` | ไป CLI | ผู้จัดแพคเกจผู้ขาย: แปลงไบนารีเป็นการแจกแจง `.ehpkg` ที่เข้ารหัสและการจัดเตรียมรายการ |
| `สนิม/เอ๊ะ-คอร์` | สนิม | เครื่องเสมือนและแอสเซมเบลอร์ `EHVM1` bytecode สำหรับการป้องกันการดำเนินการ (ดู [docs/VM.md](docs/VM.md)) |
| `สนิม/เอ๊ะ-trustd` | สนิม (แยก) | เครื่องมือตรวจสอบใบเสนอราคา TPM แบบแซนด์บ็อกซ์: แยกวิเคราะห์โครงสร้างฮาร์ดแวร์ดิบโดยไม่มี DB, ซ็อกเก็ต หรือการเข้าถึงที่เป็นความลับ |
| `rust/eh-client` | สนิม & ซี FFI | SDK ไคลเอนต์ Windows: TLS, การเชื่อมโยง TPM2/TBS, ที่เก็บข้อมูลเครื่อง DPAPI, ส่วนหัว C ABI, ไคลเอนต์สาธิต |
---
### เริ่มต้นอย่างรวดเร็ว

#### 1. การปรับใช้เซิร์ฟเวอร์

ข้อกำหนดเบื้องต้น: ไป 1.27.3+, Rust 1.99+ (สำหรับการสร้างตัวตรวจสอบแบบแยก)

___โค้ดบล็อก_0___

ใช้โทเค็นบูตสแตรปแบบใช้ครั้งเดียวที่สร้างขึ้นที่ `<data_dir>/bootstrap.token` เพื่อสร้างข้อมูลรับรองผู้ดูแลระบบหลัก:

___รหัสบล็อก_1___

#### 2. การออกใบอนุญาตและการปิดผนึกบรรจุภัณฑ์

___โค้ดบล็อก_2___

#### 3. การตรวจสอบลูกค้า (Windows)

ข้อกำหนดเบื้องต้น: Windows 10/11, TPM 2.0 (ทางเลือกสำรอง)

___รหัสบล็อก_3___
---
### คำถามที่พบบ่อย

#### การรับรองที่ได้รับความช่วยเหลือจาก TPM ทำงานอย่างไร
เครื่องไคลเอนต์สร้างคีย์การรับรอง (EK) และคีย์การรับรอง (AK) โดยตรงภายในชิปฮาร์ดแวร์ TPM 2.0 ในระหว่างการตรวจสอบความถูกต้องของเซสชัน ลูกค้าจะส่งใบเสนอราคาที่เข้ารหัสลับผ่านการลงทะเบียน PCR ของฮาร์ดแวร์ `eh-trustd` daemon ตรวจสอบลายเซ็นการเข้ารหัสโดยไม่จำเป็นต้องเข้าถึงความลับส่วนตัว

#### Matrix โทรศัพท์กลับบ้านหรือติดตามผู้ใช้หรือไม่
ไม่ Matrix เป็นส่วนตัวโดยสมบูรณ์และโฮสต์ด้วยตนเอง ไม่สื่อสารกับการวิเคราะห์ภายนอก ใบอนุญาตคลาวด์ หรือผู้ให้บริการข้อมูลประจำตัวบุคคลที่สาม การสื่อสารเครือข่ายทั้งหมดจะยังคงเคร่งครัดระหว่างไคลเอนต์ของคุณและอินสแตนซ์เซิร์ฟเวอร์ของคุณเอง

#### แอปพลิเคชันไคลเอ็นต์สามารถทำงานได้โดยไม่ต้องใช้ฮาร์ดแวร์ TPM 2.0 หรือไม่
ใช่. ลูกค้าสามารถระบุ `--no-tpm` เพื่อลงทะเบียนภายใต้ระดับความน่าเชื่อถือเฉพาะซอฟต์แวร์เท่านั้น ในสภาพแวดล้อมที่ไม่มีชิป TPM ใบอนุญาตและฮาร์ทบีทการเข้ารหัสยังคงบังคับใช้ผ่านการตรวจสอบนอกแบนด์และพื้นที่เก็บข้อมูล DPAPI มาตรฐาน

#### จะเกิดอะไรขึ้นหากอุปกรณ์ออฟไลน์อยู่
ใบอนุญาตสนับสนุนหน้าต่างการเช่าที่กำหนดค่าได้ แอปพลิเคชันไคลเอนต์สามารถดำเนินการต่อไปได้ตลอดระยะเวลาการเช่าที่ใช้งานอยู่ก่อนที่จะต้องต่ออายุออนไลน์หรือนอกกลุ่ม
---
### เอกสารและสถาปัตยกรรม

- [ข้อกำหนดโปรโตคอล](docs/PROTOCOL.md) — โปรโตคอลสายมาตรฐาน จุดสิ้นสุด และเครื่องสถานะไคลเอ็นต์/ผู้ดูแลระบบ
- [ภาพรวมสถาปัตยกรรม](docs/ARCHITECTURE.md) — ขอบเขตของระบบย่อย โหมดความล้มเหลว และขอบเขตภัยคุกคาม
- [การตัดสินใจทางสถาปัตยกรรม (ADR)](docs/DECISIONS.md) — เหตุผลในการออกแบบและข้อดีข้อเสีย
- [VM Specification](docs/VM.md) — รูปแบบโค้ดไบต์ EHVM1 และซีแมนทิกส์การดำเนินการ
- [โมเดลภัยคุกคาม](docs/THREAT_MODEL.md) — ภาพรวมภัยคุกคาม ความเสี่ยงตกค้าง และสมมติฐานด้านความปลอดภัยของฮาร์ดแวร์
- [การเสริมความปลอดภัย](docs/SECURITY.md) — สินค้าคงคลังที่เข้ารหัสลับและขั้นตอนการรายงาน
- [คู่มือการใช้งาน](docs/OPERATIONS.md) — สำรองข้อมูล กู้คืน หมุนเวียน และดำเนินการวันที่ 2
---
### การทดสอบ

___รหัสบล็อก_4___
---
### ใบอนุญาต

ได้รับอนุญาตแบบ Dual ภายใต้:
- [ใบอนุญาต Apache เวอร์ชัน 2.0] (ใบอนุญาต-APACHE)
- [ใบอนุญาต MIT] (ใบอนุญาต-MIT)

ตามตัวเลือกของคุณ