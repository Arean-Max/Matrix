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

### نظرة عامة

**Matrix** (Event Horizon) عبارة عن بنية أساسية مستقلة لترخيص البرامج ذاتية الاستضافة ومكافحة التلاعب، مصممة خصيصًا لتطبيقات سطح مكتب Windows. فهو يجمع بين تصديق جهاز TPM 2.0 المرتبط بالأجهزة مع عقود إيجار وقت التشغيل المشفرة، وعمليات التنشيط خارج النطاق، وتوفير الحزم المختومة.

لا يوجد أي قياس عن بعد لجهة خارجية، ولا يوجد قفل للموردين، ولا يوجد أي مكالمات تبعية خارجية خارج مجموعة الخوادم المستضافة ذاتيًا.
---
### المكونات

| مكون | كومة | الغرض |
| :--- | :--- | :--- |
| `cmd/eh-server` | اذهب 1.27+ وSQLite | واجهة برمجة تطبيقات HTTP الأساسية: محرك الترخيص، والتحقق من OOB، وتخزين SQLite، وبواب تنظيف الخلفية |
| `كمد/إهكتل` | اذهب سطر الأوامر | واجهة المشغل: تمهيد PKI، إصدار الترخيص، دورة حياة الجهاز، استيراد الحزم، النسخ الاحتياطية |
| `cmd/eh-builder` | اذهب سطر الأوامر | أداة حزم البائع: تحويل الثنائيات إلى توزيعات مشفرة وبيانات التزويد `.ehpkg` |
| `الصدأ/إيه النواة` | الصدأ | الجهاز الظاهري ومجمّع الرمز الثانوي `EHVM1` لحماية التنفيذ (راجع [docs/VM.md](docs/VM.md)) |
| `الصدأ/إيه-ترستد` | الصدأ (معزول) | أداة التحقق من اقتباس TPM ذات وضع الحماية: تقوم بتوزيع هياكل الأجهزة الأولية بدون قاعدة بيانات أو مآخذ توصيل أو وصول سري |
| `الصدأ/إيه العميل` | الصدأ & C FFI | SDK لعميل Windows: روابط TLS وTPM2/TBS وتخزين جهاز DPAPI ورأس C ABI وعميل تجريبي |
---
### البداية السريعة

#### 1. نشر الخادم

المتطلبات الأساسية: الانتقال إلى الإصدار 1.27.3+، وRust 1.99+ (لإنشاء أداة التحقق المعزولة).

___كود بلوك_0___

استخدم رمز التمهيد المميز للاستخدام مرة واحدة والذي تم إنشاؤه على `<data_dir>/bootstrap.token` لإنشاء بيانات اعتماد المسؤول الرئيسي:

___كود بلوك_1___

#### 2. إصدار الترخيص وختم العبوة

___كود بلوك_2___

#### 3. التحقق من صحة العميل (Windows)

المتطلبات الأساسية: Windows 10/11، TPM 2.0 (احتياطي اختياري).

___كود بلوك_3___
---
### الأسئلة الشائعة

#### كيف تعمل عملية التصديق بمساعدة TPM؟
تقوم الأجهزة العميلة بإنشاء مفتاح المصادقة (EK) ومفتاح المصادقة (AK) مباشرة داخل شريحة TPM 2.0 الخاصة بالأجهزة. أثناء التحقق من صحة الجلسة، يرسل العميل عرض أسعار مشفر عبر سجلات PCR للأجهزة. يتحقق البرنامج الخفي "eh-trustd" من التوقيع المشفر دون الحاجة إلى الوصول إلى الأسرار الخاصة.

#### هل يقوم Matrix بالاتصال بالمنزل أو بتتبع المستخدمين؟
لا، إن Matrix خاصة تمامًا وتتم استضافة نفسها ذاتيًا. ولا يتواصل مع التحليلات الخارجية أو سحابات الترخيص أو موفري الهوية التابعين لجهات خارجية. تظل جميع اتصالات الشبكة صارمة بين عملائك ومثيل الخادم الخاص بك.

#### هل يمكن تشغيل تطبيقات العميل بدون أجهزة TPM 2.0؟
نعم. يمكن للعملاء تحديد `--no-tpm` للتسجيل ضمن طبقة الثقة الخاصة بالبرنامج فقط. في البيئات التي تفتقر إلى شرائح TPM، لا يزال يتم فرض التراخيص ونبضات التشفير من خلال التحقق خارج النطاق وتخزين DPAPI القياسي.

#### ماذا يحدث إذا كان الجهاز غير متصل بالإنترنت؟
تدعم التراخيص نوافذ الإيجار القابلة للتكوين. يمكن أن تستمر تطبيقات العميل في العمل طوال مدة عقد الإيجار النشط قبل طلب التجديد عبر الإنترنت أو خارج النطاق.
---
### التوثيق والهندسة المعمارية

- [مواصفات البروتوكول](docs/PROTOCOL.md) - بروتوكول الأسلاك المعياري ونقاط النهاية وأجهزة حالة العميل/المسؤول
- [نظرة عامة على البنية](docs/ARCHITECTURE.md) - حدود النظام الفرعي، وأوضاع الفشل، وحدود التهديد
- [قرارات التصميم (ADR)](docs/DECISIONS.md) - مبررات التصميم والمقايضات
- [مواصفات VM](docs/VM.md) — تنسيق الرمز الثانوي EHVM1 ودلالات التنفيذ
- [نموذج التهديد](docs/THREAT_MODEL.md) — مشهد التهديدات والمخاطر المتبقية وافتراضات أمان الأجهزة
- [التعزيز الأمني](docs/SECURITY.md) — جرد التشفير وإجراءات إعداد التقارير
- [دليل العمليات](docs/OPERATIONS.md) — النسخ الاحتياطي والاستعادة والتدوير وعمليات اليوم الثاني
---
### الاختبارات

```bash
go test ./...            # server: unit and HTTP integration test suite
go test -race ./...      # race detector suite (requires gcc)
cd rust && cargo test    # VM, client SDK, and trustd verifier suites
```
---
### الترخيص

ترخيص مزدوج تحت إما:
- [ترخيص Apache، الإصدار 2.0](LICENSE-APACHE)
- [ترخيص معهد ماساتشوستس للتكنولوجيا] (LICENSE-MIT)

في خيارك.