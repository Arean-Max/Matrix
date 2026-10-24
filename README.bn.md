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

### ওভারভিউ

**ম্যাট্রিক্স** (ইভেন্ট হরাইজন) হল একটি স্বায়ত্তশাসিত, স্ব-হোস্টেড সফ্টওয়্যার লাইসেন্সিং এবং অ্যান্টি-টেম্পার অবকাঠামো যা বিশেষভাবে উইন্ডোজ ডেস্কটপ অ্যাপ্লিকেশনের জন্য ডিজাইন করা হয়েছে। এটি হার্ডওয়্যার-বাউন্ড TPM 2.0 ডিভাইস প্রত্যয়নকে ক্রিপ্টোগ্রাফিক রানটাইম লিজ, আউট-অফ-ব্যান্ড চ্যালেঞ্জ অ্যাক্টিভেশন এবং সিল করা প্যাকেজ প্রভিশনের সাথে যুক্ত করে।

জিরো থার্ড-পার্টি টেলিমেট্রি, শূন্য ভেন্ডর লক-ইন, এবং শূন্য এক্সটার্নাল ডিপেন্ডেন্সি কল আপনার স্ব-হোস্টেড সার্ভার ক্লাস্টারের বাইরে।
---
### উপাদান

| উপাদান | স্ট্যাক | উদ্দেশ্য |
| :--- | :--- | :--- |
| `cmd/eh-server` | যান 1.27+ এবং SQLite | কোর HTTP API: লাইসেন্সিং ইঞ্জিন, OOB যাচাইকরণ, SQLite স্টোরেজ, ব্যাকগ্রাউন্ড ক্লিনআপ দারোয়ান |
| `cmd/ehctl` | যান CLI | অপারেটর ইন্টারফেস: PKI বুটস্ট্র্যাপিং, লাইসেন্স প্রদান, ডিভাইস লাইফসাইকেল, প্যাকেজ আমদানি, ব্যাকআপ |
| `cmd/eh-builder` | যান CLI | ভেন্ডর প্যাকেজার: বাইনারিগুলিকে এনক্রিপ্ট করা `.ehpkg` ডিস্ট্রিবিউশন এবং প্রভিশনিং ম্যানিফেস্টে রূপান্তরিত করে |
| `মরিচা/ইহ-কোর` | মরিচা | `EHVM1` বাইটকোড ভার্চুয়াল মেশিন এবং এক্সিকিউশন সুরক্ষার জন্য অ্যাসেম্বলার (দেখুন [docs/VM.md](docs/VM.md)) |
| `মরিচা/এহ-বিশ্বাস` | মরিচা (বিচ্ছিন্ন) | স্যান্ডবক্সযুক্ত TPM উদ্ধৃতি যাচাইকারী: DB, সকেট, বা গোপন অ্যাক্সেস ছাড়াই কাঁচা হার্ডওয়্যার কাঠামো পার্স করে |
| `মরিচা/এহ-ক্লায়েন্ট` | মরিচা ও সি এফএফআই | উইন্ডোজ ক্লায়েন্ট SDK: TLS, TPM2/TBS বাইন্ডিং, DPAPI মেশিন স্টোরেজ, C ABI হেডার, ডেমো ক্লায়েন্ট |
---
### দ্রুত শুরু

#### 1. সার্ভার স্থাপনা

পূর্বশর্ত: Go 1.27.3+, Rust 1.99+ (বিচ্ছিন্ন যাচাইকারী বিল্ডের জন্য)।

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

মাস্টার অ্যাডমিনিস্ট্রেটর শংসাপত্র তৈরি করতে `<data_dir>/bootstrap.token`-এ জেনারেট করা একক-ব্যবহারের বুটস্ট্র্যাপ টোকেন ব্যবহার করুন:

```bash
ehctl init --bootstrap-file /var/lib/eh/bootstrap.token \
    --server https://127.0.0.1:8443 --ca /etc/eh/tls/ca.pem
```

#### 2. লাইসেন্স প্রদান এবং প্যাকেজ সিল করা

```bash
# Generate a new customer license key
ehctl license create --customer "Acme Corp" --channel manual
# Output: EH1-XXXXX-XXXXX-XXXXX-XXXXX

# Seal binary payload into protected distribution package
eh-builder pack --id demo-core --name "Demo Core" --in app.bin
# Output: demo-core.ehpkg (public) + demo-core.provision.json (secret)
ehctl packages import demo-core.provision.json
```

#### 3. ক্লায়েন্ট যাচাইকরণ (উইন্ডোজ)

পূর্বশর্ত: Windows 10/11, TPM 2.0 (ঐচ্ছিক ফলব্যাক)।

```powershell
cd rust; cargo build --release -p eh-client
target\release\eh-demo.exe --server https://lic.example.com:8443 `
    --license EH1-... --ca ca.pem --package-id demo-core `
    --package-file demo-core.ehpkg --heartbeats 3
```
---
### প্রায়শই জিজ্ঞাসিত প্রশ্ন

#### টিপিএম-সহায়ক প্রত্যয়ন কীভাবে কাজ করে?
ক্লায়েন্ট মেশিনগুলি সরাসরি তাদের হার্ডওয়্যার TPM 2.0 চিপের ভিতরে একটি এনডোর্সমেন্ট কী (EK) এবং প্রত্যয়ন কী (AK) তৈরি করে। সেশনের বৈধতার সময়, ক্লায়েন্ট হার্ডওয়্যার পিসিআর রেজিস্টারের উপর একটি ক্রিপ্টোগ্রাফিক উদ্ধৃতি জমা দেয়। 'eh-trustd' ডেমন ব্যক্তিগত গোপনীয়তায় অ্যাক্সেসের প্রয়োজন ছাড়াই ক্রিপ্টোগ্রাফিক স্বাক্ষর যাচাই করে।

#### ম্যাট্রিক্স ফোন কি হোম বা ট্র্যাক ব্যবহারকারীদের?
না। ম্যাট্রিক্স সম্পূর্ণ ব্যক্তিগত এবং স্ব-হোস্টেড। এটি বাহ্যিক বিশ্লেষণ, লাইসেন্স ক্লাউড বা তৃতীয় পক্ষের পরিচয় প্রদানকারীদের সাথে যোগাযোগ করে না। সমস্ত নেটওয়ার্ক যোগাযোগ আপনার ক্লায়েন্ট এবং আপনার নিজের সার্ভার উদাহরণের মধ্যে কঠোরভাবে অবশেষ।

#### ক্লায়েন্ট অ্যাপ্লিকেশন কি TPM 2.0 হার্ডওয়্যার ছাড়া চলতে পারে?
হ্যাঁ। ক্লায়েন্টরা শুধুমাত্র সফ্টওয়্যার ট্রাস্ট স্তরের অধীনে নিবন্ধন করতে `--no-tpm` নির্দিষ্ট করতে পারেন। TPM চিপগুলির অভাবের পরিবেশে, লাইসেন্স এবং ক্রিপ্টোগ্রাফিক হার্টবিটগুলি এখনও আউট-অফ-ব্যান্ড যাচাইকরণ এবং স্ট্যান্ডার্ড DPAPI স্টোরেজের মাধ্যমে প্রয়োগ করা হয়।

#### একটি ডিভাইস অফলাইনে থাকলে কি হবে?
লাইসেন্সগুলি কনফিগারযোগ্য লিজ উইন্ডো সমর্থন করে। ক্লায়েন্ট অ্যাপ্লিকেশনগুলি একটি অনলাইন বা ব্যান্ডের বাইরের পুনর্নবীকরণের প্রয়োজন হওয়ার আগে তাদের সক্রিয় লিজের সময়কালের জন্য কাজ চালিয়ে যেতে পারে।
---
### ডকুমেন্টেশন এবং আর্কিটেকচার

- [প্রোটোকল স্পেসিফিকেশন](docs/PROTOCOL.md) — আদর্শ ওয়্যার প্রোটোকল, এন্ডপয়েন্ট এবং ক্লায়েন্ট/অ্যাডমিন স্টেট মেশিন
- [আর্কিটেকচার ওভারভিউ](docs/ARCHITECTURE.md) — সাবসিস্টেম সীমানা, ব্যর্থতার মোড এবং হুমকির সীমানা
- [আর্কিটেকচার ডিসিশনস (ADR)](docs/DECISIONS.md) — ডিজাইনের যুক্তি এবং ট্রেড-অফ
- [VM স্পেসিফিকেশন](docs/VM.md) — EHVM1 বাইটকোড ফরম্যাট এবং এক্সিকিউশন শব্দার্থবিদ্যা
- [হুমকি মডেল](docs/THREAT_MODEL.md) — হুমকি ল্যান্ডস্কেপ, অবশিষ্ট ঝুঁকি, এবং হার্ডওয়্যার নিরাপত্তা অনুমান
- [নিরাপত্তা হার্ডেনিং](docs/SECURITY.md) — ক্রিপ্টোগ্রাফিক ইনভেন্টরি এবং রিপোর্টিং পদ্ধতি
- [অপারেশন গাইড](docs/OPERATIONS.md) — ব্যাকআপ, পুনরুদ্ধার, ঘূর্ণন, এবং দিন-2 অপারেশন
---
### টেস্ট

___কোডব্লক_৪___
---
### লাইসেন্স

উভয়ের অধীনে দ্বৈত লাইসেন্সপ্রাপ্ত:
- [অ্যাপাচি লাইসেন্স, সংস্করণ 2.0](লাইসেন্স-অ্যাপাচি)
- [এমআইটি লাইসেন্স](লাইসেন্স-এমআইটি)

আপনার বিকল্পে।