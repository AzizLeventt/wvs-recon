# 🛡️ WVS-Recon

WVS-Recon, web uygulamalarına yönelik bilgi toplama ve zafiyet tarama aracı olarak geliştirilmiştir. Komut satırından kullanılabilir, modüler yapısı sayesinde esnek ve genişletilebilir bir tarama altyapısı sunar.

---

## ⚙️ Özellikler

- 🌐 **Subdomain Taraması** (crt.sh üzerinden)
- 🔌 **Port Taraması** (çoklu port desteği)
- 📁 **Dizin Taraması** (200, 301, 403 gibi HTTP kodlarına göre filtreleme)
- ⚠️ **Zafiyetli Endpoint Tespiti** (common admin paths, backup dosyalar vs.)
- 🧪 **XSS Taraması** (input formları üzerinden basit payload testleri)
- 📄 **JSON & HTML Raporlama**
- ⚡ **Hızlı & normal tarama modu**
- 🧾 **Çoklu hedef desteği**

---

## 🧪 Kullanım

### ✅ Tek hedef:
```bash
python main.py --target example.com --subdomain --ports --dirs --vuln --xss
```

### ⚡ Hızlı mod:
```bash
python main.py --target example.com --dirs --fast
```

### 📁 Hedef listesi:
```bash
python main.py --list targets.txt --ports --dirs
```

### 💾 Özel çıktı dosyası:
```bash
python main.py --target example.com --xss --output testxss.json
```

---

## 📂 Klasör Yapısı

```
wvs_recon/
├── config/
│   └── settings.py
├── modules/
│   ├── __init__.py
│   ├── dir_enum.py
│   ├── port_scan.py
│   ├── subdomain_enum.py
│   ├── tech_detect.py
│   ├── vuln_checker.py
│   └── xss_scanner.py
├── output/
│   ├── logs/
│   │   └── scan.log
│   ├── example_com_report.json
│   ├── report.html
│   ├── report.json
│   ├── sebscafe_com_report.json
│   ├── sebscan.json
│   ├── testphp_vulnweb_com_report.json
│   └── testxss.json
├── utils/
│   ├── __init__.py
│   ├── colors.py
│   ├── file_writer.py
│   ├── html_report.py
│   ├── http_client.py
│   └── logger.py
├── wordlists/
│   ├── common.txt
│   └── quick.txt
├── targets.txt
├── main.py
├── .gitignore
├── README.md
└── requirements.txt
```

---

## ❗ Notlar

- 🧪 XSS modülü, sadece basit GET parametreli sayfaları test eder.
- 📁 `output/` klasörü altında tüm JSON ve HTML çıktılar yer alır.
- 🌐 HTML raporlar, otomatik olarak tarayıcıda açılır.