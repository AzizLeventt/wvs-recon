# WVS-Recon 🔎

Web Vulnerability Scanner – Recon Tool  
Modüler, hızlı ve detaylı web güvenlik tarayıcısı.

## 🔧 Özellikler

✅ Subdomain taraması (`crt.sh`)  
✅ Port taraması (socket)  
✅ Dizin taraması (`wordlist` destekli)  
✅ Admin panel dizin taraması (özel paths)  
✅ Zafiyetli endpoint kontrolü (`/phpinfo`, `/test`, vb.)  
✅ XSS testi (input analizli + payload istatistiği)  
✅ SQLi testi (form odaklı)  
✅ CSRF & Open Redirect testleri  
✅ IDOR zafiyeti analizi (parametre oynama)  
✅ HTML + JSON çıktı desteği  
✅ Flask web arayüzü  
✅ Otomatik rapor oluşturma (renkli ve okunabilir)

## 🚀 Kurulum

```bash
git clone https://github.com/kendi-repo/WVS-Recon.git
cd WVS-Recon
pip install -r requirements.txt
```

## ⚙️ Kullanım

### Terminal Üzerinden

```bash
python main.py --target example.com --dirs --xss --form --formtest
```

### Web Arayüzü

```bash
cd wvs_web
python app.py
```

Tarama bittiğinde otomatik olarak HTML rapor oluşturulur ve tarayıcıda görüntülenir.

## 📂 Raporlama

Tüm çıktılar `output/` dizinine `.json` ve `.html` olarak kaydedilir.  
HTML raporlar aşağıdaki bölümleri içerir:

- 🎯 Hedef
- 🌐 Subdomain listesi
- 🔓 Açık portlar
- 📂 Dizin listesi
- 🔐 Admin panel yolları
- 🛂 IDOR açıkları
- 🧪 XSS, SQLi, CSRF, Redirect zafiyetleri
- 📝 Form yapıları ve test sonuçları

## 📌 Örnek Komutlar

```bash
python main.py --target testphp.vulnweb.com --dirs --xss --form --formtest --fast
```

```bash
python main.py --list targets.txt --subdomain --ports --vuln
```


