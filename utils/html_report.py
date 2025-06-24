import json
import os
import webbrowser

def generate_html_report(json_path, output_html_path="output/report.html"):
    if not os.path.exists(json_path):
        print(f"[!] JSON dosyası bulunamadı: {json_path}")
        return

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    domain = data.get("domain", "Bilinmiyor")
    subdomains = data.get("subdomains", [])
    open_ports = data.get("open_ports", [])
    found_dirs = data.get("found_dirs", [])
    vuln_endpoints = data.get("vuln_endpoints", [])

    html = f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <title>WVS-Recon Rapor - {domain}</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }}
            h1 {{ color: #2c3e50; }}
            h2 {{ color: #34495e; }}
            ul {{ background: #fff; padding: 15px 25px; border-radius: 10px; box-shadow: 0 0 8px rgba(0,0,0,0.1); }}
            li {{ margin: 8px 0; font-size: 16px; }}
            .section {{ margin-bottom: 30px; }}
        </style>
    </head>
    <body>
        <h1>🛡️ WVS-Recon Raporu - {domain}</h1>

        <div class="section">
            <h2>🌐 Subdomain'ler</h2>
            <ul>
                {''.join(f"<li>{s}</li>" for s in subdomains) or "<li>Bulunamadı</li>"}
            </ul>
        </div>

        <div class="section">
            <h2>🚪 Açık Portlar</h2>
            <ul>
                {''.join(f"<li>{p}</li>" for p in open_ports) or "<li>Bulunamadı</li>"}
            </ul>
        </div>

        <div class="section">
            <h2>📁 Dizinler</h2>
            <ul>
                {''.join(f"<li>{d}</li>" for d in found_dirs) or "<li>Bulunamadı</li>"}
            </ul>
        </div>

        <div class="section">
            <h2>⚠️ Zafiyetli Endpoint'ler</h2>
            <ul>
                {''.join(f"<li style='color:red;'>{v}</li>" for v in vuln_endpoints) or "<li>Bulunamadı</li>"}
            </ul>
        </div>
    </body>
    </html>
    """

    # Dosyayı yaz ve klasörü oluştur
    os.makedirs(os.path.dirname(output_html_path), exist_ok=True)
    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # Tam dosya yolu (Windows uyumlu, file:/// formatında)
    full_path = os.path.abspath(output_html_path).replace(os.sep, "/")
    url = f"file:///{full_path}"
    print(f"[+] HTML raporu oluşturuldu: {url}")

    # Tarayıcıda aç
    webbrowser.open(url)

# Komut satırından çalıştırıldığında
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Kullanım: python utils/html_report.py <json_dosyasi>")
    else:
        generate_html_report(sys.argv[1])
