import json
import os
from pathlib import Path
from utils.logger import success, error


def generate_html_report(json_file: str) -> str:
    """Verilen JSON rapor dosyasını okuyup AYNI klasöre, **JSON dosya adıyla
    aynı stem'e** (uzantısız ada) sahip bir HTML raporu üretir ve yolunu döndürür.

    Örnek:
        output/example_com_report.json ➜ output/example_com_report.html
    """
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        error(f"JSON raporu okunamadı: {exc}")
        raise

    # Hedefe özgü dosya adı oluştur
    html_file = os.path.join(
        os.path.dirname(json_file),
        f"{Path(json_file).stem}.html",
    )

    # ---- HTML İçerik ----
    domain = data.get("domain", "")
    html = [
        "<!DOCTYPE html>",
        "<html lang=\"tr\">",
        "<head>",
        f"    <meta charset='UTF-8'>",
        f"    <title>WVS-Recon Raporu - {domain}</title>",
        "    <style>",
        "        body { font-family: Arial, sans-serif; padding: 20px; }",
        "        h1 { color: #4a148c; }",
        "        h2 { color: #6a1b9a; }",
        "        ul { list-style-type: none; padding-left: 0; }",
        "        li { margin-bottom: 5px; }",
        "        .code { font-family: monospace; background: #f0f0f0; padding: 3px 6px; border-radius: 4px; }",
        "    </style>",
        "</head>",
        "<body>",
        "    <h1>WVS-Recon Raporu</h1>",
        f"    <p><strong>Hedef:</strong> {domain}</p>",
    ]

    # Yardımcı şablon fonksiyonu
    def add_list_section(title: str, items):
        if items:
            html.extend([f"    <h2>{title}</h2>", "    <ul>"])
            for item in items:
                if isinstance(item, tuple):
                    # (url, code) şeklindeki veriler
                    url, code = item
                    html.append(f"        <li>{url} <span class='code'>({code})</span></li>")
                else:
                    html.append(f"        <li>{item}</li>")
            html.extend(["    </ul>"])

    add_list_section("Subdomain'ler", data.get("subdomains", []))
    add_list_section("Açık Portlar", data.get("open_ports", []))
    add_list_section("Açık Dizinler", data.get("found_dirs", []))
    add_list_section("Zafiyet Endpoint'leri", data.get("vuln_endpoints", []))
    add_list_section("XSS Açıkları", data.get("xss_results", []))

    # Formlar
    if data.get("form_data"):
        html.extend(["    <h2>Formlar</h2>", "    <ul>"])
        for form in data["form_data"]:
            html.append("        <li>")
            html.append(f"            <b>Yöntem:</b> {form.get('method', '').upper()}<br>")
            html.append(f"            <b>Action:</b> {form.get('action', '')}<br>")
            inputs = form.get("inputs", {})
            html.append("            <b>Inputlar:</b><ul>")
            if isinstance(inputs, dict):
                for name, typ in inputs.items():
                    html.append(f"                <li>{name} ({typ})</li>")
            elif isinstance(inputs, list):
                for inp in inputs:
                    if isinstance(inp, dict):
                        html.append(f"                <li>{inp.get('name', 'unknown')} ({inp.get('type', 'text')})</li>")
            html.append("            </ul><br>")
            html.append("        </li>")
        html.extend(["    </ul>"])

    # Form test sonuçları
    if data.get("form_test_results"):
        html.extend(["    <h2>Form Test Sonuçları</h2>", "    <ul>"])
        for form in data["form_test_results"]:
            html.append("        <li>")
            html.append(f"            <b>Yöntem:</b> {form.get('method', '').upper()}<br>")
            html.append(f"            <b>Action:</b> {form.get('action', '')}<br>")
            inputs = form.get("inputs", {})
            html.append("            <b>Inputlar:</b><ul>")
            if isinstance(inputs, dict):
                for name, typ in inputs.items():
                    html.append(f"                <li>{name} ({typ})</li>")
            elif isinstance(inputs, list):
                for inp in inputs:
                    if isinstance(inp, dict):
                        name = inp.get("name", "unknown")
                        typ = inp.get("type", "unknown")
                        html.append(f"                <li>{name} ({typ})</li>")
            html.append("            </ul>")
            if form.get("vulnerable"):
                html.append("            <b style='color:red;'>⚠️ Potansiyel açık tespit edildi!</b><br>")
            else:
                html.append("            <b style='color:green;'>Güvenli</b><br>")
            html.append("        </li>")
        html.extend(["    </ul>"])

    html.extend(["</body>", "</html>"])

    # Dosyayı kaydet
    try:
        with open(html_file, "w", encoding="utf-8") as f:
            f.write("\n".join(html))
        success(f"HTML raporu oluşturuldu: file://{os.path.abspath(html_file)}")
        return html_file
    except Exception as exc:
        error(f"HTML raporu kaydedilemedi: {exc}")
        raise