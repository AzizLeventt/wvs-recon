import json
import os
from pathlib import Path
from utils.logger import success, error


def generate_html_report(json_file: str) -> str:
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        error(f"JSON raporu okunamadı: {exc}")
        raise

    html_file = os.path.join(
        os.path.dirname(json_file),
        f"{Path(json_file).stem}.html",
    )

    domain = data.get("domain", "")
    html = [
        "<!DOCTYPE html>",
        "<html lang=\"tr\">",
        "<head>",
        "    <meta charset='UTF-8'>",
        f"    <title>WVS-Recon Raporu - {domain}</title>",
        "    <style>",
        "        body { font-family: Arial, sans-serif; padding: 20px; background: #f8f8f8; }",
        "        h1 { color: #4a148c; }",
        "        h2 { color: #6a1b9a; }",
        "        ul { list-style-type: none; padding-left: 0; }",
        "        li { margin-bottom: 8px; }",
        "        .code { font-family: monospace; background: #eee; padding: 2px 6px; border-radius: 4px; }",
        "        .vuln { background: #fff; border-left: 4px solid red; padding: 10px; margin-bottom: 10px; }",
        "    </style>",
        "</head>",
        "<body>",
        "    <h1>WVS-Recon Güvenlik Raporu</h1>",
        f"    <p><strong>Hedef:</strong> {domain}</p>",
    ]

    def add_list_section(title: str, items):
        if items:
            html.extend([f"<h2>{title}</h2>", "<ul>"])
            for item in items:
                if isinstance(item, tuple):
                    url, code = item
                    html.append(f"<li>{url} <span class='code'>({code})</span></li>")
                else:
                    html.append(f"<li>{item}</li>")
            html.append("</ul>")

    add_list_section("Subdomain'ler", data.get("subdomains", []))
    add_list_section("Açık Portlar", data.get("open_ports", []))
    add_list_section("Açık Dizinler", data.get("found_dirs", []))
    add_list_section("Zafiyet Endpoint'leri", data.get("vuln_endpoints", []))

    # 🔐 Zafiyet Detayları: XSS, SQLi, Redirect, CSRF
    vulns = data.get("vulnerabilities", [])
    xss_vulns = [v for v in vulns if v.get("type") == "XSS"]
    sqli_vulns = [v for v in vulns if v.get("type") == "SQLi"]
    redirect_vulns = [v for v in vulns if v.get("type") == "OpenRedirect"]
    csrf_vulns = [v for v in vulns if v.get("type") == "CSRF"]

    def add_vuln_section(title: str, vulns: list):
        if vulns:
            html.append(f"<h2>{title}</h2>")
            for v in vulns:
                html.append("<div class='vuln'>")
                html.append(f"<b>ID:</b> {v.get('id', '-')}&nbsp;&nbsp;&nbsp;<b>Input:</b> {v.get('input', '-')}")
                html.append(f"<br><b>Payload:</b> <code>{v.get('payload', '-')}</code>")
                html.append(f"<br><b>Yöntem:</b> {v.get('method', '').upper()}")
                html.append(f"<br><b>Action:</b> {v.get('action', '-')}")
                html.append(f"<br><b>Status:</b> {v.get('status', '-')}")
                snippet = v.get("response_snippet", "")
                html.append(f"<details><summary>Yanıt Snippet</summary><pre>{snippet[:1000]}</pre></details>")
                html.append("</div>")

    add_vuln_section("XSS Açıkları", xss_vulns)
    add_vuln_section("SQLi Açıkları", sqli_vulns)
    add_vuln_section("Open Redirect Açıkları", redirect_vulns)
    add_vuln_section("CSRF Açıkları", csrf_vulns)

    # Formlar
    if data.get("form_data"):
        html.extend(["<h2>Formlar</h2>", "<ul>"])
        for form in data["form_data"]:
            html.append("<li>")
            html.append(f"<b>Yöntem:</b> {form.get('method', '').upper()}<br>")
            html.append(f"<b>Action:</b> {form.get('action', '')}<br>")
            inputs = form.get("inputs", {})
            html.append("<b>Inputlar:</b><ul>")
            if isinstance(inputs, dict):
                for name, typ in inputs.items():
                    html.append(f"<li>{name} ({typ})</li>")
            elif isinstance(inputs, list):
                for inp in inputs:
                    if isinstance(inp, dict):
                        html.append(f"<li>{inp.get('name', 'unknown')} ({inp.get('type', 'text')})</li>")
            html.append("</ul></li>")
        html.append("</ul>")

    # Form test sonuçları
    if data.get("form_test_results"):
        html.extend(["<h2>Form Test Sonuçları</h2>", "<ul>"])
        for form in data["form_test_results"]:
            html.append("<li>")
            html.append(f"<b>Yöntem:</b> {form.get('method', '').upper()}<br>")
            html.append(f"<b>Action:</b> {form.get('action', '')}<br>")
            inputs = form.get("inputs", {})
            html.append("<b>Inputlar:</b><ul>")
            if isinstance(inputs, dict):
                for name, typ in inputs.items():
                    html.append(f"<li>{name} ({typ})</li>")
            elif isinstance(inputs, list):
                for inp in inputs:
                    if isinstance(inp, dict):
                        html.append(f"<li>{inp.get('name', 'unknown')} ({inp.get('type', 'text')})</li>")
            html.append("</ul>")
            if form.get("vulnerable"):
                html.append(f"<b style='color:red;'>⚠️ Potansiyel açık tespit edildi!</b><br>")
            else:
                html.append("<b style='color:green;'>Güvenli</b><br>")
            html.append("</li>")
        html.append("</ul>")

    # IDOR sonuçları
    if data.get("idor_results"):
        html.extend(["<h2>IDOR Zafiyetleri</h2>", "<ul>"])
        for item in data["idor_results"]:
            html.append("<li>")
            html.append(f"<b>🛂 URL:</b> {item.get('url', '')}<br>")
            html.append(f"<b>Parametre:</b> {item.get('param', '')}<br>")
            html.append(f"<b>Açıklama:</b> {item.get('description', '')}<br>")
            html.append("</li>")
        html.append("</ul>")



    html.extend(["</body>", "</html>"])

    try:
        with open(html_file, "w", encoding="utf-8") as f:
            f.write("\n".join(html))
        success(f"HTML raporu oluşturuldu: file://{os.path.abspath(html_file)}")
        return html_file
    except Exception as exc:
        error(f"HTML raporu kaydedilemedi: {exc}")
        raise