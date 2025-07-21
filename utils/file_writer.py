import json
import os
from datetime import datetime


def save_vulnerability(vuln_data: dict, json_path: str = "wvs_web/output/output.json") -> None:
    if not os.path.exists(json_path):
        report = {"vulnerabilities": []}
    else:
        with open(json_path, "r", encoding="utf-8") as f:
            try:
                report = json.load(f)
            except json.JSONDecodeError:
                report = {"vulnerabilities": []}

    report.setdefault("vulnerabilities", []).append(vuln_data)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def increment_payload_stat(vuln_type: str, payload: str, stat_file="wvs_web/output/payload_stats.json"):
    from pathlib import Path

    Path("wvs_web/output").mkdir(exist_ok=True)

    try:
        with open(stat_file, "r", encoding="utf-8") as f:
            stats = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        stats = {}

    if vuln_type not in stats:
        stats[vuln_type] = {}

    if payload not in stats[vuln_type]:
        stats[vuln_type][payload] = 0

    stats[vuln_type][payload] += 1

    with open(stat_file, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)


def write_json_report(
    domain: str,
    subdomains: list,
    open_ports: list,
    found_dirs: list,
    vuln_endpoints: list,
    xss_results: list,
    form_data: list,
    form_test_results: list,
    idor_results: list,
    admin_panels: list,
    filename: str = None
) -> bool:
    if filename is None:
        safe_name = domain.replace(".", "_")
        filename = f"wvs_web/output/{safe_name}_report.json"

    report = {
        "domain": domain,
        "subdomains": subdomains,
        "open_ports": open_ports,
        "found_dirs": found_dirs,
        "vuln_endpoints": vuln_endpoints,
        "vulnerabilities": xss_results,
        "form_data": form_data,
        "form_test_results": form_test_results,
        "idor_results": idor_results,
        "admin_panels": admin_panels
    }
    #
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        # ✨ HTML raporu da oluştur
        html_path = filename.replace(".json", ".html")
        generate_html_report(json_path=filename, html_path=html_path)

        return True
    except Exception as e:
        print(f"[!] JSON raporu yazılırken hata oluştu: {e}")
        return False



def generate_html_report(json_path: str = "wvs_web/output/output.json", html_path: str = None) -> None:
    if not os.path.exists(json_path):
        print("[!] output.json bulunamadı.")
        return

    with open(json_path, "r", encoding="utf-8") as f:
        try:
            report = json.load(f)
        except json.JSONDecodeError:
            print("[!] JSON dosyası okunamadı.")
            return

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    domain = report.get("domain", "?")

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>WVS-Recon Raporu</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ margin-top: 30px; }}
        ul {{ padding-left: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 8px; border: 1px solid #ccc; }}
        th {{ background: #222; color: #fff; }}
        tr:nth-child(even) {{ background: #eee; }}
        code {{ background: #eee; padding: 2px 4px; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>WVS-Recon Güvenlik Raporu</h1>
    <p><strong>Hedef:</strong> {domain}</p>
    <p><strong>Oluşturulma Zamanı:</strong> {now}</p>
"""

    def render_list(title, items):
        if not items:
            return f"<h2>{title}</h2><p>Bulunamadı.</p>"
        lis = "".join([f"<li>{i}</li>" for i in items])
        return f"<h2>{title}</h2><ul>{lis}</ul>"

    html += render_list("Subdomainler", report.get("subdomains", []))
    html += render_list("Açık Portlar", report.get("open_ports", []))
    html += render_list("Açık Dizinler", report.get("found_dirs", []))
    html += render_list("Admin Panelleri", [f"{u} ({s})" for u, s in report.get("admin_panels", [])])
    html += render_list("Zafiyet Endpoint'leri", [f"{u} ({s})" for u, s in report.get("vuln_endpoints", [])])
    html += render_list("XSS Sonuçları", report.get("vulnerabilities", []))
    html += render_list("IDOR Sonuçları", [json.dumps(i) for i in report.get("idor_results", [])])

    form_tests = report.get("form_test_results", [])
    if form_tests:
        html += "<h2>Form Test Sonuçları</h2><table><tr><th>Input</th><th>Payload</th><th>Status</th></tr>"
        for f in form_tests:
            html += f"<tr><td>{f.get('input')}</td><td><code>{f.get('payload')}</code></td><td>{f.get('status')}</td></tr>"
        html += "</table>"
    else:
        html += "<h2>Form Test Sonuçları</h2><p>Bulunamadı.</p>"

    html += "</body></html>"

    if html_path is None:
        html_path = "wvs_web/output/report.html"

    os.makedirs(os.path.dirname(html_path), exist_ok=True)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] HTML rapor oluşturuldu: {html_path}")


def initialize_report():
    os.makedirs("wvs_web/output", exist_ok=True)
    if not os.path.exists("wvs_web/output/output.json"):
        with open("wvs_web/output/output.json", "w", encoding="utf-8") as f:
            json.dump({"vulnerabilities": []}, f, indent=2, ensure_ascii=False)
