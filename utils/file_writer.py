import json
import os
from datetime import datetime

def save_vulnerability(vuln_data: dict, json_path: str = "reports/output.json") -> None:
    """
    Yeni bir vulnerability bulgusu varsa JSON rapor dosyasına ekler.
    """
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


def increment_payload_stat(vuln_type: str, payload: str, stat_file="output/payload_stats.json"):
    import json
    from pathlib import Path

    Path("output").mkdir(exist_ok=True)

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




def generate_html_report(json_path: str = "reports/output.json", html_path: str = "reports/report.html") -> None:
    """
    JSON'daki XSS bulgularını alır ve HTML rapor çıktısı oluşturur.
    """
    if not os.path.exists(json_path):
        print("[!] output.json bulunamadı.")
        return

    with open(json_path, "r", encoding="utf-8") as f:
        try:
            report = json.load(f)
        except json.JSONDecodeError:
            print("[!] JSON dosyası okunamadı.")
            return

    vulnerabilities = report.get("vulnerabilities", [])
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>WVS-Recon Raporu</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }}
        h1 {{ color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 10px; border: 1px solid #ccc; }}
        th {{ background: #222; color: #fff; }}
        tr:nth-child(even) {{ background: #eee; }}
        code {{ background: #eee; padding: 2px 4px; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>WVS-Recon Zafiyet Raporu</h1>
    <p>Oluşturulma zamanı: <strong>{now}</strong></p>
    <h2>Bulunan Zafiyetler</h2>
    <table>
        <tr>
            <th>Tür</th>
            <th>Input</th>
            <th>Payload</th>
            <th>Status</th>
            <th>Metot</th>
            <th>Action</th>
        </tr>"""

    for vuln in vulnerabilities:
        html += f"""
        <tr>
            <td>{vuln.get("type", "?" )}</td>
            <td>{vuln.get("input", "?")}</td>
            <td><code>{vuln.get("payload", "")}</code></td>
            <td>{vuln.get("status", "-")}</td>
            <td>{vuln.get("method", "-").upper()}</td>
            <td>{vuln.get("action", "")}</td>
        </tr>"""

    html += """
    </table>
</body>
</html>
"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] HTML rapor oluşturuldu: {html_path}")
def write_json_report(
    domain: str,
    subdomains: list,
    open_ports: list,
    found_dirs: list,
    vuln_endpoints: list,
    xss_results: list,
    form_data: list,
    form_test_results: list,
    idor_results: list,  # ⬅️ yeni eklendi
    admin_panels: list,  # ⬅️ yeni eklendi
    filename: str = "output/report.json"
) -> bool:
    """
    Tüm tarama sonuçlarını JSON formatında tek dosyaya yazar.
    """
    report = {
        "domain": domain,
        "subdomains": subdomains,
        "open_ports": open_ports,
        "found_dirs": found_dirs,
        "vuln_endpoints": vuln_endpoints,
        "vulnerabilities": xss_results,
        "form_data": form_data,
        "form_test_results": form_test_results,
        "idor_results": idor_results,  # ⬅️ eklendi
        "admin_panels": admin_panels  # ⬅️ eklendi
    }

    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[!] JSON raporu yazılırken hata oluştu: {e}")
        return False
