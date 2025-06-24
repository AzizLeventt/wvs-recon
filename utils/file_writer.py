import json
import os

def write_json_report(domain, subdomains, open_ports, found_dirs, vuln_endpoints=None, xss_results=None, filename="output/report.json"):
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        data = {
            "domain": domain,
            "subdomains": subdomains,
            "open_ports": open_ports,
            "found_dirs": found_dirs,
            "vuln_endpoints": vuln_endpoints or [],
            "xss_results": xss_results or []
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

        return True
    except Exception as e:
        print(f"[!] JSON yazma hatası: {e}")
        return False
