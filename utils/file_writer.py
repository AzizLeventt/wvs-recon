import json
import os

def write_json_report(domain, subdomains, open_ports, found_dirs,
                      vuln_endpoints=None, xss_results=None,
                      form_data=None, form_test_results=None,
                      filename="output/report.json"):
    try:
        # output klasörü yoksa oluştur
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        data = {
            "domain": domain,
            "subdomains": subdomains or [],
            "open_ports": open_ports or [],
            "found_dirs": found_dirs or [],
            "vuln_endpoints": vuln_endpoints or [],
            "xss_results": xss_results or [],
            "form_data": form_data or [],
            "form_test_results": form_test_results or []
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

        return True
    except Exception as e:
        print(f"[!] JSON yazma hatası: {e}")
        return False
