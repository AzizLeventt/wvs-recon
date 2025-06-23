import requests

def get_subdomains_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            print(f"[!] HTTP {response.status_code} hatası")
            return []

        try:
            entries = response.json()
        except Exception as parse_err:
            print(f"[!] JSON ayrıştırma hatası: {parse_err}")
            return []

        subdomains = set()
        for entry in entries:
            name_value = entry.get("name_value")
            if name_value:
                for sub in name_value.split("\n"):
                    if domain in sub:
                        subdomains.add(sub.strip())

        return list(subdomains)

    except Exception as e:
        print(f"[!] İstek sırasında hata oluştu: {e}")
        return []
