import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def analyze_forms(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        #
        results = []
        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").upper()
            inputs = []
            for input_tag in form.find_all("input"):
                input_type = input_tag.get("type", "text")
                input_name = input_tag.get("name")
                inputs.append({
                    "type": input_type,
                    "name": input_name
                })
            full_action = urljoin(url, action) if action else url
            results.append({
                "action": full_action,
                "method": method,
                "inputs": inputs
            })
        return results
    except Exception as e:
        print(f"[!] Form analizi hatası: {e}")
        return []
