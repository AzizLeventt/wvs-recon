import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def get_form_details(form):
    details = {
        "action": form.attrs.get("action", "").lower(),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": []
    }

    for input_tag in form.find_all("input"):
        details["inputs"].append({
            "type": input_tag.attrs.get("type", "text"),
            "name": input_tag.attrs.get("name")
        })

    return details

def scan_xss(url):
    payload = "<script>alert(1)</script>"
    vulnerable_forms = []

    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            form_details = get_form_details(form)
            data = {}

            for input_field in form_details["inputs"]:
                if input_field["name"]:
                    if input_field["type"] in ["text", "search", "email"]:
                        data[input_field["name"]] = payload
                    else:
                        data[input_field["name"]] = "test"
            #
            form_url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                response = requests.post(form_url, data=data, timeout=10)
            else:
                response = requests.get(form_url, params=data, timeout=10)

            if payload in response.text:
                vulnerable_forms.append(form_url)

    except Exception as e:
        print(f"[x] XSS tarama hatası: {e}")

    return vulnerable_forms
