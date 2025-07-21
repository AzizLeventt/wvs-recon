import requests
import urllib.parse
from utils.logger import info, success, error

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "/%5Cevil.com",
    "///evil.com"
]

def is_redirect_response(resp: requests.Response, payload: str) -> bool:
    """
    Yanıtta yönlendirme varsa ve hedef payload URL ise true döner.
    """
    if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get("Location", "")
        return payload in location
    return False

def test_open_redirect(action: str, method: str, data: dict, input_name: str, timeout: int = 10):
    """
    Belirli bir input alanında redirect payload testleri yapar.
    """
    for payload in REDIRECT_PAYLOADS:
        test_data = data.copy()
        test_data[input_name] = payload
        info(f"    [Redirect Test] {input_name} = {payload}")
        try:
            if method == "post":
                resp = requests.post(action, data=test_data, timeout=timeout, allow_redirects=False, verify=False)
            else:
                resp = requests.get(action, params=test_data, timeout=timeout, allow_redirects=False, verify=False)

            if is_redirect_response(resp, payload):
                success(f"    🚨 Open Redirect bulundu! Payload: {payload}")
                return {
                    "input": input_name,
                    "payload": payload,
                    "status": resp.status_code,
                    "location": resp.headers.get("Location", ""),
                    "response_snippet": resp.text[:1000]
                }

        except Exception as exc:
            error(f"    Redirect testi başarısız: {exc}")
    return None
#