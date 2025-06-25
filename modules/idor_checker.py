# modules/idor_checker.py

import requests
from urllib.parse import urljoin
from utils.logger import info, success, error

requests.packages.urllib3.disable_warnings()


def test_idor(base_url: str) -> list:
    """
    Basit IDOR testi: yaygın kaynaklara yetkisiz erişim denenir.
    """
    test_paths = [
        "/admin", "/user/1", "/user/2", "/profile/1",
        "/profile?user=1", "/invoice/1", "/order/1",
        "/orders/1", "/api/user/1", "/api/profile/1",
        "/account?id=1", "/download?file=secret.pdf"
    ]

    found = []

    info("IDOR şüpheli URL'ler test ediliyor...")

    for path in test_paths:
        url = urljoin(base_url, path)
        try:
            resp = requests.get(url, timeout=10, verify=False)
            if resp.status_code == 200 and "unauthorized" not in resp.text.lower():
                success(f"IDOR şüphesi: {url} (HTTP {resp.status_code})")
                found.append((url, resp.status_code))
            elif resp.status_code in (401, 403):
                info(f"Yetkisiz erişim engellendi: {url} (HTTP {resp.status_code})")
        except Exception as e:
            error(f"İstek başarısız: {url} — {e}")

    return found
