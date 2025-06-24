import requests

VULN_PATHS = [
    "/.env",
    "/phpinfo.php",
    "/server-status",
    "/adminer.php",
    "/debug",
    "/.git",
    "/config.php",
    "/.DS_Store",
    "/backup.zip",
    "/database.sql"
]

def check_vuln_endpoints(domain, timeout=5):
    if not domain.startswith("http"):
        domain = "http://" + domain

    found = []
    headers = {"User-Agent": "Mozilla/5.0"}

    for path in VULN_PATHS:
        url = f"{domain.rstrip('/')}{path}"
        try:
            res = requests.get(url, headers=headers, timeout=timeout)
            if res.status_code in [200, 301, 302, 403, 500]:
                found.append((url, res.status_code))
        except requests.RequestException:
            continue

    return found
