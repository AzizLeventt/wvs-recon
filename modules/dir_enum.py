import requests

def dir_enum(domain, wordlist, timeout=3):
    found_dirs = []

    if not domain.startswith("http"):
        domain = "http://" + domain

    headers = {
        "User-Agent": "Mozilla/5.0"
    }
#
    for word in wordlist:
        url = f"{domain.rstrip('/')}/{word.strip()}"
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            if response.status_code in [200, 301, 302, 403]:
                found_dirs.append((url, response.status_code))
        except requests.RequestException:
            pass

    return found_dirs

# ✅ Admin panel tarayıcı
def scan_admin_panels(domain, timeout=3):
    found_admins = []

    if not domain.startswith("http"):
        domain = "http://" + domain

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    admin_paths = [
        "admin", "admin/login", "adminpanel", "cpanel", "administrator",
        "admin1", "admin2", "login", "admin-area", "cms", "backend", "controlpanel"
    ]

    for path in admin_paths:
        url = f"{domain.rstrip('/')}/{path}"
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            if response.status_code in [200, 301, 302, 403]:
                found_admins.append((url, response.status_code))
        except requests.RequestException:
            pass

    return found_admins
