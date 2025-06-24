import requests

def dir_enum(domain, wordlist, timeout=3):
    found_dirs = []

    if not domain.startswith("http"):
        domain = "http://" + domain

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    for word in wordlist:
        url = f"{domain.rstrip('/')}/{word.strip()}"
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            if response.status_code in [200, 301, 302, 403]:
                found_dirs.append((url, response.status_code))
        except requests.RequestException:
            pass

    return found_dirs
