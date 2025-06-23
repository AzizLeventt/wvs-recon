# main.py

from modules.subdomain_enum import get_subdomains_crtsh
from utils.logger import info, success, error
from colorama import Fore, Style
import sys

def main():
    try:
        target = input("Hedef domain: ").strip()
        target = target.replace("https://", "").replace("http://", "").strip("/")

        if not target:
            error("Lütfen geçerli bir domain gir.")
            sys.exit(1)

        info(f"Hedef alındı: {target}")
        subdomains = get_subdomains_crtsh(target)

        if subdomains:
            success(f"{len(subdomains)} subdomain bulundu:\n")
            for sub in subdomains:
                print(f"{Fore.YELLOW}- {sub}{Style.RESET_ALL}")
        else:
            error("Hiç subdomain bulunamadı.")

    except KeyboardInterrupt:
        error("Kullanıcı tarafından durduruldu.")
    except Exception as e:
        error(f"Beklenmeyen bir hata: {e}")

if __name__ == "__main__":
    main()
