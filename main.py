# main.py

import argparse
import socket
import sys
from datetime import datetime
from modules.subdomain_enum import get_subdomains_crtsh
from modules.port_scan import run_port_scan
from modules.dir_enum import dir_enum
from modules.vuln_checker import check_vuln_endpoints
from utils.logger import info, success, error
from utils.file_writer import write_json_report
from utils.html_report import generate_html_report
from colorama import Fore, Style
import os

def scan_target(target, args):
    target = target.replace("https://", "").replace("http://", "").strip("/")
    start_time = datetime.now()
    info(f"Hedef alındı: {target}")

    subdomains = []
    open_ports = []
    found_dirs = []
    vuln_results = []

    try:
        if args.subdomain:
            subdomains = get_subdomains_crtsh(target)
            if subdomains:
                success(f"{len(subdomains)} subdomain bulundu:")
                for s in subdomains:
                    print(f"{Fore.YELLOW}- {s}{Style.RESET_ALL}")
            else:
                info("Hiç subdomain bulunamadı.")

        if args.ports or args.dirs or args.vuln:
            try:
                ip = socket.gethostbyname(target)
                info(f"{target} domaininin IP adresi: {ip}")
            except Exception as e:
                error(f"IP adresi alınamadı: {e}")
                return

        if args.ports:
            info(f"{ip} için port taraması başlatılıyor...")
            open_ports = run_port_scan(ip)
            if open_ports:
                success(f"Açık portlar: {open_ports}")
            else:
                info("Açık port bulunamadı.")

        if args.dirs:
            try:
                wordlist_path = "wordlists/quick.txt" if args.fast else "wordlists/common.txt"
                with open(wordlist_path, "r", encoding="utf-8") as f:
                    words = f.read().splitlines()
            except FileNotFoundError:
                error(f"Wordlist dosyası bulunamadı: {wordlist_path}")
                words = []

            if words:
                info(f"{target} için dizin taraması başlatılıyor...")
                results = dir_enum(target, words)
                if results:
                    success("Açık dizinler bulundu:")
                    for url, code in results:
                        color = Fore.GREEN if code == 200 else (
                            Fore.YELLOW if code in [301, 302] else Fore.MAGENTA
                        )
                        print(f"{color}- {url} ({code}){Style.RESET_ALL}")
                    found_dirs = [url for url, _ in results]
                else:
                    info("Hiçbir dizin bulunamadı.")

        if args.vuln:
            info(f"{target} için zafiyet endpoint taraması başlatılıyor...")
            vuln_results = check_vuln_endpoints(target)
            if vuln_results:
                success("Potansiyel tehlikeli endpoint'ler bulundu:")
                for url, code in vuln_results:
                    print(f"{Fore.RED}- {url} ({code}){Style.RESET_ALL}")
            else:
                info("Tehlikeli endpoint bulunamadı.")

        output_name = args.output if args.output else f"{target.replace('.', '_')}_report.json"
        output_path = os.path.join("output", output_name)

        if write_json_report(
            domain=target,
            subdomains=subdomains,
            open_ports=open_ports,
            found_dirs=found_dirs,
            vuln_endpoints=vuln_results,
            filename=output_path
        ):
            success(f"Tüm sonuçlar '{output_path}' dosyasına kaydedildi.")

            # ✅ Otomatik HTML raporu oluştur
            try:
                generate_html_report(output_path)
            except Exception as e:
                error(f"HTML raporu oluşturulamadı: {e}")
        else:
            error("Sonuçlar kaydedilemedi.")

    except Exception as e:
        error(f"Beklenmeyen bir hata: {e}")

    duration = datetime.now() - start_time
    info(f"{target} için tarama süresi: {duration}")

def main():
    parser = argparse.ArgumentParser(description="WVS-Recon - Çoklu Hedef CLI Aracı")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", help="Tek hedef domain (örn: example.com)")
    group.add_argument("--list", help="Hedef domain listesi (örn: targets.txt)")
    parser.add_argument("--subdomain", action="store_true", help="Subdomain taraması yap")
    parser.add_argument("--ports", action="store_true", help="Port taraması yap")
    parser.add_argument("--dirs", action="store_true", help="Dizin taraması yap")
    parser.add_argument("--vuln", action="store_true", help="Zafiyet endpoint taraması yap")
    parser.add_argument("--fast", action="store_true", help="Hızlı tarama modunu etkinleştir")
    parser.add_argument("--output", help="Çıktı JSON dosya adı (sadece --target ile birlikte)")
    args = parser.parse_args()

    if args.target:
        scan_target(args.target, args)
    elif args.list:
        try:
            with open(args.list, "r", encoding="utf-8") as f:
                targets = [line.strip() for line in f if line.strip()]
            for target in targets:
                scan_target(target, args)
        except FileNotFoundError:
            error(f"Liste dosyası bulunamadı: {args.list}")
        except Exception as e:
            error(f"Liste okunamadı: {e}")

if __name__ == "__main__":
    main()
