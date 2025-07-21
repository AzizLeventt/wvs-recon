import argparse
import os
import socket
from datetime import datetime
from pathlib import Path

from colorama import Fore, Style

from modules.subdomain_enum import get_subdomains_crtsh
from modules.port_scan import run_port_scan

from modules.vuln_checker import check_vuln_endpoints
from modules.xss_scanner import scan_xss
from modules.form_scanner import scan_forms
from modules.form_tester import test_forms
from modules.idor_checker import test_idor

from modules.dir_enum import dir_enum, scan_admin_panels

from utils.input_analyzer import analyze_input  # param ayrımı & payload seçimi
from utils.logger import info, success, error
from utils.file_writer import write_json_report
from utils.html_report import generate_html_report

############################################################
# 1. Yardımcı işler
############################################################

def _print_dirs(results):
    for url, code in results:
        color = (
            Fore.GREEN if code == 200 else
            Fore.YELLOW if code in (301, 302) else
            Fore.MAGENTA
        )
        print(f"{color}- {url} ({code}){Style.RESET_ALL}")


def _scan_and_test_forms(target_url: str, verbose: bool):
    """Forms ➜ input ayrımı ➜ payload seçimi ➜ test gönderimi zinciri"""
    info(f"{target_url} için form taraması başlatılıyor...")
    forms = scan_forms(target_url)

    if not forms:
        info("Hiç form bulunamadı.")
        return [], []

    success(f"{len(forms)} form bulundu.")

    # Verileri, payload seçimiyle birlikte CLI'da göstermek için
    for idx, form in enumerate(forms, 1):
        print(f"\n  [{idx}] {form['method'].upper()} -> {form['action']}")
        for inp in form.get("inputs", []):
            name = inp.get("name", "unknown")
            itype = inp.get("type", "text")
            print(f"     - {name} ({itype})")
            if verbose:
                payloads = analyze_input(itype, name).get("payloads", [])[:2]
                print(f"       örnek payloadlar: {payloads}")

    # Ardından otomatik payload gönderimi & test
    test_results = test_forms(forms, target_url)
    for idx, res in enumerate(test_results, 1):
        if res.get("vulnerable"):
            print(f"{Fore.RED}     ⚠️ Form {idx}: Potansiyel açık tespit edildi!{Style.RESET_ALL}")
        elif verbose:
            print(f"     Form {idx}: sorun bulunamadı.")

    return forms, test_results

############################################################
# 2. Ana hedef tarama
############################################################

def scan_target(domain: str, args: argparse.Namespace):
    """Bir domain (veya subdomain) için modüler tarama akışı"""

    # 2.1 Temel temizlik & başlangıç
    domain = domain.replace("https://", "").replace("http://", "").strip("/")
    target_url = f"http://{domain}"
    start_ts = datetime.now()
    info(f"Hedef alındı: {domain}")

    # Çıktıları depolayacak yapılar
    subdomains = []
    open_ports = []
    found_dirs = []
    vuln_endpoints = []
    xss_results = []
    form_data = []
    form_test_results = []
    idor_results = []  # ⬅️ 2.1 Temel temizlik & başlangıç kısmına eklendi
    admin_panels = []
    try:
        ####################################################
        # 2.2 Subdomain Enum
        ####################################################
        if args.subdomain:
            subdomains = get_subdomains_crtsh(domain)
            if subdomains:
                success(f"{len(subdomains)} subdomain bulundu:")
                for s in subdomains:
                    print(f"{Fore.YELLOW}- {s}{Style.RESET_ALL}")
            else:
                info("Hiç subdomain bulunamadı.")

        ####################################################
        # 2.3 IP çözümleme (diğer taramalar öncesi tek noktada)
        ####################################################
        if any([args.ports, args.dirs, args.vuln, args.xss, args.form, args.formtest]):
            try:
                ip = socket.gethostbyname(domain)
                info(f"{domain} IP → {ip}")
            except Exception as exc:
                error(f"IP adresi alınamadı: {exc}")
                return
        else:
            ip = None  # kullanılmayacak

        ####################################################
        # 2.4 Port Scan
        ####################################################
        if args.ports and ip:
            info("Port taraması başlatılıyor…")
            open_ports = run_port_scan(ip)
            if open_ports:
                success(f"Açık portlar: {open_ports}")
            else:
                info("Açık port yok.")

        ####################################################
        # 2.5 Directory Enum
        ####################################################
        if args.dirs:
            wlist = (
                args.wordlist if args.wordlist and os.path.isfile(args.wordlist)
                else ("wordlists/quick.txt" if args.fast else "wordlists/common.txt")
            )
            try:
                with open(wlist, "r", encoding="utf-8") as fh:
                    words = fh.read().splitlines()
            except FileNotFoundError:
                error(f"Wordlist bulunamadı: {wlist}")
                words = []

            if words:
                info(f"Dizin taraması ({len(words)} kelime)…")
                dir_res = dir_enum(domain, words)
                if dir_res:
                    success("Açık dizinler bulundu:")
                    _print_dirs(dir_res)
                    found_dirs = [u for u, _ in dir_res]
                else:
                    info("Dizin bulunamadı.")

                # Admin panel taraması
                info("Admin panel taraması başlatılıyor...")
                admin_panels = scan_admin_panels(domain)
                if admin_panels:
                    success("Admin panel yolları bulundu:")
                    for url, status in admin_panels:
                        print(f"{Fore.CYAN}- {url} ({status}){Style.RESET_ALL}")
                else:
                    info("Admin panel bulunamadı.")

        ####################################################
        # 2.6 Vulnerability Endpoint Check
        ####################################################
        if args.vuln:
            info("Zafiyet endpoint taraması…")
            vuln_endpoints = check_vuln_endpoints(domain)
            if vuln_endpoints:
                success("Tehlikeli endpoint'ler:")
                for u, c in vuln_endpoints:
                    print(f"{Fore.RED}- {u} ({c}){Style.RESET_ALL}")
            else:
                info("Tehlikeli endpoint yok.")

        ####################################################
        # 2.7 XSS Scan
        ####################################################
        if args.xss:
            info("XSS taraması…")
            xss_results = scan_xss(target_url)
            if xss_results:
                success("XSS açıkları bulundu:")
                for u in xss_results:
                    print(f"{Fore.RED}- {u}{Style.RESET_ALL}")
            else:
                info("XSS açığı bulunamadı.")

        ####################################################
        # 2.8 Form ➜ Parametre ➜ Payload ➜ Test zinciri
        ####################################################
        if args.form or args.formtest:
            form_data, form_test_results = _scan_and_test_forms(target_url, args.verbose)

        ####################################################
        # 2.9 IDOR Testi
        ####################################################
        if args.formtest:
            info("IDOR testi başlatılıyor…")
            idor_results = test_idor(target_url)  # Sadece target_url parametresi veriyoruz
            if idor_results:
                success(f"{len(idor_results)} potansiyel IDOR zafiyeti tespit edildi.")
            else:
                info("IDOR zafiyeti bulunamadı.")

        ####################################################
        # 2.10 Raporlama
        ####################################################
        out_name = (
            args.output if args.output else f"{domain.replace('.', '_')}_report.json"
        )
        out_path = Path("wvs_web/output") / out_name

        success_flag = write_json_report(
            domain=domain,
            subdomains=subdomains,
            open_ports=open_ports,
            found_dirs=found_dirs,
            admin_panels=admin_panels,
            vuln_endpoints=vuln_endpoints,
            xss_results=xss_results,
            form_data=form_data,
            form_test_results=form_test_results,
            idor_results=idor_results,
            filename=str(out_path),
        )

        if success_flag:
            success(f"Tüm sonuçlar '{out_path}' dosyasına kaydedildi.")
            try:
                generate_html_report(str(out_path))
            except Exception as exc:
                error(f"HTML raporu oluşturulamadı: {exc}")

    except Exception as e:
        error(f"Hedef taraması sırasında hata oluştu: {e}")

    dur = datetime.now() - start_ts
    info(f"{domain} taraması tamamlandı (süre: {dur})")

############################################################
# 3. CLI
############################################################

def main():
    parser = argparse.ArgumentParser(
        description="WVS-Recon – Çoklu Hedef Güvenlik Tarayıcısı"
    )

    tgt_grp = parser.add_mutually_exclusive_group(required=True)
    tgt_grp.add_argument("--target", help="Tek hedef domain (örn: example.com)")
    tgt_grp.add_argument("--list", help="Dosyadan hedef listesi (örn: targets.txt)")

    parser.add_argument("--subdomain", action="store_true", help="Subdomain taraması")
    parser.add_argument("--ports", action="store_true", help="Port taraması")
    parser.add_argument("--dirs", action="store_true", help="Dizin taraması")
    parser.add_argument("--vuln", action="store_true", help="Zafiyet endpoint taraması")
    parser.add_argument("--xss", action="store_true", help="XSS taraması")
    parser.add_argument("--form", action="store_true", help="Form & input bul")
    parser.add_argument("--formtest", action="store_true", help="Formlara payload gönder & test et")
    parser.add_argument("--fast", action="store_true", help="Hızlı mod (küçük wordlist)")
    parser.add_argument("--wordlist", help="Özel wordlist yolu (yalnızca --dirs ile)")
    parser.add_argument("--output", help="Çıktı JSON adı (sadece --target ile)")
    parser.add_argument("--verbose", action="store_true", help="Detaylı payload/log çıktı")

    args = parser.parse_args()

    if args.target:
        scan_target(args.target, args)
    elif args.list:
        try:
            with open(args.list, "r", encoding="utf-8") as fh:
                targets = [t.strip() for t in fh if t.strip()]
            for dom in targets:
                scan_target(dom, args)
        except FileNotFoundError:
            error(f"Liste dosyası bulunamadı: {args.list}")
        except Exception as exc:
            error(f"Liste okunamadı: {exc}")


if __name__ == "__main__":
    main()
