from colorama import Fore, Style, init
import os
from datetime import datetime

init(autoreset=True)

LOG_PATH = "output/logs/scan.log"
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

def write_to_log(message):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"{timestamp} {message}\n")

def info(msg):
    print(f"{Fore.CYAN}[i]{Style.RESET_ALL} {msg}")
    write_to_log(f"[i] {msg}")

def success(msg):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
    write_to_log(f"[+] {msg}")

def warning(msg):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
    write_to_log(f"[!] {msg}")

def error(msg):
    print(f"{Fore.RED}[x]{Style.RESET_ALL} {msg}")
    write_to_log(f"[x] {msg}")
