from colorama import Fore, Style, init

init(autoreset=True)

def info(msg):
    print(f"{Fore.CYAN}[i]{Style.RESET_ALL} {msg}")

def success(msg):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

def warning(msg):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

def error(msg):
    print(f"{Fore.RED}[x]{Style.RESET_ALL} {msg}")
