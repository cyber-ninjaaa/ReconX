"""Terminal display helpers — colored output, section headers, tables."""

from colorama import Fore, Style, init

init(autoreset=True)

# ── Palette ──────────────────────────────────────────────────────────────────
R  = Fore.RED
G  = Fore.GREEN
Y  = Fore.YELLOW
B  = Fore.BLUE
C  = Fore.CYAN
M  = Fore.MAGENTA
W  = Fore.WHITE
DIM = Style.DIM
BOLD = Style.BRIGHT
RESET = Style.RESET_ALL


def banner():
    print(f"""{C}{BOLD}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ 
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ 
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
{RESET}{DIM}  Automated Reconnaissance Framework  v1.0  by Amine Bououd
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
""")


def section(title: str):
    width = 54
    print(f"\n{C}{BOLD}  ┌{'─' * width}┐")
    print(f"  │  {Y}{BOLD}{title:<{width - 2}}{C}│")
    print(f"  └{'─' * width}┘{RESET}")


def info(msg: str):
    print(f"  {C}[{W}*{C}]{RESET} {msg}")


def success(msg: str):
    print(f"  {G}[{W}+{G}]{RESET} {msg}")


def warn(msg: str):
    print(f"  {Y}[{W}!{Y}]{RESET} {msg}")


def error(msg: str):
    print(f"  {R}[{W}✗{R}]{RESET} {msg}")


def result(label: str, value: str):
    print(f"  {DIM}{label:<22}{RESET}{W}{value}{RESET}")


def found(value: str):
    print(f"  {G}  ↳ {value}{RESET}")


def summary_table(title: str, rows: list[tuple]):
    section(title)
    for label, value in rows:
        result(label, str(value))


def divider():
    print(f"  {DIM}{'─' * 56}{RESET}")
