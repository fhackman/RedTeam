#!/usr/bin/env python3
"""
Red Team Tools - Professional Auto-Installer (Linux/Kali Edition)
Automatically detects and installs missing packages with progress indicators
For educational and authorized security testing only
"""

import subprocess
import sys
import os
import shutil
import time
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# ANSI colors
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

C = Colors

# Package requirements
CORE_PACKAGES = [
    ("colorama", ">=0.4.6"),
    ("pyfiglet", ">=0.8.0"),
    ("rich", ">=13.0.0"),
    ("requests", ">=2.28.0"),
]

NETWORK_PACKAGES = [
    ("scapy", ">=2.5.0"),
    ("python-nmap", ">=0.7.1"),
    ("paramiko", ">=3.0.0"),
    ("netifaces", ">=0.11.0"),
    ("netaddr", ">=0.8.0"),
    ("dnspython", ">=2.3.0"),
    ("impacket", ">=0.10.0"),
]

WEB_PACKAGES = [
    ("beautifulsoup4", ">=4.11.0"),
    ("selenium", ">=4.8.0"),
    ("lxml", ">=4.9.0"),
    ("fake-useragent", ">=1.1.0"),
]

SYSTEM_PACKAGES = [
    ("psutil", ">=5.9.0"),
    ("pycryptodome", ">=3.17.0"),
    ("pynput", ">=1.7.6"),
    ("python-xlib", ">=0.33"),
]

CRYPTO_PACKAGES = [
    ("cryptography", ">=39.0.0"),
    ("Pillow", ">=9.4.0"),
]

OSINT_PACKAGES = [
    ("python-whois", ">=0.8.0"),
    ("exifread", ">=3.0.0"),
    ("PyPDF2", ">=3.0.0"),
]

FORENSICS_PACKAGES = [
    ("python-magic", ">=0.4.27"),
]

WIRELESS_PACKAGES = [
    ("wifi", ">=0.3.8"),
]

# Linux system packages (apt)
SYSTEM_DEPS = [
    "nmap",
    "hashcat",
    "john",
    "hydra",
    "sqlmap",
    "nikto",
    "gobuster",
    "dirb",
    "wfuzz",
    "aircrack-ng",
    "reaver",
    "bettercap",
    "ettercap-text-only",
    "macchanger",
    "netcat-openbsd",
    "tcpdump",
    "wireshark-cli",
    "masscan",
    "enum4linux",
    "smbclient",
    "nbtscan",
    "onesixtyone",
    "snmpwalk",
    "dnsrecon",
    "dnsenum",
    "fierce",
    "whois",
    "theharvester",
    "recon-ng",
    "sublist3r",
    "wpscan",
    "whatweb",
    "wafw00f",
    "commix",
    "xsser",
    "msfconsole",
    "exploitdb",
    "wordlists",
    "seclists",
]

# External tools info
EXTERNAL_TOOLS = {
    "nmap": {"desc": "Network mapper", "pkg": "nmap"},
    "hashcat": {"desc": "Password recovery", "pkg": "hashcat"},
    "john": {"desc": "John the Ripper", "pkg": "john"},
    "hydra": {"desc": "Login cracker", "pkg": "hydra"},
    "sqlmap": {"desc": "SQL injection", "pkg": "sqlmap"},
    "nikto": {"desc": "Web scanner", "pkg": "nikto"},
    "gobuster": {"desc": "Directory buster", "pkg": "gobuster"},
    "aircrack-ng": {"desc": "WiFi security", "pkg": "aircrack-ng"},
    "bettercap": {"desc": "Network attack", "pkg": "bettercap"},
    "masscan": {"desc": "Port scanner", "pkg": "masscan"},
    "wpscan": {"desc": "WordPress scanner", "pkg": "wpscan"},
    "msfconsole": {"desc": "Metasploit", "pkg": "metasploit-framework"},
    "recon-ng": {"desc": "Recon framework", "pkg": "recon-ng"},
    "theharvester": {"desc": "OSINT tool", "pkg": "theharvester"},
    "enum4linux": {"desc": "SMB enumeration", "pkg": "enum4linux"},
}


def print_banner():
    """Display installer banner"""
    banner = f"""
{C.RED}██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗     ███████╗██████╗ 
██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║     ██╔════╝██╔══██╗
██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║     █████╗  ██████╔╝
██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║     ██╔══╝  ██╔══██╗
██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗███████╗██║  ██║
╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝{C.RESET}
    
    {C.CYAN}Red Team Tools - Linux/Kali Installer{C.RESET}
    {C.YELLOW}Platform: Linux (Kali/Debian/Ubuntu){C.RESET}
"""
    print(banner)


def print_status(msg: str, status: str = "info"):
    icons = {"success": f"{C.GREEN}[+]{C.RESET}", "error": f"{C.RED}[-]{C.RESET}",
             "warning": f"{C.YELLOW}[!]{C.RESET}", "info": f"{C.BLUE}[*]{C.RESET}"}
    print(f"{icons.get(status, icons['info'])} {msg}")


def progress_bar(current: int, total: int, prefix: str = "", length: int = 40):
    percent = (current / total) * 100 if total > 0 else 100
    filled = int(length * current // max(total, 1))
    bar = f"{C.GREEN}{'█' * filled}{C.RESET}{'░' * (length - filled)}"
    print(f"\r{prefix} |{bar}| {percent:.1f}%", end="", flush=True)
    if current >= total:
        print()


def is_root() -> bool:
    """Check if running as root"""
    return os.geteuid() == 0


def check_package_installed(package_name: str) -> bool:
    """Check if a Python package is installed"""
    import_mappings = {
        "beautifulsoup4": "bs4", "python-nmap": "nmap", "pycryptodome": "Crypto",
        "python-whois": "whois", "fake-useragent": "fake_useragent",
        "python-magic": "magic", "python-xlib": "Xlib", "pypdf2": "PyPDF2",
        "dnspython": "dns",
    }
    import_name = import_mappings.get(package_name.lower(), package_name.replace("-", "_").lower())
    try:
        __import__(import_name)
        return True
    except ImportError:
        return False


def install_package(package_name: str, version: str = "") -> Tuple[bool, str]:
    """Install a Python package using pip"""
    package_spec = f"{package_name}{version}" if version else package_name
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", package_spec, "--quiet", "--break-system-packages"],
            capture_output=True, text=True, timeout=120
        )
        return (True, "OK") if result.returncode == 0 else (False, result.stderr.strip()[:50])
    except Exception as e:
        return False, str(e)[:50]


def check_system_tool(tool: str) -> bool:
    """Check if system tool is installed"""
    return shutil.which(tool) is not None


def install_system_packages(packages: List[str]):
    """Install system packages via apt"""
    if not is_root():
        print_status("Root required for system packages. Run with sudo.", "warning")
        return
    
    print_status("Updating package lists...", "info")
    subprocess.run(["apt", "update", "-qq"], capture_output=True)
    
    missing = [pkg for pkg in packages if not check_system_tool(pkg.split()[0])]
    
    if not missing:
        print_status("All system packages already installed!", "success")
        return
    
    print_status(f"Installing {len(missing)} system packages...", "info")
    
    for i, pkg in enumerate(missing):
        progress_bar(i, len(missing), f"  Installing {pkg[:20]}")
        result = subprocess.run(
            ["apt", "install", "-y", "-qq", pkg],
            capture_output=True, text=True
        )
    
    progress_bar(len(missing), len(missing), "  Complete")
    print_status("System packages installed!", "success")


def install_packages(packages: List[Tuple[str, str]], category: str) -> Dict[str, bool]:
    """Install Python packages"""
    print(f"\n{C.CYAN}{C.BOLD}Installing {category} packages...{C.RESET}")
    
    results = {}
    missing = [(pkg, ver) for pkg, ver in packages if not check_package_installed(pkg)]
    
    if not missing:
        print_status(f"All {category} packages installed!", "success")
        return {pkg: True for pkg, _ in packages}
    
    for i, (pkg, ver) in enumerate(missing):
        progress_bar(i, len(missing), f"  {pkg[:15]}")
        success, msg = install_package(pkg, ver)
        results[pkg] = success
        if not success:
            print(f"\n    {C.RED}Failed: {msg}{C.RESET}")
    
    progress_bar(len(missing), len(missing), "  Complete")
    return results


def check_all_packages():
    """Check status of all packages"""
    print(f"\n{C.CYAN}{C.BOLD}Package Status{C.RESET}")
    print(f"{C.CYAN}{'─' * 50}{C.RESET}")
    
    all_pkgs = {
        "Core": CORE_PACKAGES, "Network": NETWORK_PACKAGES, "Web": WEB_PACKAGES,
        "System": SYSTEM_PACKAGES, "Crypto": CRYPTO_PACKAGES, "OSINT": OSINT_PACKAGES,
        "Forensics": FORENSICS_PACKAGES, "Wireless": WIRELESS_PACKAGES,
    }
    
    for category, packages in all_pkgs.items():
        print(f"\n{C.YELLOW}[{category}]{C.RESET}")
        for pkg, ver in packages:
            icon = f"{C.GREEN}✓{C.RESET}" if check_package_installed(pkg) else f"{C.RED}✗{C.RESET}"
            print(f"  {icon} {pkg}")


def check_external_tools():
    """Check external tools"""
    print(f"\n{C.CYAN}{C.BOLD}External Tools{C.RESET}")
    print(f"{C.CYAN}{'─' * 50}{C.RESET}\n")
    
    for tool, info in EXTERNAL_TOOLS.items():
        installed = check_system_tool(tool)
        icon = f"{C.GREEN}✓{C.RESET}" if installed else f"{C.RED}✗{C.RESET}"
        print(f"  {icon} {tool:<15} - {info['desc']}")
        if not installed:
            print(f"      {C.YELLOW}Install: sudo apt install {info['pkg']}{C.RESET}")


def install_all():
    """Install everything"""
    upgrade_pip()
    
    for cat, pkgs in [("Core", CORE_PACKAGES), ("Network", NETWORK_PACKAGES),
                       ("Web", WEB_PACKAGES), ("System", SYSTEM_PACKAGES),
                       ("Crypto", CRYPTO_PACKAGES), ("OSINT", OSINT_PACKAGES),
                       ("Forensics", FORENSICS_PACKAGES), ("Wireless", WIRELESS_PACKAGES)]:
        install_packages(pkgs, cat)


def upgrade_pip():
    """Upgrade pip"""
    print(f"\n{C.CYAN}Upgrading pip...{C.RESET}")
    subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip", "--quiet", "--break-system-packages"],
                   capture_output=True)
    print_status("pip upgraded", "success")


def setup_wordlists():
    """Setup wordlists directory with links to system wordlists"""
    script_dir = Path(__file__).parent
    wordlists_dir = script_dir / "wordlists"
    wordlists_dir.mkdir(exist_ok=True)
    
    # Common Kali wordlist locations
    kali_wordlists = [
        ("/usr/share/wordlists/rockyou.txt", "rockyou.txt"),
        ("/usr/share/wordlists/rockyou.txt.gz", "rockyou.txt.gz"),
        ("/usr/share/seclists", "seclists"),
        ("/usr/share/wordlists/dirb", "dirb"),
        ("/usr/share/wordlists/dirbuster", "dirbuster"),
        ("/usr/share/wordlists/wfuzz", "wfuzz"),
    ]
    
    print(f"\n{C.CYAN}Setting up wordlists...{C.RESET}")
    
    for src, name in kali_wordlists:
        src_path = Path(src)
        dest = wordlists_dir / name
        
        if src_path.exists() and not dest.exists():
            try:
                dest.symlink_to(src_path)
                print_status(f"Linked {name}", "success")
            except:
                pass
    
    # Decompress rockyou if needed
    rockyou_gz = Path("/usr/share/wordlists/rockyou.txt.gz")
    rockyou = Path("/usr/share/wordlists/rockyou.txt")
    
    if rockyou_gz.exists() and not rockyou.exists() and is_root():
        print_status("Decompressing rockyou.txt...", "info")
        subprocess.run(["gzip", "-d", "-k", str(rockyou_gz)], capture_output=True)


def interactive_menu():
    """Interactive installation menu"""
    print_banner()
    
    if not is_root():
        print_status("Run with sudo for full functionality", "warning")
    
    while True:
        print(f"\n{C.CYAN}{C.BOLD}Installation Options{C.RESET}")
        print(f"{C.CYAN}{'─' * 40}{C.RESET}")
        print(f"  {C.YELLOW}[1]{C.RESET} Install All Python Packages")
        print(f"  {C.YELLOW}[2]{C.RESET} Install System Tools (apt)")
        print(f"  {C.YELLOW}[3]{C.RESET} Check Package Status")
        print(f"  {C.YELLOW}[4]{C.RESET} Check External Tools")
        print(f"  {C.YELLOW}[5]{C.RESET} Setup Wordlists")
        print(f"  {C.YELLOW}[6]{C.RESET} Install Everything")
        print(f"  {C.RED}[0]{C.RESET} Exit")
        
        choice = input(f"\n{C.CYAN}[?]{C.RESET} Select: ").strip()
        
        if choice == "0":
            print(f"\n{C.GREEN}Done! Happy hacking!{C.RESET}")
            break
        elif choice == "1":
            install_all()
        elif choice == "2":
            install_system_packages(SYSTEM_DEPS)
        elif choice == "3":
            check_all_packages()
        elif choice == "4":
            check_external_tools()
        elif choice == "5":
            setup_wordlists()
        elif choice == "6":
            install_all()
            install_system_packages(SYSTEM_DEPS)
            setup_wordlists()


def auto_install():
    """Auto-install missing packages"""
    all_packages = CORE_PACKAGES + NETWORK_PACKAGES + WEB_PACKAGES + SYSTEM_PACKAGES + CRYPTO_PACKAGES + OSINT_PACKAGES + FORENSICS_PACKAGES
    missing = [(pkg, ver) for pkg, ver in all_packages if not check_package_installed(pkg)]
    
    if not missing:
        return True
    
    print(f"\n{C.YELLOW}[!] Installing missing packages...{C.RESET}\n")
    
    for pkg, ver in missing:
        print(f"  Installing {pkg}... ", end="", flush=True)
        success, _ = install_package(pkg, ver)
        print(f"{C.GREEN}OK{C.RESET}" if success else f"{C.RED}FAILED{C.RESET}")
    
    return True


def main():
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ("--install", "-i"):
            print_banner()
            install_all()
        elif arg in ("--system", "-s"):
            print_banner()
            install_system_packages(SYSTEM_DEPS)
        elif arg in ("--check", "-c"):
            print_banner()
            check_all_packages()
            check_external_tools()
        elif arg in ("--auto", "-a"):
            auto_install()
        elif arg in ("--all", "-A"):
            print_banner()
            install_all()
            install_system_packages(SYSTEM_DEPS)
            setup_wordlists()
        elif arg in ("--help", "-h"):
            print(f"""
{C.CYAN}Red Team Tools Installer (Linux/Kali){C.RESET}

Usage: python3 installer.py [option]

Options:
  --install, -i   Install Python packages
  --system, -s    Install system tools (apt)
  --check, -c     Check all packages
  --all, -A       Install everything
  --auto, -a      Auto-install missing (quiet)
  --help, -h      Show this help
""")
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
