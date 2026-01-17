#!/usr/bin/env python3
"""
Red Team Tools - Main Menu
Professional Security Testing Toolkit (Linux/Kali Edition)
For authorized security testing and incident analysis only

██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗
██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║
██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝

Version 2.0 - Kali Edition
"""

import os
import sys
import importlib
import platform

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Auto-install missing packages
def check_and_install():
    """Check and install missing packages"""
    try:
        from installer import auto_install
        auto_install()
    except ImportError:
        pass

check_and_install()

from utils import *

# Version info
VERSION = "2.0.0"
VERSION_NAME = "Kali Edition"


class RedTeamMenu:
    """Main menu for Red Team Tools"""
    
    TOOLS = {
        "Network Reconnaissance": [
            ("Port Scanner", "network.port_scanner"),
            ("Network Mapper", "network.network_mapper"),
            ("Service Enumerator", "network.service_enum"),
            ("Packet Sniffer", "network.packet_sniffer"),
            ("SSH Bruteforce", "network.ssh_bruteforce"),
            ("DNS Enumeration", "network.dns_enum"),
        ],
        "Web Security": [
            ("Directory Bruteforcer", "web.dir_bruteforcer"),
            ("XSS Scanner", "web.xss_scanner"),
            ("SQL Injection Tester", "web.sqli_tester"),
            ("Subdomain Enumerator", "web.subdomain_enum"),
            ("Web Crawler", "web.crawler"),
            ("LFI Scanner", "web.lfi_scanner"),
        ],
        "Password & Credentials": [
            ("Password Generator", "password.password_generator"),
            ("Hash Cracker", "password.hash_cracker"),
            ("Hash Identifier", "password.hash_identifier"),
        ],
        "OSINT (Intelligence)": [
            ("Email Hunter", "osint.email_hunter"),
            ("WHOIS Lookup", "osint.whois_lookup"),
            ("Metadata Extractor", "osint.metadata_extractor"),
        ],
        "System Tools": [
            ("Process Monitor", "system.process_monitor"),
            ("Privilege Escalation Checker", "system.priv_escalation_checker"),
            ("Persistence Checker", "system.persistence_checker"),
        ],
        "Forensics & Analysis": [
            ("File Analyzer", "forensics.file_analyzer"),
            ("Log Parser", "forensics.log_parser"),
        ],
        "Exploit Development": [
            ("Shellcode Generator", "exploit.shellcode_gen"),
            ("Buffer Overflow Helper", "exploit.buffer_overflow_helper"),
            ("Payload Encoder", "exploit.payload_encoder"),
        ],
        "Wireless Attacks": [
            ("WiFi Scanner", "wireless.wifi_scanner"),
            ("Deauth Attack", "wireless.deauth"),
        ],
        "Cryptography": [
            ("Crypto Tools", "crypto.crypto_tools"),
            ("Steganography", "crypto.steganography"),
        ],
        "Phishing & Social Eng": [
            ("Email Spoofer", "phishing.email_spoofer"),
            ("Phishing Page Generator", "phishing.phishing_generator"),
        ],
    }
    
    def __init__(self):
        self.running = True
    
    def display_banner(self):
        """Display main banner"""
        clear_screen()
        
        banner_text = f"""
{R}██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗
██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║
██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝{RESET}
        """
        
        print(banner_text)
        print(f"{R}{'═' * 70}{RESET}")
        print(f"{C}  Version {VERSION} - {VERSION_NAME}{RESET}")
        print(f"{Y}  Platform: {platform.system()} {platform.release()} | Python {platform.python_version()}{RESET}")
        print(f"{R}{'═' * 70}{RESET}")
        print(f"{Y}  ⚠  FOR AUTHORIZED SECURITY TESTING ONLY  ⚠{RESET}")
        print(f"{R}{'═' * 70}{RESET}")
        print()
    
    def display_categories(self):
        """Display tool categories"""
        print(f"\n{C}{BRIGHT}TOOL CATEGORIES{RESET}")
        print(f"{C}{'─' * 50}{RESET}")
        
        categories = list(self.TOOLS.keys())
        for i, cat in enumerate(categories, 1):
            tool_count = len(self.TOOLS[cat])
            print(f"  {Y}[{i:2}]{RESET} {cat} ({tool_count} tools)")
        
        print(f"\n  {C}[S]{RESET}  System Health Check")
        print(f"  {C}[I]{RESET}  Install Dependencies")
        print(f"  {R}[0]{RESET}  Exit")
        print()
        
        return categories
    
    def display_tools(self, category: str):
        """Display tools in a category"""
        tools = self.TOOLS.get(category, [])
        
        clear_screen()
        print(f"\n{C}{BRIGHT}{category.upper()}{RESET}")
        print(f"{C}{'─' * 50}{RESET}")
        
        for i, (name, module) in enumerate(tools, 1):
            print(f"  {Y}[{i}]{RESET} {name}")
        
        print(f"\n  {R}[0]{RESET} Back to Main Menu")
        print()
        
        return tools
    
    def run_tool(self, module_path: str):
        """Run a specific tool"""
        try:
            module = importlib.import_module(module_path)
            
            if hasattr(module, 'interactive_mode'):
                module.interactive_mode()
            else:
                error("Tool does not have interactive mode")
        except ImportError as e:
            error(f"Failed to load tool: {e}")
            print(f"{Y}Tip: Run 'python installer.py' to install dependencies{RESET}")
        except Exception as e:
            error(f"Error running tool: {e}")
        
        print()
        input(f"{C}Press Enter to continue...{RESET}")
    
    def system_health_check(self):
        """Check system and tool status"""
        clear_screen()
        print(f"\n{C}{BRIGHT}═══ System Health Check ═══{RESET}\n")
        
        # System info
        print(f"{Y}System Info:{RESET}")
        print(f"  Platform:    {platform.system()} {platform.release()}")
        print(f"  Python:      {platform.python_version()}")
        print(f"  Architecture: {platform.machine()}")
        
        # Check admin/root
        is_admin = False
        if os.name == 'nt':
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                pass
        else:
            is_admin = os.geteuid() == 0
        
        print(f"  Admin/Root:  {'Yes' if is_admin else 'No'}")
        
        # Check key packages
        print(f"\n{Y}Package Status:{RESET}")
        packages = [
            ("colorama", "colorama"),
            ("requests", "requests"),
            ("scapy", "scapy"),
            ("paramiko", "paramiko"),
            ("beautifulsoup4", "bs4"),
            ("pycryptodome", "Crypto"),
            ("dnspython", "dns"),
            ("python-whois", "whois"),
            ("psutil", "psutil"),
        ]
        
        for name, import_name in packages:
            try:
                __import__(import_name)
                print(f"  {G}✓{RESET} {name}")
            except ImportError:
                print(f"  {R}✗{RESET} {name}")
        
        # Check external tools
        print(f"\n{Y}External Tools:{RESET}")
        import shutil
        tools = ["nmap", "hashcat", "john", "hydra", "sqlmap", "nikto"]
        
        for tool in tools:
            path = shutil.which(tool)
            if path:
                print(f"  {G}✓{RESET} {tool}")
            else:
                print(f"  {R}✗{RESET} {tool}")
        
        print()
        input(f"{C}Press Enter to continue...{RESET}")
    
    def run_installer(self):
        """Run the package installer"""
        try:
            from installer import interactive_menu
            interactive_menu()
        except ImportError:
            error("installer.py not found")
            input(f"{C}Press Enter to continue...{RESET}")
    
    def main_loop(self):
        """Main menu loop"""
        while self.running:
            self.display_banner()
            categories = self.display_categories()
            
            try:
                choice = prompt("Select category").strip().lower()
                
                if choice == "0":
                    self.running = False
                    clear_screen()
                    print(f"\n{G}Thanks for using Red Team Tools!{RESET}")
                    print(f"{Y}Stay ethical. Stay legal.{RESET}\n")
                    break
                
                if choice == "s":
                    self.system_health_check()
                    continue
                
                if choice == "i":
                    self.run_installer()
                    continue
                
                try:
                    cat_num = int(choice)
                    if 1 <= cat_num <= len(categories):
                        category = categories[cat_num - 1]
                        
                        while True:
                            tools = self.display_tools(category)
                            
                            tool_choice = prompt("Select tool").strip()
                            
                            if tool_choice == "0":
                                break
                            
                            try:
                                tool_num = int(tool_choice)
                                if 1 <= tool_num <= len(tools):
                                    name, module_path = tools[tool_num - 1]
                                    clear_screen()
                                    self.run_tool(module_path)
                                else:
                                    error("Invalid selection")
                            except ValueError:
                                error("Please enter a number")
                    else:
                        error("Invalid selection")
                except ValueError:
                    error("Invalid input")
            
            except KeyboardInterrupt:
                print()
                if confirm("Exit Red Team Tools?"):
                    self.running = False
                    break


def quick_run(tool_name: str):
    """Quick run a specific tool by name"""
    tool_map = {
        "portscan": "network.port_scanner",
        "netmap": "network.network_mapper",
        "service": "network.service_enum",
        "sniffer": "network.packet_sniffer",
        "ssh": "network.ssh_bruteforce",
        "dns": "network.dns_enum",
        "passgen": "password.password_generator",
        "hashcrack": "password.hash_cracker",
        "hashid": "password.hash_identifier",
        "dirbust": "web.dir_bruteforcer",
        "xss": "web.xss_scanner",
        "sqli": "web.sqli_tester",
        "subdomain": "web.subdomain_enum",
        "crawler": "web.crawler",
        "lfi": "web.lfi_scanner",
        "email": "osint.email_hunter",
        "whois": "osint.whois_lookup",
        "metadata": "osint.metadata_extractor",
        "procmon": "system.process_monitor",
        "privesc": "system.priv_escalation_checker",
        "persist": "system.persistence_checker",
        "fileanalyze": "forensics.file_analyzer",
        "logparse": "forensics.log_parser",
        "shellcode": "exploit.shellcode_gen",
        "bof": "exploit.buffer_overflow_helper",
        "encode": "exploit.payload_encoder",
        "crypto": "crypto.crypto_tools",
        "stego": "crypto.steganography",
        "phish": "phishing.phishing_generator",
        "wifi": "wireless.wifi_scanner",
        "deauth": "wireless.deauth",
    }
    
    if tool_name in tool_map:
        try:
            module = importlib.import_module(tool_map[tool_name])
            if hasattr(module, 'interactive_mode'):
                module.interactive_mode()
        except ImportError as e:
            error(f"Failed to load tool: {e}")
    else:
        print(f"Available tools: {', '.join(sorted(tool_map.keys()))}")


def main():
    """Main entry point"""
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        
        if arg in ("--help", "-h"):
            print(f"""
{C}Red Team Tools - Professional Security Toolkit{RESET}

Usage: python main_menu.py [option|tool]

Options:
  --help, -h      Show this help
  --version, -v   Show version
  --check, -c     Run system health check
  --install, -i   Run installer

Tools (quick launch):
  portscan, dns, ssh, crawler, sqli, xss, lfi,
  hashcrack, passgen, email, whois, metadata,
  fileanalyze, logparse, privesc, and more...

Example:
  python main_menu.py portscan
  python main_menu.py --install
""")
        elif arg in ("--version", "-v"):
            print(f"Red Team Tools v{VERSION} - {VERSION_NAME}")
        
        elif arg in ("--check", "-c"):
            menu = RedTeamMenu()
            menu.system_health_check()
        
        elif arg in ("--install", "-i"):
            from installer import interactive_menu
            interactive_menu()
        
        else:
            quick_run(arg)
    else:
        menu = RedTeamMenu()
        menu.main_loop()


if __name__ == "__main__":
    main()

