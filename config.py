#!/usr/bin/env python3
"""
Red Team Tools - Centralized Configuration (Linux/Kali Edition)
For educational and authorized security testing only
"""

import os
import sys
import platform
import shutil
from pathlib import Path
from typing import Dict, Optional, List

# =============================================================================
# PLATFORM DETECTION
# =============================================================================

IS_LINUX = sys.platform.startswith('linux')
IS_KALI = os.path.exists('/etc/kali-release')
IS_DEBIAN = os.path.exists('/etc/debian_version')
PLATFORM = "Kali Linux" if IS_KALI else "Linux"
ARCHITECTURE = platform.machine()
PYTHON_VERSION = sys.version_info

# =============================================================================
# DIRECTORY PATHS
# =============================================================================

BASE_DIR = Path(__file__).parent.absolute()
OUTPUT_DIR = BASE_DIR / "output"
LOGS_DIR = BASE_DIR / "logs"
TEMP_DIR = BASE_DIR / "temp"
WORDLISTS_DIR = BASE_DIR / "wordlists"
REPORTS_DIR = BASE_DIR / "reports"
LOOT_DIR = BASE_DIR / "loot"

for directory in [OUTPUT_DIR, LOGS_DIR, TEMP_DIR, WORDLISTS_DIR, REPORTS_DIR, LOOT_DIR]:
    directory.mkdir(exist_ok=True)

# =============================================================================
# KALI/LINUX TOOL PATHS
# =============================================================================

class ExternalTools:
    """External tool path configuration for Kali/Linux"""
    
    # Network tools
    NMAP = shutil.which("nmap")
    MASSCAN = shutil.which("masscan")
    NETCAT = shutil.which("nc") or shutil.which("netcat")
    TCPDUMP = shutil.which("tcpdump")
    WIRESHARK = shutil.which("wireshark") or shutil.which("tshark")
    
    # Password tools
    HASHCAT = shutil.which("hashcat")
    JOHN = shutil.which("john")
    HYDRA = shutil.which("hydra")
    
    # Web tools
    SQLMAP = shutil.which("sqlmap")
    NIKTO = shutil.which("nikto")
    GOBUSTER = shutil.which("gobuster")
    DIRB = shutil.which("dirb")
    WFUZZ = shutil.which("wfuzz")
    WPSCAN = shutil.which("wpscan")
    WHATWEB = shutil.which("whatweb")
    
    # Wireless tools
    AIRCRACK = shutil.which("aircrack-ng")
    AIREPLAY = shutil.which("aireplay-ng")
    AIRODUMP = shutil.which("airodump-ng")
    AIRMON = shutil.which("airmon-ng")
    REAVER = shutil.which("reaver")
    BETTERCAP = shutil.which("bettercap")
    MACCHANGER = shutil.which("macchanger")
    
    # Exploitation
    METASPLOIT = shutil.which("msfconsole")
    MSFVENOM = shutil.which("msfvenom")
    SEARCHSPLOIT = shutil.which("searchsploit")
    
    # OSINT
    THEHARVESTER = shutil.which("theHarvester") or shutil.which("theharvester")
    RECON_NG = shutil.which("recon-ng")
    MALTEGO = shutil.which("maltego")
    
    # Enumeration
    ENUM4LINUX = shutil.which("enum4linux")
    SMBCLIENT = shutil.which("smbclient")
    NBTSCAN = shutil.which("nbtscan")
    DNSRECON = shutil.which("dnsrecon")
    DNSENUM = shutil.which("dnsenum")
    FIERCE = shutil.which("fierce")
    
    @classmethod
    def get(cls, tool_name: str) -> Optional[str]:
        attr_name = tool_name.upper().replace("-", "_")
        return getattr(cls, attr_name, None)
    
    @classmethod
    def is_available(cls, tool_name: str) -> bool:
        path = cls.get(tool_name)
        return path is not None and os.path.exists(path)
    
    @classmethod
    def get_available_tools(cls) -> List[str]:
        tools = ["nmap", "masscan", "hashcat", "john", "hydra", "sqlmap", 
                 "nikto", "gobuster", "aircrack-ng", "metasploit", "wpscan",
                 "enum4linux", "bettercap", "theharvester"]
        return [t for t in tools if cls.is_available(t)]

# =============================================================================
# KALI WORDLISTS
# =============================================================================

class Wordlists:
    """Kali Linux wordlist paths"""
    
    # System wordlists
    ROCKYOU = Path("/usr/share/wordlists/rockyou.txt")
    ROCKYOU_GZ = Path("/usr/share/wordlists/rockyou.txt.gz")
    
    # SecLists
    SECLISTS = Path("/usr/share/seclists")
    SECLISTS_PASSWORDS = SECLISTS / "Passwords"
    SECLISTS_USERNAMES = SECLISTS / "Usernames"
    SECLISTS_DISCOVERY = SECLISTS / "Discovery"
    SECLISTS_FUZZING = SECLISTS / "Fuzzing"
    
    # Dirb/Dirbuster
    DIRB = Path("/usr/share/wordlists/dirb")
    DIRBUSTER = Path("/usr/share/wordlists/dirbuster")
    
    # Wfuzz
    WFUZZ = Path("/usr/share/wordlists/wfuzz")
    
    # Common wordlists
    COMMON_PASSWORDS = SECLISTS_PASSWORDS / "Common-Credentials/10-million-password-list-top-100000.txt"
    COMMON_USERNAMES = SECLISTS_USERNAMES / "Names/names.txt"
    COMMON_DIRS = SECLISTS_DISCOVERY / "Web-Content/common.txt"
    COMMON_SUBDOMAINS = SECLISTS_DISCOVERY / "DNS/subdomains-top1million-5000.txt"
    
    # Local wordlists
    LOCAL_DIR = WORDLISTS_DIR
    
    @classmethod
    def get(cls, wordlist_type: str) -> Optional[Path]:
        mapping = {
            "rockyou": cls.ROCKYOU,
            "passwords": cls.COMMON_PASSWORDS,
            "usernames": cls.COMMON_USERNAMES,
            "directories": cls.COMMON_DIRS,
            "subdomains": cls.COMMON_SUBDOMAINS,
        }
        return mapping.get(wordlist_type.lower())
    
    @classmethod
    def find(cls, name: str) -> Optional[Path]:
        """Find wordlist by partial name"""
        search_paths = [cls.SECLISTS, cls.DIRB, cls.DIRBUSTER, cls.WFUZZ, cls.LOCAL_DIR]
        
        for base in search_paths:
            if base.exists():
                for path in base.rglob(f"*{name}*"):
                    if path.is_file():
                        return path
        return None

# =============================================================================
# NETWORK INTERFACES
# =============================================================================

class NetworkConfig:
    """Network configuration"""
    
    CONNECTION_TIMEOUT = 5.0
    READ_TIMEOUT = 10.0
    SCAN_TIMEOUT = 30.0
    MAX_THREADS = 100
    REQUESTS_PER_SECOND = 10
    
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                   445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
    
    DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    
    @staticmethod
    def get_interfaces() -> List[str]:
        """Get network interfaces"""
        try:
            import netifaces
            return netifaces.interfaces()
        except:
            interfaces = []
            net_path = Path("/sys/class/net")
            if net_path.exists():
                interfaces = [d.name for d in net_path.iterdir()]
            return interfaces
    
    @staticmethod
    def get_wireless_interfaces() -> List[str]:
        """Get wireless interfaces"""
        wireless = []
        for iface in NetworkConfig.get_interfaces():
            if iface.startswith(('wlan', 'wlp', 'ath', 'wifi')):
                wireless.append(iface)
        return wireless

# =============================================================================
# WIRELESS CONFIG
# =============================================================================

class WirelessConfig:
    """Wireless attack configuration"""
    
    MONITOR_MODE_SUFFIX = "mon"
    DEFAULT_CHANNEL = 6
    DEAUTH_PACKETS = 10
    BEACON_INTERVAL = 100
    
    @staticmethod
    def get_monitor_interface(iface: str) -> str:
        return f"{iface}{WirelessConfig.MONITOR_MODE_SUFFIX}"

# =============================================================================
# EXPLOIT CONFIG
# =============================================================================

class ExploitConfig:
    DEFAULT_LHOST = "0.0.0.0"
    DEFAULT_LPORT = 4444
    PAYLOAD_FORMATS = ["raw", "c", "python", "bash", "elf", "hex", "base64"]
    ARCHITECTURES = ["x86", "x64", "arm", "arm64"]
    PLATFORMS = ["linux", "windows", "android"]

# =============================================================================
# LOGGING
# =============================================================================

class LogConfig:
    LOG_LEVEL = "INFO"
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_FILE = LOGS_DIR / "redteam.log"
    MAX_LOG_SIZE = 10 * 1024 * 1024
    BACKUP_COUNT = 5

# =============================================================================
# VERSION
# =============================================================================

VERSION = "2.0.0"
VERSION_NAME = "Kali Edition"

# =============================================================================
# HELPERS
# =============================================================================

def is_root() -> bool:
    return os.geteuid() == 0

def get_local_ip() -> str:
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_system_info() -> Dict[str, str]:
    return {
        "platform": PLATFORM,
        "is_kali": IS_KALI,
        "architecture": ARCHITECTURE,
        "python_version": f"{PYTHON_VERSION.major}.{PYTHON_VERSION.minor}.{PYTHON_VERSION.micro}",
        "is_root": is_root(),
        "hostname": platform.node(),
    }

# Legal disclaimer
DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║  ⚠️  AUTHORIZED SECURITY TESTING ONLY  ⚠️                                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This toolkit is for authorized penetration testing and security research.  ║
║  Unauthorized access to computer systems is ILLEGAL.                         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

def init_environment():
    for directory in [OUTPUT_DIR, LOGS_DIR, TEMP_DIR, WORDLISTS_DIR, REPORTS_DIR, LOOT_DIR]:
        directory.mkdir(exist_ok=True)
    return True

init_environment()
