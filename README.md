<p align="center">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Linux"/>
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

<h1 align="center">
  🔴 Red Team Toolkit
</h1>

<p align="center">
  <b>Professional Penetration Testing & Security Assessment Suite for Kali Linux</b>
</p>

<p align="center">
  <img width="700" src="https://raw.githubusercontent.com/placeholder/redteam/main/screenshots/banner.png" alt="Red Team Banner"/>
</p>

```
██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗
██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║
██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
                    v2.0 - Kali Edition
```

---

## ⚠️ Legal Disclaimer

> **This toolkit is designed for AUTHORIZED SECURITY TESTING and EDUCATIONAL purposes ONLY.**

By using this toolkit, you acknowledge that:

- ✅ You have explicit written permission from the system/network owner
- ✅ You are conducting authorized penetration testing or security research
- ✅ You will NOT use these tools for malicious or illegal purposes
- ✅ You accept full responsibility for your actions

**🚨 Unauthorized access to computer systems is ILLEGAL and punishable by law.**

---

## 🚀 Quick Start

### Prerequisites

- Kali Linux (recommended) or Debian/Ubuntu
- Python 3.8+
- Root privileges (for network/wireless tools)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/redteam-toolkit.git
cd redteam-toolkit

# Install Python packages
sudo python3 installer.py --install

# Install Kali system tools (nmap, hashcat, aircrack-ng, etc.)
sudo python3 installer.py --system

# OR install everything at once
sudo python3 installer.py --all
```

### Launch

```bash
# Interactive menu (recommended)
sudo python3 main_menu.py

# Quick launch specific tool
sudo python3 main_menu.py wifi
sudo python3 main_menu.py portscan
python3 main_menu.py sqli

# System health check
python3 main_menu.py --check
```

---

## 📦 Features

### 🌐 Network Reconnaissance

| Tool                   | Description                                         |
| ---------------------- | --------------------------------------------------- |
| **Port Scanner**       | Multi-threaded port scanning with service detection |
| **Network Mapper**     | Network discovery and host enumeration              |
| **Service Enumerator** | Service version detection and fingerprinting        |
| **Packet Sniffer**     | Network traffic capture and analysis                |
| **SSH Bruteforce**     | SSH credential testing with rate limiting           |
| **DNS Enumeration**    | DNS records, zone transfers, subdomain discovery    |

### 🕸️ Web Security

| Tool                      | Description                                       |
| ------------------------- | ------------------------------------------------- |
| **SQL Injection Tester**  | Error, time-based, and boolean SQLi detection     |
| **XSS Scanner**           | Reflected and stored XSS vulnerability testing    |
| **Directory Bruteforcer** | Web directory and file discovery                  |
| **Subdomain Enumerator**  | Subdomain discovery and enumeration               |
| **Web Crawler**           | Website spider, form extraction, email harvesting |
| **LFI Scanner**           | Local File Inclusion vulnerability scanner        |

### 📡 Wireless Attacks

| Tool              | Description                                       |
| ----------------- | ------------------------------------------------- |
| **WiFi Scanner**  | Wireless network discovery with aircrack-ng/Scapy |
| **Deauth Attack** | Deauthentication using aireplay-ng/Scapy          |

### 🔍 OSINT (Intelligence)

| Tool                   | Description                                     |
| ---------------------- | ----------------------------------------------- |
| **Email Hunter**       | Email enumeration, MX lookup, web scraping      |
| **WHOIS Lookup**       | Domain/IP information, DNS records, geolocation |
| **Metadata Extractor** | EXIF, GPS, PDF metadata extraction              |

### 🔐 Password & Credentials

| Tool                   | Description                                      |
| ---------------------- | ------------------------------------------------ |
| **Hash Cracker**       | Multi-algorithm hash cracking (MD5, SHA, bcrypt) |
| **Hash Identifier**    | Automatic hash type detection                    |
| **Password Generator** | Secure password generation                       |

### 🔬 Forensics & Analysis

| Tool              | Description                                      |
| ----------------- | ------------------------------------------------ |
| **File Analyzer** | Hash calculation, entropy, suspicious indicators |
| **Log Parser**    | Security log analysis, attack pattern detection  |

### 💻 System Tools

| Tool                             | Description                    |
| -------------------------------- | ------------------------------ |
| **Process Monitor**              | System process analysis        |
| **Privilege Escalation Checker** | Linux privesc vector detection |
| **Persistence Checker**          | Detect persistence mechanisms  |
| **Reverse Shell Handler**        | Multi-session shell handler    |

### 💣 Exploit Development

| Tool                       | Description                   |
| -------------------------- | ----------------------------- |
| **Shellcode Generator**    | Generate and encode shellcode |
| **Buffer Overflow Helper** | BOF exploitation assistance   |
| **Payload Encoder**        | Payload encoding/obfuscation  |

### 🔒 Cryptography

| Tool              | Description                     |
| ----------------- | ------------------------------- |
| **Crypto Tools**  | Encryption/decryption utilities |
| **Steganography** | Hide data in images             |

---

## 📁 Directory Structure

```
Red_Team/
├── main_menu.py          # Main launcher with interactive menu
├── installer.py          # Auto-installer (pip + apt)
├── config.py             # Centralized configuration
├── utils.py              # Shared utilities
├── requirements.txt      # Python dependencies
├── setup.py              # Package setup
├── README.md             # This file
│
├── network/              # Network reconnaissance tools
├── web/                  # Web security tools
├── wireless/             # Wireless attack tools
├── osint/                # OSINT/Intelligence tools
├── password/             # Password cracking tools
├── forensics/            # Digital forensics tools
├── system/               # System exploitation tools
├── exploit/              # Exploit development tools
├── crypto/               # Cryptography tools
├── phishing/             # Social engineering tools
│
├── wordlists/            # Local wordlists (links to Kali's)
├── output/               # Tool output files
├── logs/                 # Log files
├── loot/                 # Captured data
└── reports/              # Generated reports
```

---

## 🔧 Configuration

Edit `config.py` to customize:

```python
# Tool paths
ExternalTools.NMAP        # Path to nmap
ExternalTools.HASHCAT     # Path to hashcat
ExternalTools.AIRCRACK    # Path to aircrack-ng

# Wordlists
Wordlists.ROCKYOU         # /usr/share/wordlists/rockyou.txt
Wordlists.SECLISTS        # /usr/share/seclists/

# Network settings
NetworkConfig.CONNECTION_TIMEOUT = 5.0
NetworkConfig.MAX_THREADS = 100
```

---

## 📚 Usage Examples

### Port Scanning

```bash
# Quick launch
python3 main_menu.py portscan

# Programmatic use
from network.port_scanner import PortScanner
scanner = PortScanner("192.168.1.1", ports="1-1000")
results = scanner.scan()
```

### SQL Injection Testing

```bash
python3 main_menu.py sqli
# Enter target URL with parameter: http://target.com/page?id=1
```

### WiFi Scanning (requires root)

```bash
sudo python3 main_menu.py wifi
# 1. Enable monitor mode on wlan0
# 2. Scan for networks
```

### OSINT - Email Discovery

```bash
python3 main_menu.py email
# Enter target domain: example.com
```

---

## 🛠️ System Requirements

### Kali Linux (Recommended)

```bash
# Most tools are pre-installed
sudo apt update
sudo apt install -y nmap hashcat john hydra aircrack-ng sqlmap
```

### Other Linux Distros

```bash
# Install system tools
sudo python3 installer.py --system
```

### Python Packages

```bash
pip3 install -r requirements.txt
```

---

## 🤝 Contributing

Contributions are welcome! Please ensure:

1. Code follows existing style conventions
2. Tools include proper documentation
3. All tools have `interactive_mode()` function
4. Add appropriate warnings and disclaimers
5. Test on Kali Linux before submitting

```bash
# Run syntax check before PR
python3 -m py_compile your_tool.py
```

---

## 📋 Changelog

### v2.0 - Kali Edition

- ✅ Optimized for Kali Linux
- ✅ Added wireless attack module (WiFi Scanner, Deauth)
- ✅ apt integration for system tools
- ✅ Kali wordlist integration
- ✅ 40+ tools across 10 categories
- ✅ Auto-installer with progress bars
- ✅ Centralized configuration

### v1.0 - Initial Release

- Basic penetration testing tools
- Cross-platform support

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Kali Linux](https://www.kali.org/) - The ultimate penetration testing distro
- [SecLists](https://github.com/danielmiessler/SecLists) - Security wordlists
- [Scapy](https://scapy.net/) - Packet manipulation library
- [Aircrack-ng](https://www.aircrack-ng.org/) - WiFi security suite

---

<p align="center">
  <b>Built for Security Professionals</b><br>
  <i>Stay Ethical. Stay Legal. Happy Hacking! 🎯</i>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-usage-examples">Usage</a> •
  <a href="#-contributing">Contributing</a>
</p>
