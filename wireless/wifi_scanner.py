#!/usr/bin/env python3
"""
Red Team Tools - WiFi Scanner
Wireless network discovery and analysis
For authorized security testing only - Linux/Kali
"""

import sys
import os
import subprocess
import re
import time
from typing import Dict, List, Optional
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import *

try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class WiFiScanner:
    """WiFi network scanner using aircrack-ng suite"""
    
    def __init__(self, interface: str = None):
        self.interface = interface
        self.monitor_interface = None
        self.networks: Dict[str, Dict] = {}
        self.clients: List[Dict] = []
        self.scanning = False
    
    def get_wireless_interfaces(self) -> List[str]:
        """Get available wireless interfaces"""
        interfaces = []
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True, stderr=subprocess.STDOUT)
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line or 'ESSID' in line:
                    iface = line.split()[0]
                    if iface:
                        interfaces.append(iface)
        except:
            # Fallback to /sys/class/net
            net_path = Path("/sys/class/net")
            if net_path.exists():
                for iface_dir in net_path.iterdir():
                    wireless_path = iface_dir / "wireless"
                    if wireless_path.exists():
                        interfaces.append(iface_dir.name)
        return interfaces
    
    def enable_monitor_mode(self, interface: str = None) -> Optional[str]:
        """Enable monitor mode using airmon-ng"""
        iface = interface or self.interface
        if not iface:
            error("No interface specified")
            return None
        
        if not self._check_root():
            error("Root privileges required for monitor mode")
            return None
        
        info(f"Enabling monitor mode on {iface}...")
        
        # Kill interfering processes
        subprocess.run(['airmon-ng', 'check', 'kill'], capture_output=True)
        
        # Enable monitor mode
        result = subprocess.run(['airmon-ng', 'start', iface], capture_output=True, text=True)
        
        # Find the monitor interface name
        for line in result.stdout.split('\n'):
            if 'monitor mode' in line.lower() or 'mon' in line:
                match = re.search(r'(\w+mon\w*|\w+mon)', line)
                if match:
                    self.monitor_interface = match.group(1)
                    break
        
        if not self.monitor_interface:
            # Try common naming patterns
            for suffix in ['mon', 'mon0']:
                check_iface = f"{iface}{suffix}" if not iface.endswith('mon') else iface
                result = subprocess.run(['iwconfig', check_iface], capture_output=True)
                if result.returncode == 0:
                    self.monitor_interface = check_iface
                    break
        
        if self.monitor_interface:
            success(f"Monitor mode enabled: {self.monitor_interface}")
            return self.monitor_interface
        else:
            error("Failed to enable monitor mode")
            return None
    
    def disable_monitor_mode(self, interface: str = None):
        """Disable monitor mode"""
        iface = interface or self.monitor_interface
        if iface:
            subprocess.run(['airmon-ng', 'stop', iface], capture_output=True)
            info(f"Disabled monitor mode on {iface}")
            
            # Restart network manager
            subprocess.run(['systemctl', 'start', 'NetworkManager'], capture_output=True)
    
    def scan_networks_airodump(self, duration: int = 30) -> Dict[str, Dict]:
        """Scan networks using airodump-ng"""
        iface = self.monitor_interface or self.interface
        if not iface:
            error("No monitor interface available")
            return {}
        
        output_prefix = "/tmp/airodump_scan"
        
        # Clean old files
        for ext in ['-01.csv', '-01.cap', '-01.kismet.csv', '-01.kismet.netxml']:
            try:
                os.remove(f"{output_prefix}{ext}")
            except:
                pass
        
        info(f"Scanning for {duration} seconds...")
        
        # Run airodump-ng
        proc = subprocess.Popen(
            ['airodump-ng', '-w', output_prefix, '--output-format', 'csv', iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        
        time.sleep(duration)
        proc.terminate()
        proc.wait()
        
        # Parse results
        csv_file = f"{output_prefix}-01.csv"
        if os.path.exists(csv_file):
            self._parse_airodump_csv(csv_file)
        
        return self.networks
    
    def scan_networks_scapy(self, duration: int = 30) -> Dict[str, Dict]:
        """Scan networks using Scapy (requires monitor mode)"""
        if not SCAPY_AVAILABLE:
            error("Scapy not available")
            return {}
        
        iface = self.monitor_interface or self.interface
        if not iface:
            error("No interface available")
            return {}
        
        self.networks = {}
        self.scanning = True
        
        def packet_handler(pkt):
            if not self.scanning:
                return
            
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                bssid = pkt[Dot11].addr2
                
                if bssid not in self.networks:
                    # Get SSID
                    ssid = ""
                    if pkt.haslayer(Dot11Elt):
                        elt = pkt[Dot11Elt]
                        while elt:
                            if elt.ID == 0:  # SSID
                                ssid = elt.info.decode(errors='ignore')
                            if elt.ID == 3:  # Channel
                                channel = ord(elt.info) if elt.info else 0
                            elt = elt.payload.getlayer(Dot11Elt)
                    
                    # Get signal strength
                    signal = -100
                    if pkt.haslayer(RadioTap):
                        try:
                            signal = pkt[RadioTap].dBm_AntSignal
                        except:
                            pass
                    
                    # Get encryption
                    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
                    encryption = "Open"
                    if 'privacy' in cap:
                        encryption = "WEP/WPA"
                    
                    self.networks[bssid] = {
                        'ssid': ssid or '<Hidden>',
                        'bssid': bssid,
                        'channel': getattr(locals(), 'channel', 0),
                        'signal': signal,
                        'encryption': encryption,
                    }
        
        info(f"Scanning on {iface} for {duration} seconds...")
        
        try:
            sniff(iface=iface, prn=packet_handler, timeout=duration, store=0)
        except Exception as e:
            error(f"Scan error: {e}")
        
        self.scanning = False
        return self.networks
    
    def _parse_airodump_csv(self, csv_file: str):
        """Parse airodump-ng CSV output"""
        try:
            with open(csv_file, 'r', errors='ignore') as f:
                content = f.read()
            
            # Split into AP and client sections
            sections = content.split('\n\n')
            
            # Parse APs (first section)
            if sections:
                lines = sections[0].strip().split('\n')
                for line in lines[2:]:  # Skip headers
                    parts = line.split(',')
                    if len(parts) >= 14:
                        bssid = parts[0].strip()
                        if bssid and ':' in bssid:
                            self.networks[bssid] = {
                                'bssid': bssid,
                                'channel': int(parts[3].strip() or 0),
                                'signal': int(parts[8].strip() or -100),
                                'encryption': parts[5].strip(),
                                'cipher': parts[6].strip(),
                                'auth': parts[7].strip(),
                                'ssid': parts[13].strip() or '<Hidden>',
                            }
        except Exception as e:
            error(f"Parse error: {e}")
    
    def _check_root(self) -> bool:
        return os.geteuid() == 0
    
    def print_networks(self):
        """Print discovered networks"""
        if not self.networks:
            warning("No networks found")
            return
        
        print(f"\n{C}{BRIGHT}═══ Discovered Networks ({len(self.networks)}) ═══{RESET}")
        print(f"\n{'BSSID':<18} {'CH':>3} {'dBm':>5} {'Encryption':<15} {'SSID'}")
        print(f"{'-'*18} {'-'*3} {'-'*5} {'-'*15} {'-'*20}")
        
        for bssid, info in sorted(self.networks.items(), key=lambda x: x[1].get('signal', -100), reverse=True):
            enc = info.get('encryption', 'Unknown')[:15]
            ssid = info.get('ssid', '<Hidden>')[:25]
            ch = info.get('channel', 0)
            sig = info.get('signal', -100)
            
            sig_color = G if sig > -50 else (Y if sig > -70 else R)
            print(f"{bssid:<18} {ch:>3} {sig_color}{sig:>5}{RESET} {enc:<15} {ssid}")


def interactive_mode():
    """Interactive WiFi scanning"""
    clear_screen()
    print_banner("WIFI SCANNER", font="small", color="cyan")
    
    print(f"{R}{'═' * 50}{RESET}")
    print(f"{Y}⚠  AUTHORIZED TESTING ONLY - Requires root{RESET}")
    print(f"{R}{'═' * 50}{RESET}\n")
    
    if os.geteuid() != 0:
        error("This tool requires root privileges!")
        print(f"{Y}Run with: sudo python3 main_menu.py{RESET}")
        input(f"\n{C}Press Enter...{RESET}")
        return
    
    scanner = WiFiScanner()
    
    # Show available interfaces
    interfaces = scanner.get_wireless_interfaces()
    if interfaces:
        success(f"Found interfaces: {', '.join(interfaces)}")
    else:
        error("No wireless interfaces found")
    
    while True:
        print(f"\n{C}OPTIONS{RESET}")
        print(f"  {Y}[1]{RESET} List Wireless Interfaces")
        print(f"  {Y}[2]{RESET} Enable Monitor Mode")
        print(f"  {Y}[3]{RESET} Scan Networks (airodump-ng)")
        print(f"  {Y}[4]{RESET} Scan Networks (Scapy)")
        print(f"  {Y}[5]{RESET} Disable Monitor Mode")
        print(f"  {R}[0]{RESET} Back")
        
        choice = prompt("Select").strip()
        
        if choice == "0":
            if scanner.monitor_interface:
                if confirm("Disable monitor mode before exit?"):
                    scanner.disable_monitor_mode()
            break
        
        elif choice == "1":
            interfaces = scanner.get_wireless_interfaces()
            if interfaces:
                print(f"\n{G}Wireless Interfaces:{RESET}")
                for iface in interfaces:
                    print(f"  • {iface}")
            else:
                error("No wireless interfaces found")
        
        elif choice == "2":
            interfaces = scanner.get_wireless_interfaces()
            if not interfaces:
                error("No wireless interfaces")
                continue
            
            print(f"\nAvailable: {', '.join(interfaces)}")
            iface = prompt("Interface").strip()
            if iface in interfaces or iface:
                scanner.enable_monitor_mode(iface)
        
        elif choice == "3":
            duration = int(prompt("Scan duration [30]").strip() or "30")
            scanner.scan_networks_airodump(duration)
            scanner.print_networks()
        
        elif choice == "4":
            if not SCAPY_AVAILABLE:
                error("Scapy not installed")
                continue
            duration = int(prompt("Scan duration [30]").strip() or "30")
            scanner.scan_networks_scapy(duration)
            scanner.print_networks()
        
        elif choice == "5":
            scanner.disable_monitor_mode()
    
    input(f"\n{C}Press Enter...{RESET}")


if __name__ == "__main__":
    interactive_mode()
