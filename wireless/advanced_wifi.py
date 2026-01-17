#!/usr/bin/env python3
"""
Red Team Toolkit - Advanced WiFi Module
Integration layer for PyAirgeddon red team capabilities

This module provides a unified interface to access PyAirgeddon's
advanced wireless attack capabilities from the Red Team toolkit.

Features:
- Network reconnaissance and analysis
- Karma/MANA rogue AP attacks
- Stealth scanning with evasion
- Client fingerprinting and PNL collection
"""

import os
import sys
from typing import Optional, List, Dict, Callable
from dataclasses import dataclass
from datetime import datetime

# Add pyairgeddon to path
PYAIRGEDDON_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    'pyairgeddon'
)
if PYAIRGEDDON_PATH not in sys.path:
    sys.path.insert(0, PYAIRGEDDON_PATH)

# Try to import pyairgeddon modules
try:
    from pyairgeddon_recon import (
        BeaconAnalyzer, ProbeTracker, HiddenNetworkDetector,
        ClientFingerprinter, VendorLookup, ReconCoordinator
    )
    RECON_AVAILABLE = True
except ImportError:
    RECON_AVAILABLE = False

try:
    from pyairgeddon_karma import (
        KarmaAttack, MANAAttack, LoudMANA, PNLCollector
    )
    KARMA_AVAILABLE = True
except ImportError:
    KARMA_AVAILABLE = False

try:
    from pyairgeddon_evasion import (
        MACRandomizer, PowerController, TimingController,
        WIDSDetector, StealthScanner, EvasionCoordinator
    )
    EVASION_AVAILABLE = True
except ImportError:
    EVASION_AVAILABLE = False

try:
    from pyairgeddon_core import WirelessInterface, NetworkScanner
    CORE_AVAILABLE = True
except ImportError:
    CORE_AVAILABLE = False

try:
    from pyairgeddon_attacks import DeauthAttack, DoSAttack, WPSAttack
    ATTACKS_AVAILABLE = True
except ImportError:
    ATTACKS_AVAILABLE = False

try:
    from pyairgeddon_eviltwin import EvilTwinAP
    EVILTWIN_AVAILABLE = True
except ImportError:
    EVILTWIN_AVAILABLE = False


# ============================================================================
# AVAILABILITY CHECK
# ============================================================================

def get_available_modules() -> Dict[str, bool]:
    """Get availability status of all modules"""
    return {
        "recon": RECON_AVAILABLE,
        "karma": KARMA_AVAILABLE,
        "evasion": EVASION_AVAILABLE,
        "core": CORE_AVAILABLE,
        "attacks": ATTACKS_AVAILABLE,
        "eviltwin": EVILTWIN_AVAILABLE
    }


def check_requirements() -> List[str]:
    """Check for missing requirements and return list of issues"""
    issues = []
    
    modules = get_available_modules()
    missing = [name for name, available in modules.items() if not available]
    
    if missing:
        issues.append(f"Missing modules: {', '.join(missing)}")
        issues.append("Ensure pyairgeddon is properly installed")
    
    # Check for scapy
    try:
        import scapy
    except ImportError:
        issues.append("Scapy not installed (pip install scapy)")
    
    # Check for root on Linux
    if os.name != 'nt' and os.geteuid() != 0:
        issues.append("Root privileges required for wireless operations")
    
    return issues


# ============================================================================
# UNIFIED WIRELESS TOOLKIT
# ============================================================================

class AdvancedWiFiToolkit:
    """
    Unified interface to all PyAirgeddon capabilities
    """
    
    def __init__(self, interface: str = None):
        """
        Initialize the toolkit
        
        Args:
            interface: Wireless interface to use (auto-detect if None)
        """
        self.interface = interface
        self._detect_interface()
        
        # Initialize available modules
        self.recon: Optional[ReconCoordinator] = None
        self.karma: Optional[KarmaAttack] = None
        self.mana: Optional[MANAAttack] = None
        self.evasion: Optional[EvasionCoordinator] = None
        self.scanner: Optional[StealthScanner] = None
        
        if self.interface:
            self._init_modules()
    
    def _detect_interface(self):
        """Auto-detect wireless interface if not specified"""
        if self.interface:
            return
        
        if CORE_AVAILABLE:
            try:
                wifi = WirelessInterface()
                wifi.refresh_interfaces()
                if wifi.interfaces:
                    self.interface = list(wifi.interfaces.keys())[0]
            except:
                pass
        
        if not self.interface:
            # Fallback to common names
            for iface in ['wlan0', 'wlan1', 'wlp2s0', 'wlp3s0']:
                if os.path.exists(f'/sys/class/net/{iface}'):
                    self.interface = iface
                    break
    
    def _init_modules(self):
        """Initialize available modules"""
        if not self.interface:
            return
        
        if RECON_AVAILABLE:
            self.recon = ReconCoordinator(self.interface)
        
        if KARMA_AVAILABLE:
            self.karma = KarmaAttack(self.interface)
            self.mana = MANAAttack(self.interface)
        
        if EVASION_AVAILABLE:
            self.evasion = EvasionCoordinator(self.interface)
            self.scanner = StealthScanner(self.interface)
    
    def get_status(self) -> Dict:
        """Get current toolkit status"""
        return {
            "interface": self.interface,
            "modules": get_available_modules(),
            "requirements": check_requirements()
        }
    
    # ========================================================================
    # RECONNAISSANCE
    # ========================================================================
    
    def scan_networks(self, duration: int = 30, stealth: bool = True,
                      log_callback: Callable = None) -> List[Dict]:
        """
        Scan for wireless networks
        
        Args:
            duration: Scan duration in seconds
            stealth: Use stealth scanning mode
            log_callback: Callback for log messages
        """
        if not self.interface:
            if log_callback:
                log_callback("[!] No interface available")
            return []
        
        if stealth and self.scanner:
            result = self.scanner.start_passive_scan(
                duration=duration,
                stealth_level=2,
                log_callback=log_callback
            )
            return result.networks
        elif self.recon:
            self.recon.start_full_recon(log_callback)
            import time
            time.sleep(duration)
            self.recon.stop_recon(log_callback)
            return [
                {
                    "ssid": b.ssid,
                    "bssid": b.bssid,
                    "channel": b.channel,
                    "encryption": b.encryption,
                    "signal": b.signal
                }
                for b in self.recon.beacon_analyzer.get_beacons()
            ]
        
        return []
    
    def analyze_security(self, log_callback: Callable = None) -> List[Dict]:
        """Analyze security issues in scanned networks"""
        if self.recon and self.recon.beacon_analyzer:
            return self.recon.beacon_analyzer.get_security_issues()
        return []
    
    def track_clients(self, duration: int = 60,
                      log_callback: Callable = None) -> List[Dict]:
        """
        Track wireless clients and their probe requests
        
        Returns list of clients with their PNL
        """
        if not RECON_AVAILABLE or not self.interface:
            return []
        
        tracker = ProbeTracker(self.interface)
        tracker.start_tracking(log_callback=log_callback)
        
        import time
        time.sleep(duration)
        
        tracker.stop_tracking(log_callback)
        
        return [
            {
                "mac": c.mac,
                "vendor": c.vendor,
                "probed_ssids": list(c.probed_ssids),
                "first_seen": c.first_seen.isoformat(),
                "last_seen": c.last_seen.isoformat()
            }
            for c in tracker.get_clients()
        ]
    
    # ========================================================================
    # ATTACKS
    # ========================================================================
    
    def start_karma(self, channel: int = 6,
                    log_callback: Callable = None) -> bool:
        """
        Start Karma attack (respond to probe requests)
        """
        if not self.karma:
            if log_callback:
                log_callback("[!] Karma module not available")
            return False
        
        return self.karma.start(channel=channel, log_callback=log_callback)
    
    def stop_karma(self, log_callback: Callable = None) -> Dict:
        """Stop Karma attack and return results"""
        if not self.karma:
            return {}
        
        result = self.karma.stop(log_callback)
        return {
            "ssids_collected": result.ssids_collected,
            "total_probes": result.total_probes
        }
    
    def start_mana(self, ssid: str = "FreeWifi", channel: int = 6,
                   loud_mode: bool = False,
                   log_callback: Callable = None) -> bool:
        """
        Start MANA attack (full rogue AP)
        
        Args:
            ssid: Primary SSID for the AP
            channel: WiFi channel
            loud_mode: Broadcast collected SSIDs
        """
        if not self.mana:
            if log_callback:
                log_callback("[!] MANA module not available")
            return False
        
        return self.mana.start(
            ssid=ssid,
            channel=channel,
            loud_mode=loud_mode,
            log_callback=log_callback
        )
    
    def stop_mana(self, log_callback: Callable = None) -> Dict:
        """Stop MANA attack"""
        if not self.mana:
            return {}
        
        result = self.mana.stop(log_callback)
        return {
            "ssids_collected": result.ssids_collected,
            "clients_connected": len(result.clients_connected)
        }
    
    def deauth_client(self, target_bssid: str, client_mac: str = None,
                      count: int = 10, log_callback: Callable = None) -> bool:
        """
        Send deauthentication packets
        
        Args:
            target_bssid: Target AP MAC address
            client_mac: Target client (None for broadcast)
            count: Number of deauth packets
        """
        if not ATTACKS_AVAILABLE or not self.interface:
            return False
        
        attack = DeauthAttack(self.interface)
        attack.start(
            target_bssid=target_bssid,
            client_mac=client_mac,
            count=count,
            continuous=False,
            log_callback=log_callback
        )
        return True
    
    # ========================================================================
    # EVASION
    # ========================================================================
    
    def setup_stealth(self, level: int = 2,
                      log_callback: Callable = None) -> bool:
        """
        Setup stealth mode on interface
        
        Level 1: MAC randomization
        Level 2: + Low power
        Level 3: + Aggressive timing jitter
        """
        if not self.evasion:
            if log_callback:
                log_callback("[!] Evasion module not available")
            return False
        
        return self.evasion.setup_stealth_mode(level, log_callback)
    
    def restore_interface(self, log_callback: Callable = None):
        """Restore original interface settings"""
        if self.evasion:
            self.evasion.cleanup_stealth_mode(log_callback)
    
    def randomize_mac(self, vendor: str = None,
                      log_callback: Callable = None) -> str:
        """
        Randomize interface MAC address
        
        Args:
            vendor: Preferred vendor (apple, samsung, google, intel, random)
        
        Returns: New MAC address or empty string on failure
        """
        if not EVASION_AVAILABLE or not self.interface:
            return ""
        
        randomizer = MACRandomizer(prefer_vendor=vendor)
        return randomizer.randomize_interface(self.interface, log_callback=log_callback)
    
    def start_wids_monitor(self, log_callback: Callable = None) -> bool:
        """Start WIDS detection monitoring"""
        if not EVASION_AVAILABLE or not self.interface:
            return False
        
        detector = WIDSDetector(self.interface)
        return detector.start_monitoring(log_callback)
    
    # ========================================================================
    # COLLECTION
    # ========================================================================
    
    def collect_pnl(self, duration: int = 60,
                    log_callback: Callable = None) -> Dict:
        """
        Collect Preferred Network Lists from nearby clients
        
        Returns: Dict with clients and their preferred networks
        """
        if not KARMA_AVAILABLE or not self.interface:
            return {}
        
        collector = PNLCollector(self.interface)
        collector.start_collection(log_callback=log_callback)
        
        import time
        time.sleep(duration)
        
        collector.stop_collection(log_callback)
        
        return {
            "clients": {
                mac: list(ssids) for mac, ssids in collector.pnl_data.items()
            },
            "popular_ssids": collector.get_popular_ssids()
        }


# ============================================================================
# INTERACTIVE MODE
# ============================================================================

def interactive_mode():
    """Interactive menu for Red Team WiFi operations"""
    print("\n" + "=" * 60)
    print("  Red Team Toolkit - Advanced WiFi Module")
    print("  Integration with PyAirgeddon")  
    print("=" * 60 + "\n")
    
    # Check requirements
    issues = check_requirements()
    if issues:
        print("[!] Requirements check:")
        for issue in issues:
            print(f"    - {issue}")
        print()
    
    modules = get_available_modules()
    print("[*] Available modules:")
    for name, available in modules.items():
        status = "✓" if available else "✗"
        print(f"    [{status}] {name}")
    print()
    
    interface = input("[?] Enter wireless interface (default: auto-detect): ").strip()
    
    toolkit = AdvancedWiFiToolkit(interface or None)
    print(f"[*] Using interface: {toolkit.interface or 'None detected'}")
    
    if not toolkit.interface:
        print("[!] No wireless interface available")
        return
    
    print("\n[*] Options:")
    print("  1. Network Scan (Stealth)")
    print("  2. Track Clients (PNL Collection)")
    print("  3. Security Analysis")
    print("  4. Karma Attack")
    print("  5. MANA Attack")
    print("  6. Setup Stealth Mode")
    print("  7. Randomize MAC")
    print("  0. Exit")
    
    def log(msg):
        print(msg)
    
    while True:
        choice = input("\n[?] Select option: ").strip()
        
        if choice == "0":
            toolkit.restore_interface(log)
            break
        
        elif choice == "1":
            duration = input("[?] Scan duration (default 30s): ").strip()
            duration = int(duration) if duration else 30
            print(f"\n[*] Scanning for {duration} seconds...")
            networks = toolkit.scan_networks(duration, stealth=True, log_callback=log)
            print(f"\n[+] Found {len(networks)} networks:")
            for net in sorted(networks, key=lambda x: x.get('signal', -100), reverse=True)[:15]:
                print(f"    {net.get('ssid', '<Hidden>'):32} "
                      f"{net.get('bssid', '')} "
                      f"Ch{net.get('channel', 0):2} "
                      f"{net.get('encryption', 'OPEN'):6} "
                      f"{net.get('signal', -100)}dBm")
        
        elif choice == "2":
            duration = input("[?] Track duration (default 60s): ").strip()
            duration = int(duration) if duration else 60
            print(f"\n[*] Tracking clients for {duration} seconds...")
            clients = toolkit.track_clients(duration, log)
            print(f"\n[+] Found {len(clients)} clients:")
            for client in clients[:15]:
                ssids = ", ".join(list(client.get('probed_ssids', []))[:3])
                print(f"    {client['mac']} ({client.get('vendor', 'Unknown')}) -> {ssids}")
        
        elif choice == "3":
            print("\n[*] Analyzing security issues...")
            issues = toolkit.analyze_security(log)
            if issues:
                for issue in issues:
                    print(f"\n  Network: {issue.get('ssid', '')} ({issue.get('bssid', '')})")
                    for vuln in issue.get('issues', []):
                        print(f"    [{vuln['severity']}] {vuln['issue']}: {vuln['description']}")
            else:
                print("[*] No security issues found (or no networks scanned yet)")
        
        elif choice == "4":
            channel = input("[?] Channel (default 6): ").strip()
            channel = int(channel) if channel else 6
            print("\n[*] Starting Karma attack (Ctrl+C to stop)...")
            if toolkit.start_karma(channel, log):
                try:
                    import time
                    while True:
                        time.sleep(5)
                        if toolkit.karma:
                            ssids = toolkit.karma.get_collected_ssids()
                            print(f"[*] Collected {len(ssids)} SSIDs")
                except KeyboardInterrupt:
                    result = toolkit.stop_karma(log)
                    print(f"\n[+] Final: {len(result.get('ssids_collected', []))} SSIDs")
        
        elif choice == "5":
            ssid = input("[?] SSID (default 'FreeWifi'): ").strip() or "FreeWifi"
            channel = input("[?] Channel (default 6): ").strip()
            channel = int(channel) if channel else 6
            loud = input("[?] Loud mode? (y/N): ").strip().lower() == 'y'
            print("\n[*] Starting MANA attack (Ctrl+C to stop)...")
            if toolkit.start_mana(ssid, channel, loud, log):
                try:
                    import time
                    while True:
                        time.sleep(5)
                except KeyboardInterrupt:
                    toolkit.stop_mana(log)
        
        elif choice == "6":
            level = input("[?] Stealth level 1-3 (default 2): ").strip()
            level = int(level) if level else 2
            toolkit.setup_stealth(level, log)
        
        elif choice == "7":
            vendor = input("[?] Vendor (apple/samsung/google/intel/random): ").strip()
            new_mac = toolkit.randomize_mac(vendor or None, log)
            if new_mac:
                print(f"[+] New MAC: {new_mac}")


if __name__ == "__main__":
    interactive_mode()
