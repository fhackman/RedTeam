#!/usr/bin/env python3
"""
Red Team Tools - WHOIS Lookup
Domain and IP information gathering
For educational and authorized security testing only
"""

import sys
import os
import socket
import json
from typing import Dict, Optional, List
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import *

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class WhoisLookup:
    """WHOIS and domain information lookup tool"""
    
    # IP Geolocation API (free tier)
    GEOIP_API = "http://ip-api.com/json/{ip}"
    
    def __init__(self):
        """Initialize WHOIS lookup tool"""
        self.results: Dict = {}
    
    def lookup_domain(self, domain: str) -> Dict:
        """Perform WHOIS lookup on domain"""
        if not WHOIS_AVAILABLE:
            return {"error": "python-whois not installed"}
        
        result = {
            "domain": domain,
            "type": "domain",
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name_servers": [],
            "status": [],
            "registrant": {},
            "raw": None,
        }
        
        try:
            w = whois.whois(domain)
            
            result["registrar"] = w.registrar
            result["creation_date"] = self._format_date(w.creation_date)
            result["expiration_date"] = self._format_date(w.expiration_date)
            result["updated_date"] = self._format_date(w.updated_date)
            result["name_servers"] = self._to_list(w.name_servers)
            result["status"] = self._to_list(w.status)
            result["raw"] = w.text if hasattr(w, 'text') else str(w)
            
            # Registrant info (if available)
            result["registrant"] = {
                "name": getattr(w, 'name', None),
                "org": getattr(w, 'org', None),
                "country": getattr(w, 'country', None),
                "state": getattr(w, 'state', None),
                "city": getattr(w, 'city', None),
                "email": getattr(w, 'emails', None),
            }
            
        except Exception as e:
            result["error"] = str(e)
        
        self.results[domain] = result
        return result
    
    def lookup_ip(self, ip: str) -> Dict:
        """Lookup IP address information"""
        result = {
            "ip": ip,
            "type": "ip",
            "hostname": None,
            "geolocation": {},
            "dns_records": {},
        }
        
        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            result["hostname"] = hostname
        except:
            pass
        
        # Geolocation
        if REQUESTS_AVAILABLE:
            try:
                response = requests.get(
                    self.GEOIP_API.format(ip=ip),
                    timeout=10
                )
                if response.status_code == 200:
                    geo = response.json()
                    result["geolocation"] = {
                        "country": geo.get("country"),
                        "country_code": geo.get("countryCode"),
                        "region": geo.get("regionName"),
                        "city": geo.get("city"),
                        "zip": geo.get("zip"),
                        "lat": geo.get("lat"),
                        "lon": geo.get("lon"),
                        "timezone": geo.get("timezone"),
                        "isp": geo.get("isp"),
                        "org": geo.get("org"),
                        "as": geo.get("as"),
                    }
            except Exception as e:
                result["geolocation"]["error"] = str(e)
        
        self.results[ip] = result
        return result
    
    def get_dns_records(self, domain: str) -> Dict:
        """Get all DNS records for domain"""
        if not DNS_AVAILABLE:
            return {"error": "dnspython not installed"}
        
        records = {
            "domain": domain,
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "SOA": None,
            "CNAME": [],
        }
        
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                
                if rtype == "MX":
                    records[rtype] = [
                        {"priority": r.preference, "host": str(r.exchange).rstrip('.')}
                        for r in answers
                    ]
                elif rtype == "SOA":
                    r = answers[0]
                    records[rtype] = {
                        "mname": str(r.mname).rstrip('.'),
                        "rname": str(r.rname).rstrip('.'),
                        "serial": r.serial,
                        "refresh": r.refresh,
                        "retry": r.retry,
                        "expire": r.expire,
                        "minimum": r.minimum,
                    }
                else:
                    records[rtype] = [str(r).rstrip('.').strip('"') for r in answers]
                    
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                records["error"] = "Domain does not exist"
                break
            except Exception:
                pass
        
        return records
    
    def check_dnssec(self, domain: str) -> Dict:
        """Check DNSSEC status"""
        if not DNS_AVAILABLE:
            return {"enabled": False, "error": "dnspython not installed"}
        
        result = {
            "domain": domain,
            "dnssec_enabled": False,
            "dnskey": [],
            "ds": [],
        }
        
        try:
            # Check for DNSKEY records
            answers = dns.resolver.resolve(domain, 'DNSKEY')
            result["dnskey"] = [str(r) for r in answers]
            result["dnssec_enabled"] = True
        except:
            pass
        
        try:
            # Check for DS records
            answers = dns.resolver.resolve(domain, 'DS')
            result["ds"] = [str(r) for r in answers]
        except:
            pass
        
        return result
    
    def reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None
    
    def _format_date(self, date_val) -> Optional[str]:
        """Format date value to string"""
        if date_val is None:
            return None
        if isinstance(date_val, list):
            date_val = date_val[0] if date_val else None
        if isinstance(date_val, datetime):
            return date_val.strftime("%Y-%m-%d %H:%M:%S")
        return str(date_val)
    
    def _to_list(self, val) -> List:
        """Convert value to list"""
        if val is None:
            return []
        if isinstance(val, list):
            return [str(v).lower() if isinstance(v, str) else str(v) for v in val]
        return [str(val)]
    
    def print_domain_result(self, result: Dict):
        """Print domain WHOIS result"""
        if "error" in result and result.get("registrar") is None:
            error(f"Lookup failed: {result['error']}")
            return
        
        print(f"\n{C}{BRIGHT}═══ WHOIS: {result['domain']} ═══{RESET}")
        
        if result.get("registrar"):
            print(f"\n{Y}Registration Info:{RESET}")
            print(f"  Registrar:    {result['registrar']}")
            print(f"  Created:      {result['creation_date'] or 'N/A'}")
            print(f"  Expires:      {result['expiration_date'] or 'N/A'}")
            print(f"  Updated:      {result['updated_date'] or 'N/A'}")
        
        if result.get("name_servers"):
            print(f"\n{Y}Name Servers:{RESET}")
            for ns in result["name_servers"][:5]:
                print(f"  • {ns}")
        
        if result.get("status"):
            print(f"\n{Y}Status:{RESET}")
            for status in result["status"][:5]:
                # Extract status name without URL
                status_name = status.split()[0] if status else status
                print(f"  • {status_name}")
        
        registrant = result.get("registrant", {})
        if any(registrant.values()):
            print(f"\n{Y}Registrant:{RESET}")
            if registrant.get("name"):
                print(f"  Name:     {registrant['name']}")
            if registrant.get("org"):
                print(f"  Org:      {registrant['org']}")
            if registrant.get("country"):
                print(f"  Country:  {registrant['country']}")
            if registrant.get("email"):
                emails = registrant['email']
                if isinstance(emails, list):
                    for email in emails[:3]:
                        print(f"  Email:    {email}")
                else:
                    print(f"  Email:    {emails}")
    
    def print_ip_result(self, result: Dict):
        """Print IP lookup result"""
        print(f"\n{C}{BRIGHT}═══ IP Info: {result['ip']} ═══{RESET}")
        
        if result.get("hostname"):
            print(f"\n{Y}Hostname:{RESET} {result['hostname']}")
        
        geo = result.get("geolocation", {})
        if geo and "error" not in geo:
            print(f"\n{Y}Geolocation:{RESET}")
            print(f"  Country:  {geo.get('country', 'N/A')} ({geo.get('country_code', '')})")
            print(f"  Region:   {geo.get('region', 'N/A')}")
            print(f"  City:     {geo.get('city', 'N/A')}")
            if geo.get("lat") and geo.get("lon"):
                print(f"  Coords:   {geo['lat']}, {geo['lon']}")
            print(f"  Timezone: {geo.get('timezone', 'N/A')}")
            print(f"\n{Y}Network:{RESET}")
            print(f"  ISP:      {geo.get('isp', 'N/A')}")
            print(f"  Org:      {geo.get('org', 'N/A')}")
            print(f"  AS:       {geo.get('as', 'N/A')}")
    
    def print_dns_result(self, result: Dict):
        """Print DNS records result"""
        print(f"\n{C}{BRIGHT}═══ DNS Records: {result['domain']} ═══{RESET}")
        
        if "error" in result:
            error(result["error"])
            return
        
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
        
        for rtype in record_types:
            records = result.get(rtype, [])
            if records:
                print(f"\n{Y}{rtype} Records:{RESET}")
                for r in records[:10]:
                    if isinstance(r, dict):
                        # MX records
                        print(f"  [{r.get('priority', 0):3}] {r.get('host', '')}")
                    else:
                        print(f"  • {r}")
        
        soa = result.get("SOA")
        if soa:
            print(f"\n{Y}SOA Record:{RESET}")
            print(f"  Primary NS: {soa.get('mname', 'N/A')}")
            print(f"  Admin:      {soa.get('rname', 'N/A')}")
            print(f"  Serial:     {soa.get('serial', 'N/A')}")


def interactive_mode():
    """Interactive mode for WHOIS lookup"""
    clear_screen()
    print_banner("WHOIS LOOKUP", font="slant", color="cyan")
    
    print(f"{Y}⚠  For authorized testing only!{RESET}\n")
    
    lookup = WhoisLookup()
    
    while True:
        print(f"\n{C}{BRIGHT}OPTIONS{RESET}")
        print(f"{C}{'─' * 40}{RESET}")
        print(f"  {Y}[1]{RESET} Domain WHOIS Lookup")
        print(f"  {Y}[2]{RESET} IP Address Lookup")
        print(f"  {Y}[3]{RESET} DNS Records Lookup")
        print(f"  {Y}[4]{RESET} Reverse DNS Lookup")
        print(f"  {Y}[5]{RESET} Check DNSSEC")
        print(f"  {Y}[6]{RESET} Full Domain Scan")
        print(f"  {R}[0]{RESET} Back to Main Menu")
        print()
        
        try:
            choice = prompt("Select option").strip()
            
            if choice == "0":
                break
            
            elif choice == "1":
                if not WHOIS_AVAILABLE:
                    error("python-whois not installed!")
                    print("Run: pip install python-whois")
                    continue
                
                domain = prompt("Enter domain (e.g., google.com)").strip()
                if not domain:
                    continue
                
                info(f"Looking up {domain}...")
                result = lookup.lookup_domain(domain)
                lookup.print_domain_result(result)
            
            elif choice == "2":
                ip = prompt("Enter IP address").strip()
                if not ip:
                    continue
                
                info(f"Looking up {ip}...")
                result = lookup.lookup_ip(ip)
                lookup.print_ip_result(result)
            
            elif choice == "3":
                if not DNS_AVAILABLE:
                    error("dnspython not installed!")
                    print("Run: pip install dnspython")
                    continue
                
                domain = prompt("Enter domain").strip()
                if not domain:
                    continue
                
                info(f"Getting DNS records for {domain}...")
                result = lookup.get_dns_records(domain)
                lookup.print_dns_result(result)
            
            elif choice == "4":
                ip = prompt("Enter IP address").strip()
                if not ip:
                    continue
                
                hostname = lookup.reverse_dns(ip)
                if hostname:
                    success(f"Hostname: {hostname}")
                else:
                    error("No reverse DNS record found")
            
            elif choice == "5":
                if not DNS_AVAILABLE:
                    error("dnspython not installed!")
                    continue
                
                domain = prompt("Enter domain").strip()
                if not domain:
                    continue
                
                result = lookup.check_dnssec(domain)
                if result.get("dnssec_enabled"):
                    success(f"DNSSEC is enabled for {domain}")
                else:
                    warning(f"DNSSEC is NOT enabled for {domain}")
            
            elif choice == "6":
                domain = prompt("Enter domain for full scan").strip()
                if not domain:
                    continue
                
                print(f"\n{C}Running full domain scan...{RESET}\n")
                
                # WHOIS
                if WHOIS_AVAILABLE:
                    info("Getting WHOIS data...")
                    whois_result = lookup.lookup_domain(domain)
                    lookup.print_domain_result(whois_result)
                
                # DNS
                if DNS_AVAILABLE:
                    info("Getting DNS records...")
                    dns_result = lookup.get_dns_records(domain)
                    lookup.print_dns_result(dns_result)
                    
                    # DNSSEC
                    info("Checking DNSSEC...")
                    dnssec = lookup.check_dnssec(domain)
                    if dnssec.get("dnssec_enabled"):
                        success("DNSSEC: Enabled")
                    else:
                        warning("DNSSEC: Not enabled")
                
                # Get IP and lookup
                try:
                    ip = socket.gethostbyname(domain)
                    info(f"IP lookup for {ip}...")
                    ip_result = lookup.lookup_ip(ip)
                    lookup.print_ip_result(ip_result)
                except:
                    pass
        
        except KeyboardInterrupt:
            print()
            if confirm("Exit WHOIS Lookup?"):
                break
        except Exception as e:
            error(f"Error: {e}")
    
    print()
    input(f"{C}Press Enter to continue...{RESET}")


if __name__ == "__main__":
    interactive_mode()
