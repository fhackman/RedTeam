#!/usr/bin/env python3
"""
Red Team Tools - DNS Enumeration
Comprehensive DNS reconnaissance tool
For authorized security testing only
"""

import sys
import os
import socket
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import *

try:
    import dns.resolver
    import dns.zone
    import dns.query
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class DNSEnumerator:
    """Comprehensive DNS enumeration tool"""
    
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "dns", "dns1", "dns2", "mx", "mx1", "mx2", "blog", "dev", "test", "admin",
        "portal", "vpn", "remote", "api", "app", "web", "secure", "login", "m",
        "mobile", "static", "cdn", "assets", "img", "images", "media", "video",
        "staging", "stage", "uat", "qa", "demo", "beta", "alpha", "old", "new",
        "shop", "store", "cart", "checkout", "pay", "payment", "billing",
        "support", "help", "docs", "wiki", "kb", "forum", "community",
        "git", "gitlab", "github", "svn", "repo", "jenkins", "ci", "cd",
        "monitor", "status", "health", "metrics", "logs", "elk", "grafana",
        "db", "database", "mysql", "postgres", "mongo", "redis", "cache",
        "auth", "oauth", "sso", "id", "identity", "ldap", "ad",
    ]
    
    def __init__(self, domain: str, timeout: float = 5.0):
        self.domain = domain.lower().strip()
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver() if DNS_AVAILABLE else None
        if self.resolver:
            self.resolver.timeout = timeout
            self.resolver.lifetime = timeout
    
    def get_all_records(self) -> Dict[str, List]:
        """Get all DNS records for domain"""
        records = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "SOA": [], "CNAME": []}
        
        for rtype in records.keys():
            try:
                answers = self.resolver.resolve(self.domain, rtype)
                if rtype == "MX":
                    records[rtype] = [{"priority": r.preference, "host": str(r.exchange).rstrip('.')} for r in answers]
                elif rtype == "SOA":
                    r = answers[0]
                    records[rtype] = [{"mname": str(r.mname), "serial": r.serial}]
                else:
                    records[rtype] = [str(r).rstrip('.').strip('"') for r in answers]
            except:
                pass
        
        return records
    
    def zone_transfer(self) -> Optional[List[str]]:
        """Attempt zone transfer"""
        records = []
        try:
            ns_records = self.resolver.resolve(self.domain, 'NS')
            for ns in ns_records:
                ns_addr = str(ns).rstrip('.')
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_addr, self.domain, timeout=self.timeout))
                    for name, node in zone.nodes.items():
                        records.append(str(name))
                    if records:
                        return records
                except:
                    pass
        except:
            pass
        return None
    
    def enumerate_subdomains(self, wordlist: List[str] = None, threads: int = 20) -> List[Dict]:
        """Enumerate subdomains"""
        if wordlist is None:
            wordlist = self.COMMON_SUBDOMAINS
        
        found = []
        
        def check_subdomain(subdomain: str) -> Optional[Dict]:
            fqdn = f"{subdomain}.{self.domain}"
            try:
                answers = self.resolver.resolve(fqdn, 'A')
                ips = [str(r) for r in answers]
                return {"subdomain": subdomain, "fqdn": fqdn, "ips": ips}
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
            
            for i, future in enumerate(as_completed(futures)):
                progress_bar(i + 1, len(wordlist), "  Enumerating")
                result = future.result()
                if result:
                    found.append(result)
        
        print()
        return found
    
    def reverse_lookup(self, ip: str) -> Optional[str]:
        """Reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None
    
    def print_results(self, records: Dict):
        """Print DNS records"""
        print(f"\n{C}{BRIGHT}═══ DNS Records: {self.domain} ═══{RESET}")
        
        for rtype, values in records.items():
            if values:
                print(f"\n{Y}{rtype} Records:{RESET}")
                for v in values[:10]:
                    if isinstance(v, dict):
                        print(f"  • {v}")
                    else:
                        print(f"  • {v}")


def interactive_mode():
    """Interactive DNS enumeration"""
    clear_screen()
    print_banner("DNS ENUM", font="small", color="cyan")
    
    if not DNS_AVAILABLE:
        error("dnspython not installed! Run: pip install dnspython")
        input(f"\n{C}Press Enter...{RESET}")
        return
    
    while True:
        print(f"\n{C}OPTIONS{RESET}")
        print(f"  {Y}[1]{RESET} Get All DNS Records")
        print(f"  {Y}[2]{RESET} Enumerate Subdomains")
        print(f"  {Y}[3]{RESET} Attempt Zone Transfer")
        print(f"  {Y}[4]{RESET} Reverse DNS Lookup")
        print(f"  {R}[0]{RESET} Back")
        
        choice = prompt("Select").strip()
        
        if choice == "0":
            break
        
        elif choice == "1":
            domain = prompt("Domain").strip()
            if domain:
                enum = DNSEnumerator(domain)
                records = enum.get_all_records()
                enum.print_results(records)
        
        elif choice == "2":
            domain = prompt("Domain").strip()
            if domain:
                enum = DNSEnumerator(domain)
                info(f"Enumerating subdomains for {domain}...")
                found = enum.enumerate_subdomains()
                
                if found:
                    print(f"\n{G}Found {len(found)} subdomains:{RESET}")
                    for sub in found:
                        print(f"  • {sub['fqdn']} -> {', '.join(sub['ips'])}")
                else:
                    warning("No subdomains found")
        
        elif choice == "3":
            domain = prompt("Domain").strip()
            if domain:
                enum = DNSEnumerator(domain)
                info("Attempting zone transfer...")
                records = enum.zone_transfer()
                
                if records:
                    success(f"Zone transfer successful! Found {len(records)} records")
                    for r in records[:20]:
                        print(f"  • {r}")
                else:
                    warning("Zone transfer failed (as expected on most servers)")
        
        elif choice == "4":
            ip = prompt("IP Address").strip()
            if ip:
                enum = DNSEnumerator("")
                hostname = enum.reverse_lookup(ip)
                if hostname:
                    success(f"Hostname: {hostname}")
                else:
                    error("No reverse DNS record")
    
    input(f"\n{C}Press Enter...{RESET}")


if __name__ == "__main__":
    interactive_mode()
