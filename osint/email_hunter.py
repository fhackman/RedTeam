#!/usr/bin/env python3
"""
Red Team Tools - Email Hunter
Email enumeration and harvesting tool
For educational and authorized security testing only
"""

import re
import sys
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Dict, Optional
from urllib.parse import urlparse, urljoin

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import *

try:
    import requests
    from bs4 import BeautifulSoup
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class EmailHunter:
    """Email enumeration and harvesting tool"""
    
    # Common email patterns
    EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    
    # Common email formats
    EMAIL_FORMATS = [
        "{first}.{last}@{domain}",
        "{first}{last}@{domain}",
        "{f}{last}@{domain}",
        "{first}_{last}@{domain}",
        "{first}-{last}@{domain}",
        "{last}.{first}@{domain}",
        "{f}.{last}@{domain}",
        "{first}@{domain}",
        "{last}@{domain}",
    ]
    
    # Common role-based emails
    ROLE_EMAILS = [
        "admin", "administrator", "info", "contact", "support",
        "help", "sales", "marketing", "hr", "careers", "jobs",
        "press", "media", "legal", "billing", "accounts",
        "webmaster", "postmaster", "hostmaster", "abuse",
        "security", "noreply", "no-reply", "newsletter",
        "feedback", "enquiries", "office", "reception",
    ]
    
    def __init__(self, domain: str, timeout: float = 10.0):
        """Initialize email hunter"""
        self.domain = domain.lower().strip()
        self.timeout = timeout
        self.session = requests.Session() if REQUESTS_AVAILABLE else None
        self.found_emails: Set[str] = set()
        self.verified_emails: Set[str] = set()
        self.mx_records: List[str] = []
        
        if self.session:
            self.session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })
    
    def get_mx_records(self) -> List[str]:
        """Get MX records for domain"""
        if not DNS_AVAILABLE:
            warning("dnspython not available - skipping MX lookup")
            return []
        
        try:
            answers = dns.resolver.resolve(self.domain, 'MX')
            self.mx_records = [str(r.exchange).rstrip('.') for r in answers]
            return self.mx_records
        except Exception as e:
            error(f"MX lookup failed: {e}")
            return []
    
    def extract_emails_from_text(self, text: str) -> Set[str]:
        """Extract emails from text content"""
        emails = set()
        matches = re.findall(self.EMAIL_REGEX, text, re.IGNORECASE)
        
        for email in matches:
            email = email.lower()
            # Filter to target domain or all domains
            if self.domain in email or not self.domain:
                emails.add(email)
        
        return emails
    
    def scrape_website(self, url: str = None, max_pages: int = 10) -> Set[str]:
        """Scrape website for email addresses"""
        if not REQUESTS_AVAILABLE:
            error("requests/beautifulsoup4 not available")
            return set()
        
        if not url:
            url = f"https://www.{self.domain}"
        
        visited = set()
        to_visit = [url]
        found_emails = set()
        
        info(f"Scraping {url} for emails...")
        
        while to_visit and len(visited) < max_pages:
            current_url = to_visit.pop(0)
            
            if current_url in visited:
                continue
            
            visited.add(current_url)
            
            try:
                response = self.session.get(current_url, timeout=self.timeout, verify=False)
                
                # Extract emails from response
                emails = self.extract_emails_from_text(response.text)
                found_emails.update(emails)
                
                # Parse links for more pages
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(current_url, href)
                    
                    # Only follow links on same domain
                    if self.domain in urlparse(full_url).netloc:
                        if full_url not in visited:
                            to_visit.append(full_url)
                
            except Exception as e:
                pass  # Skip failed pages
            
            progress_bar(len(visited), max_pages, "  Scraping")
        
        print()
        self.found_emails.update(found_emails)
        return found_emails
    
    def search_google(self, num_results: int = 50) -> Set[str]:
        """Search Google for emails (respects rate limits)"""
        if not REQUESTS_AVAILABLE:
            return set()
        
        # Google dorks for email discovery
        dorks = [
            f'site:{self.domain} "@{self.domain}"',
            f'"{self.domain}" email',
            f'intext:"@{self.domain}"',
        ]
        
        found_emails = set()
        info("Searching for emails (limited due to rate limits)...")
        
        # Note: This is a simplified version. Real implementation
        # would use proper Google API or respect robots.txt
        for dork in dorks:
            try:
                # This is a placeholder - real implementation would
                # use Google Custom Search API
                warning(f"Google dork (manual): {dork}")
            except Exception as e:
                pass
        
        self.found_emails.update(found_emails)
        return found_emails
    
    def generate_emails(self, names: List[Dict[str, str]]) -> Set[str]:
        """Generate possible emails from names"""
        generated = set()
        
        for name_info in names:
            first = name_info.get('first', '').lower()
            last = name_info.get('last', '').lower()
            
            if not first or not last:
                continue
            
            f = first[0] if first else ''
            l = last[0] if last else ''
            
            for pattern in self.EMAIL_FORMATS:
                try:
                    email = pattern.format(
                        first=first,
                        last=last,
                        f=f,
                        l=l,
                        domain=self.domain
                    )
                    generated.add(email)
                except:
                    pass
        
        return generated
    
    def generate_role_emails(self) -> Set[str]:
        """Generate common role-based emails"""
        return {f"{role}@{self.domain}" for role in self.ROLE_EMAILS}
    
    def verify_email_mx(self, email: str) -> bool:
        """Verify email domain has MX records"""
        if not DNS_AVAILABLE:
            return True  # Can't verify, assume valid
        
        domain = email.split('@')[1]
        try:
            dns.resolver.resolve(domain, 'MX')
            return True
        except:
            return False
    
    def verify_email_smtp(self, email: str) -> Optional[bool]:
        """
        Attempt SMTP verification (VRFY command)
        Note: Most servers disable this
        """
        # This is often blocked - placeholder for demonstration
        return None
    
    def run_full_scan(self, include_role_based: bool = True) -> Dict:
        """Run full email enumeration"""
        results = {
            "domain": self.domain,
            "mx_records": [],
            "found_emails": [],
            "role_emails": [],
            "total": 0,
        }
        
        # Get MX records
        info(f"Scanning domain: {self.domain}")
        mx_records = self.get_mx_records()
        results["mx_records"] = mx_records
        
        if mx_records:
            success(f"Found {len(mx_records)} MX record(s)")
            for mx in mx_records:
                print(f"    → {mx}")
        
        # Scrape website
        website_emails = self.scrape_website()
        results["found_emails"] = list(website_emails)
        
        if website_emails:
            success(f"Found {len(website_emails)} email(s) on website")
        
        # Generate role-based emails
        if include_role_based:
            role_emails = self.generate_role_emails()
            results["role_emails"] = list(role_emails)
            info(f"Generated {len(role_emails)} role-based emails")
        
        # Total unique
        all_emails = self.found_emails.copy()
        if include_role_based:
            all_emails.update(results["role_emails"])
        
        results["total"] = len(all_emails)
        
        return results
    
    def print_results(self, results: Dict):
        """Print scan results"""
        print(f"\n{C}{BRIGHT}═══ Email Hunter Results ═══{RESET}")
        print(f"{C}Domain:{RESET} {results['domain']}")
        
        if results['mx_records']:
            print(f"\n{Y}MX Records:{RESET}")
            for mx in results['mx_records']:
                print(f"  • {mx}")
        
        if results['found_emails']:
            print(f"\n{G}Found Emails ({len(results['found_emails'])}):{RESET}")
            for email in sorted(results['found_emails']):
                print(f"  • {email}")
        
        if results['role_emails']:
            print(f"\n{B}Role-Based Emails (Generated):{RESET}")
            for email in sorted(results['role_emails'])[:10]:
                print(f"  • {email}")
            if len(results['role_emails']) > 10:
                print(f"  ... and {len(results['role_emails']) - 10} more")
        
        print(f"\n{C}Total unique emails: {results['total']}{RESET}")


def interactive_mode():
    """Interactive mode for email hunting"""
    clear_screen()
    print_banner("EMAIL HUNTER", font="slant", color="cyan")
    
    print(f"{Y}⚠  For authorized testing only!{RESET}\n")
    
    if not REQUESTS_AVAILABLE:
        error("Required packages not installed!")
        print("Run: pip install requests beautifulsoup4 dnspython")
        return
    
    while True:
        print(f"\n{C}{BRIGHT}OPTIONS{RESET}")
        print(f"{C}{'─' * 40}{RESET}")
        print(f"  {Y}[1]{RESET} Scan Domain for Emails")
        print(f"  {Y}[2]{RESET} Generate Role-Based Emails")
        print(f"  {Y}[3]{RESET} Generate Emails from Names")
        print(f"  {Y}[4]{RESET} Check MX Records")
        print(f"  {R}[0]{RESET} Back to Main Menu")
        print()
        
        try:
            choice = prompt("Select option").strip()
            
            if choice == "0":
                break
            
            elif choice == "1":
                domain = prompt("Enter domain (e.g., example.com)").strip()
                if not domain:
                    error("Domain required")
                    continue
                
                hunter = EmailHunter(domain)
                results = hunter.run_full_scan()
                hunter.print_results(results)
            
            elif choice == "2":
                domain = prompt("Enter domain").strip()
                if not domain:
                    error("Domain required")
                    continue
                
                hunter = EmailHunter(domain)
                emails = hunter.generate_role_emails()
                
                print(f"\n{G}Generated Role-Based Emails:{RESET}")
                for email in sorted(emails):
                    print(f"  • {email}")
            
            elif choice == "3":
                domain = prompt("Enter domain").strip()
                if not domain:
                    continue
                
                names = []
                print("Enter names (first last), empty line to finish:")
                while True:
                    name = input("  ").strip()
                    if not name:
                        break
                    parts = name.split()
                    if len(parts) >= 2:
                        names.append({"first": parts[0], "last": parts[-1]})
                
                if names:
                    hunter = EmailHunter(domain)
                    emails = hunter.generate_emails(names)
                    
                    print(f"\n{G}Generated Emails:{RESET}")
                    for email in sorted(emails):
                        print(f"  • {email}")
            
            elif choice == "4":
                domain = prompt("Enter domain").strip()
                if not domain:
                    continue
                
                hunter = EmailHunter(domain)
                mx_records = hunter.get_mx_records()
                
                if mx_records:
                    print(f"\n{G}MX Records for {domain}:{RESET}")
                    for mx in mx_records:
                        print(f"  • {mx}")
                else:
                    error("No MX records found")
        
        except KeyboardInterrupt:
            print()
            if confirm("Exit Email Hunter?"):
                break
        except Exception as e:
            error(f"Error: {e}")
    
    print()
    input(f"{C}Press Enter to continue...{RESET}")


if __name__ == "__main__":
    interactive_mode()
