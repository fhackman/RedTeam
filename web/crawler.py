#!/usr/bin/env python3
"""
Red Team Tools - Web Crawler
Web spider for reconnaissance
For authorized security testing only
"""

import sys
import os
import re
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Set, Optional
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import *

try:
    import requests
    from bs4 import BeautifulSoup
    AVAILABLE = True
except ImportError:
    AVAILABLE = False


class WebCrawler:
    """Web crawler for reconnaissance"""
    
    def __init__(self, base_url: str, max_pages: int = 100, timeout: float = 10.0):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.timeout = timeout
        
        self.visited: Set[str] = set()
        self.pages: List[Dict] = []
        self.forms: List[Dict] = []
        self.links: Set[str] = set()
        self.external_links: Set[str] = set()
        self.emails: Set[str] = set()
        self.comments: List[str] = []
        self.scripts: Set[str] = set()
        self.params: Dict[str, Set[str]] = defaultdict(set)
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.session.verify = False
    
    def crawl(self) -> Dict:
        """Start crawling"""
        to_visit = [self.base_url]
        
        while to_visit and len(self.visited) < self.max_pages:
            url = to_visit.pop(0)
            
            if url in self.visited:
                continue
            
            if not self._is_same_domain(url):
                self.external_links.add(url)
                continue
            
            self.visited.add(url)
            progress_bar(len(self.visited), self.max_pages, "  Crawling")
            
            try:
                response = self.session.get(url, timeout=self.timeout)
                content_type = response.headers.get('Content-Type', '')
                
                if 'text/html' not in content_type:
                    continue
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract data
                page_links = self._extract_links(soup, url)
                to_visit.extend([l for l in page_links if l not in self.visited])
                
                self._extract_forms(soup, url)
                self._extract_emails(response.text)
                self._extract_comments(response.text)
                self._extract_scripts(soup, url)
                self._extract_params(url)
                
                self.pages.append({
                    "url": url, "status": response.status_code,
                    "title": soup.title.string if soup.title else ""
                })
                
            except Exception:
                pass
        
        print()
        return self.get_results()
    
    def _is_same_domain(self, url: str) -> bool:
        """Check if URL is same domain"""
        return self.domain in urlparse(url).netloc
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract links from page"""
        links = []
        for tag in soup.find_all(['a', 'link'], href=True):
            href = tag['href']
            full_url = urljoin(base_url, href)
            
            # Clean URL
            parsed = urlparse(full_url)
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            if self._is_same_domain(clean_url):
                links.append(clean_url)
                self.links.add(clean_url)
            else:
                self.external_links.add(full_url)
        
        return links
    
    def _extract_forms(self, soup: BeautifulSoup, page_url: str):
        """Extract forms from page"""
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').upper()
            
            inputs = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                inputs.append({
                    "name": inp.get('name', ''),
                    "type": inp.get('type', 'text'),
                    "id": inp.get('id', '')
                })
            
            self.forms.append({
                "page": page_url,
                "action": urljoin(page_url, action),
                "method": method,
                "inputs": inputs
            })
    
    def _extract_emails(self, text: str):
        """Extract emails from text"""
        pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        matches = re.findall(pattern, text)
        self.emails.update(matches)
    
    def _extract_comments(self, text: str):
        """Extract HTML comments"""
        pattern = r'<!--(.*?)-->'
        matches = re.findall(pattern, text, re.DOTALL)
        for comment in matches:
            comment = comment.strip()
            if comment and len(comment) < 500:
                self.comments.append(comment)
    
    def _extract_scripts(self, soup: BeautifulSoup, base_url: str):
        """Extract script sources"""
        for script in soup.find_all('script', src=True):
            src = script['src']
            self.scripts.add(urljoin(base_url, src))
    
    def _extract_params(self, url: str):
        """Extract URL parameters"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in params.keys():
            self.params[param].add(url)
    
    def get_results(self) -> Dict:
        """Get crawl results"""
        return {
            "base_url": self.base_url,
            "pages_crawled": len(self.visited),
            "pages": self.pages,
            "forms": self.forms,
            "links": list(self.links),
            "external_links": list(self.external_links),
            "emails": list(self.emails),
            "scripts": list(self.scripts),
            "params": {k: list(v) for k, v in self.params.items()},
            "comments": self.comments[:50],
        }
    
    def print_results(self):
        """Print crawl summary"""
        print(f"\n{C}{BRIGHT}═══ Crawl Results: {self.domain} ═══{RESET}")
        
        print(f"\n{Y}Summary:{RESET}")
        print(f"  Pages crawled:    {len(self.visited)}")
        print(f"  Forms found:      {len(self.forms)}")
        print(f"  External links:   {len(self.external_links)}")
        print(f"  Scripts:          {len(self.scripts)}")
        print(f"  Emails found:     {len(self.emails)}")
        print(f"  URL parameters:   {len(self.params)}")
        
        if self.forms:
            print(f"\n{Y}Forms:{RESET}")
            for form in self.forms[:10]:
                print(f"  [{form['method']}] {form['action']}")
                for inp in form['inputs'][:5]:
                    print(f"    → {inp['name']} ({inp['type']})")
        
        if self.params:
            print(f"\n{Y}URL Parameters (potential injection points):{RESET}")
            for param in list(self.params.keys())[:10]:
                print(f"  • {param}")
        
        if self.emails:
            print(f"\n{Y}Emails:{RESET}")
            for email in list(self.emails)[:10]:
                print(f"  • {email}")
        
        if self.comments:
            print(f"\n{Y}HTML Comments (first 5):{RESET}")
            for comment in self.comments[:5]:
                print(f"  <!-- {comment[:80]}... -->")


def interactive_mode():
    """Interactive web crawling"""
    clear_screen()
    print_banner("WEB CRAWLER", font="small", color="cyan")
    
    if not AVAILABLE:
        error("Required packages not installed!")
        print("Run: pip install requests beautifulsoup4")
        input(f"\n{C}Press Enter...{RESET}")
        return
    
    while True:
        print(f"\n{C}OPTIONS{RESET}")
        print(f"  {Y}[1]{RESET} Crawl Website")
        print(f"  {Y}[2]{RESET} Extract Forms Only")
        print(f"  {Y}[3]{RESET} Find Emails")
        print(f"  {R}[0]{RESET} Back")
        
        choice = prompt("Select").strip()
        
        if choice == "0":
            break
        
        elif choice == "1":
            url = prompt("Target URL").strip()
            if not url.startswith('http'):
                url = f"https://{url}"
            
            max_pages = int(prompt("Max pages [50]").strip() or "50")
            
            crawler = WebCrawler(url, max_pages)
            info(f"Crawling {url}...")
            crawler.crawl()
            crawler.print_results()
        
        elif choice == "2":
            url = prompt("Target URL").strip()
            if not url.startswith('http'):
                url = f"https://{url}"
            
            crawler = WebCrawler(url, max_pages=20)
            crawler.crawl()
            
            if crawler.forms:
                print(f"\n{G}Found {len(crawler.forms)} forms:{RESET}")
                for form in crawler.forms:
                    print(f"\n  {Y}[{form['method']}]{RESET} {form['action']}")
                    for inp in form['inputs']:
                        print(f"    • {inp['name']} ({inp['type']})")
            else:
                warning("No forms found")
        
        elif choice == "3":
            url = prompt("Target URL").strip()
            if not url.startswith('http'):
                url = f"https://{url}"
            
            crawler = WebCrawler(url, max_pages=30)
            crawler.crawl()
            
            if crawler.emails:
                print(f"\n{G}Found {len(crawler.emails)} emails:{RESET}")
                for email in crawler.emails:
                    print(f"  • {email}")
            else:
                warning("No emails found")
    
    input(f"\n{C}Press Enter...{RESET}")


if __name__ == "__main__":
    interactive_mode()
