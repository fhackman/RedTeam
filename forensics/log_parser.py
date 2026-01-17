#!/usr/bin/env python3
"""
Red Team Tools - Log Parser
Security log analysis for incident response
For authorized security testing and incident analysis
"""

import sys
import os
import re
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import *


class LogParser:
    """Multi-format log parser for security analysis"""
    
    # Common log patterns
    PATTERNS = {
        "apache_combined": r'(?P<ip>\d+\.\d+\.\d+\.\d+).*\[(?P<datetime>[^\]]+)\] "(?P<method>\w+) (?P<path>[^\s]+).*?" (?P<status>\d+)',
        "apache_error": r'\[(?P<datetime>[^\]]+)\] \[(?P<level>\w+)\].*?(?P<message>.+)',
        "nginx": r'(?P<ip>\d+\.\d+\.\d+\.\d+).*\[(?P<datetime>[^\]]+)\] "(?P<method>\w+) (?P<path>[^\s]+)',
        "syslog": r'(?P<datetime>\w+\s+\d+\s+\d+:\d+:\d+).*?(?P<host>\S+)\s+(?P<service>\S+?)(\[\d+\])?:\s*(?P<message>.+)',
        "auth_log": r'(?P<datetime>\w+\s+\d+\s+\d+:\d+:\d+).*?(?P<message>.*?(Failed|Accepted|Invalid|session).*)',
        "windows_security": r'(?P<datetime>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?(?P<event_id>\d{4}).*?(?P<message>.+)',
    }
    
    # Suspicious patterns to detect
    SUSPICIOUS_PATTERNS = {
        "sql_injection": [
            r"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|--\s*$|;\s*drop\s+table)",
            r"(?i)(select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from)",
        ],
        "xss": [
            r"(?i)(<script|javascript:|onerror\s*=|onload\s*=)",
            r"(?i)(alert\s*\(|document\.cookie|eval\s*\()",
        ],
        "path_traversal": [
            r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)",
            r"(?i)(etc/passwd|etc/shadow|windows/system32)",
        ],
        "command_injection": [
            r"(\||\;|\`|\$\(|&&|\|\|).*?(cat|ls|dir|whoami|id|pwd|wget|curl)",
        ],
        "brute_force": [
            r"(?i)(failed\s+password|authentication\s+failure|invalid\s+user)",
        ],
        "scanning": [
            r"(?i)(nikto|sqlmap|nmap|masscan|gobuster|dirb|wpscan)",
        ],
    }
    
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.entries: List[Dict] = []
        self.suspicious_entries: List[Dict] = []
        self.stats: Dict = {}
    
    def parse_log(self, log_type: str = "auto", max_lines: int = 10000) -> List[Dict]:
        """Parse log file"""
        if not os.path.exists(self.log_path):
            error(f"Log file not found: {self.log_path}")
            return []
        
        self.entries = []
        
        try:
            with open(self.log_path, 'r', errors='ignore') as f:
                lines = f.readlines()[:max_lines]
        except Exception as e:
            error(f"Error reading log: {e}")
            return []
        
        # Auto-detect log type
        if log_type == "auto":
            log_type = self._detect_log_type(lines[:10])
        
        pattern = self.PATTERNS.get(log_type)
        if not pattern:
            warning(f"Unknown log type, using raw parsing")
            pattern = r'(?P<line>.+)'
        
        regex = re.compile(pattern)
        
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            
            match = regex.search(line)
            if match:
                entry = match.groupdict()
                entry['line_num'] = i + 1
                entry['raw'] = line
                self.entries.append(entry)
            else:
                self.entries.append({'line_num': i + 1, 'raw': line})
        
        return self.entries
    
    def _detect_log_type(self, sample_lines: List[str]) -> str:
        """Auto-detect log format"""
        sample = '\n'.join(sample_lines)
        
        if re.search(r'\d+\.\d+\.\d+\.\d+.*\[.*\] "GET|POST', sample):
            return "apache_combined"
        if re.search(r'\[error\]|\[warn\]|\[notice\]', sample, re.I):
            return "apache_error"
        if re.search(r'sshd|sudo|su\[|pam_', sample):
            return "auth_log"
        if re.search(r'\w{3}\s+\d+\s+\d+:\d+:\d+', sample):
            return "syslog"
        
        return "syslog"
    
    def detect_suspicious(self) -> List[Dict]:
        """Detect suspicious patterns in log entries"""
        self.suspicious_entries = []
        
        for entry in self.entries:
            raw = entry.get('raw', '')
            path = entry.get('path', '')
            message = entry.get('message', '')
            
            check_content = f"{raw} {path} {message}"
            
            for attack_type, patterns in self.SUSPICIOUS_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, check_content, re.I):
                        suspicious = entry.copy()
                        suspicious['attack_type'] = attack_type
                        suspicious['matched_pattern'] = pattern[:50]
                        self.suspicious_entries.append(suspicious)
                        break
        
        return self.suspicious_entries
    
    def get_statistics(self) -> Dict:
        """Calculate log statistics"""
        self.stats = {
            "total_entries": len(self.entries),
            "suspicious_count": len(self.suspicious_entries),
            "ip_counts": Counter(),
            "status_counts": Counter(),
            "path_counts": Counter(),
            "attack_types": Counter(),
            "hourly_distribution": defaultdict(int),
        }
        
        for entry in self.entries:
            if 'ip' in entry:
                self.stats['ip_counts'][entry['ip']] += 1
            if 'status' in entry:
                self.stats['status_counts'][entry['status']] += 1
            if 'path' in entry:
                path = entry['path'].split('?')[0]  # Remove query string
                self.stats['path_counts'][path] += 1
        
        for entry in self.suspicious_entries:
            self.stats['attack_types'][entry.get('attack_type', 'unknown')] += 1
        
        return self.stats
    
    def find_brute_force(self, threshold: int = 5) -> List[str]:
        """Detect potential brute force attacks"""
        ip_failures = Counter()
        
        for entry in self.entries:
            raw = entry.get('raw', '').lower()
            if 'failed' in raw or 'invalid' in raw or 'authentication failure' in raw:
                ip = entry.get('ip', '')
                if not ip:
                    # Try to extract IP from message
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', raw)
                    if match:
                        ip = match.group(1)
                if ip:
                    ip_failures[ip] += 1
        
        return [ip for ip, count in ip_failures.items() if count >= threshold]
    
    def print_summary(self):
        """Print analysis summary"""
        stats = self.get_statistics()
        
        print(f"\n{C}{BRIGHT}═══ Log Analysis Summary ═══{RESET}")
        print(f"\n{Y}Overview:{RESET}")
        print(f"  Total entries:     {stats['total_entries']:,}")
        print(f"  Suspicious:        {stats['suspicious_count']}")
        
        if stats['ip_counts']:
            print(f"\n{Y}Top IPs:{RESET}")
            for ip, count in stats['ip_counts'].most_common(5):
                print(f"  {ip}: {count:,} requests")
        
        if stats['status_counts']:
            print(f"\n{Y}HTTP Status Codes:{RESET}")
            for status, count in stats['status_counts'].most_common(10):
                color = G if status.startswith('2') else (Y if status.startswith('3') else R)
                print(f"  {color}{status}{RESET}: {count:,}")
        
        if stats['attack_types']:
            print(f"\n{R}Attack Types Detected:{RESET}")
            for attack, count in stats['attack_types'].most_common():
                print(f"  {attack}: {count}")
        
        # Brute force detection
        brute_force_ips = self.find_brute_force()
        if brute_force_ips:
            print(f"\n{R}⚠ Potential Brute Force Sources:{RESET}")
            for ip in brute_force_ips[:5]:
                print(f"  • {ip}")


def interactive_mode():
    """Interactive log parsing"""
    clear_screen()
    print_banner("LOG PARSER", font="small", color="cyan")
    
    while True:
        print(f"\n{C}OPTIONS{RESET}")
        print(f"  {Y}[1]{RESET} Analyze Log File")
        print(f"  {Y}[2]{RESET} Detect Suspicious Activity")
        print(f"  {Y}[3]{RESET} Find Brute Force Attempts")
        print(f"  {Y}[4]{RESET} Search Log")
        print(f"  {R}[0]{RESET} Back")
        
        choice = prompt("Select").strip()
        
        if choice == "0":
            break
        
        elif choice == "1":
            log_path = prompt("Log file path").strip().strip('"')
            if not os.path.exists(log_path):
                error("File not found")
                continue
            
            parser = LogParser(log_path)
            info("Parsing log file...")
            parser.parse_log()
            parser.detect_suspicious()
            parser.print_summary()
        
        elif choice == "2":
            log_path = prompt("Log file path").strip().strip('"')
            if not os.path.exists(log_path):
                error("File not found")
                continue
            
            parser = LogParser(log_path)
            parser.parse_log()
            suspicious = parser.detect_suspicious()
            
            if suspicious:
                print(f"\n{R}Found {len(suspicious)} suspicious entries:{RESET}")
                for entry in suspicious[:20]:
                    print(f"\n  {Y}[{entry.get('attack_type', 'unknown')}]{RESET}")
                    print(f"  Line {entry.get('line_num', '?')}: {entry.get('raw', '')[:100]}")
            else:
                success("No suspicious patterns detected")
        
        elif choice == "3":
            log_path = prompt("Log file path").strip().strip('"')
            threshold = int(prompt("Failure threshold [5]").strip() or "5")
            
            if not os.path.exists(log_path):
                error("File not found")
                continue
            
            parser = LogParser(log_path)
            parser.parse_log()
            ips = parser.find_brute_force(threshold)
            
            if ips:
                print(f"\n{R}Potential brute force IPs:{RESET}")
                for ip in ips:
                    print(f"  • {ip}")
            else:
                success("No brute force attempts detected")
        
        elif choice == "4":
            log_path = prompt("Log file path").strip().strip('"')
            search_term = prompt("Search term").strip()
            
            if not os.path.exists(log_path):
                error("File not found")
                continue
            
            matches = []
            with open(log_path, 'r', errors='ignore') as f:
                for i, line in enumerate(f, 1):
                    if search_term.lower() in line.lower():
                        matches.append((i, line.strip()))
            
            if matches:
                print(f"\n{G}Found {len(matches)} matches:{RESET}")
                for line_num, line in matches[:20]:
                    print(f"  [{line_num}] {line[:100]}")
            else:
                warning("No matches found")
    
    input(f"\n{C}Press Enter...{RESET}")


if __name__ == "__main__":
    interactive_mode()
