#!/usr/bin/env python3
"""
Red Team Tools - File Analyzer
Forensic file analysis tool
For incident analysis and authorized security testing
"""

import sys
import os
import hashlib
import math
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import struct
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import *


class FileAnalyzer:
    """Comprehensive file analysis tool"""
    
    # Magic bytes signatures
    SIGNATURES = {
        b'\x50\x4B\x03\x04': 'ZIP/Office Document',
        b'\x50\x4B\x05\x06': 'ZIP Empty',
        b'\x52\x61\x72\x21': 'RAR Archive',
        b'\x7F\x45\x4C\x46': 'ELF Executable (Linux)',
        b'\x4D\x5A': 'PE Executable (Windows)',
        b'\x25\x50\x44\x46': 'PDF Document',
        b'\x89\x50\x4E\x47': 'PNG Image',
        b'\xFF\xD8\xFF': 'JPEG Image',
        b'\x47\x49\x46\x38': 'GIF Image',
        b'\x42\x4D': 'BMP Image',
        b'\x49\x44\x33': 'MP3 Audio',
        b'\x00\x00\x00\x1C\x66\x74\x79\x70': 'MP4 Video',
        b'\x1F\x8B\x08': 'GZIP Compressed',
        b'\x42\x5A\x68': 'BZIP2 Compressed',
        b'\xFD\x37\x7A\x58\x5A': 'XZ Compressed',
        b'\xCA\xFE\xBA\xBE': 'Java Class',
        b'\x53\x51\x4C\x69\x74\x65': 'SQLite Database',
        b'\x23\x21': 'Script (shebang)',
        b'\xD0\xCF\x11\xE0': 'MS Office (OLE)',
    }
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.path = Path(file_path)
        self.results: Dict = {}
    
    def analyze(self) -> Dict:
        """Perform comprehensive file analysis"""
        if not self.path.exists():
            return {"error": f"File not found: {self.file_path}"}
        
        stat = self.path.stat()
        
        self.results = {
            "file": str(self.path.absolute()),
            "name": self.path.name,
            "extension": self.path.suffix,
            "size": stat.st_size,
            "size_human": bytes_to_human(stat.st_size),
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
            "permissions": oct(stat.st_mode)[-3:],
            "hashes": self.calculate_hashes(),
            "file_type": self.detect_file_type(),
            "entropy": self.calculate_entropy(),
            "strings": [],
            "is_executable": self.is_executable(),
        }
        
        # Check for suspicious characteristics
        self.results["suspicious"] = self.check_suspicious()
        
        return self.results
    
    def calculate_hashes(self) -> Dict[str, str]:
        """Calculate file hashes"""
        hashes = {"md5": "", "sha1": "", "sha256": ""}
        
        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()
                hashes["md5"] = hashlib.md5(content).hexdigest()
                hashes["sha1"] = hashlib.sha1(content).hexdigest()
                hashes["sha256"] = hashlib.sha256(content).hexdigest()
        except:
            pass
        
        return hashes
    
    def detect_file_type(self) -> str:
        """Detect file type from magic bytes"""
        try:
            with open(self.file_path, 'rb') as f:
                header = f.read(16)
            
            for magic, file_type in self.SIGNATURES.items():
                if header.startswith(magic):
                    return file_type
            
            # Check for text file
            try:
                with open(self.file_path, 'r', encoding='utf-8') as f:
                    f.read(1024)
                return "Text File"
            except:
                return "Unknown Binary"
        except:
            return "Unknown"
    
    def calculate_entropy(self) -> float:
        """Calculate Shannon entropy (high entropy may indicate encryption/compression)"""
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0
            
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    p = count / len(data)
                    entropy -= p * math.log2(p)
            
            return round(entropy, 4)
        except:
            return 0.0
    
    def extract_strings(self, min_length: int = 4, max_strings: int = 100) -> List[str]:
        """Extract printable strings from file"""
        strings = []
        pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        
        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()
            
            matches = re.findall(pattern, content)
            strings = [m.decode('ascii', errors='ignore') for m in matches[:max_strings]]
        except:
            pass
        
        return strings
    
    def is_executable(self) -> bool:
        """Check if file is executable"""
        try:
            with open(self.file_path, 'rb') as f:
                header = f.read(4)
            
            # Windows PE
            if header[:2] == b'\x4D\x5A':
                return True
            # Linux ELF
            if header == b'\x7F\x45\x4C\x46':
                return True
            # Script with shebang
            if header[:2] == b'\x23\x21':
                return True
        except:
            pass
        
        return False
    
    def check_suspicious(self) -> List[str]:
        """Check for suspicious characteristics"""
        suspicious = []
        
        # High entropy (possible encryption/packing)
        entropy = self.results.get("entropy", 0)
        if entropy > 7.5:
            suspicious.append(f"High entropy ({entropy}) - possible encryption/packing")
        
        # Extension mismatch
        detected = self.results.get("file_type", "")
        extension = self.path.suffix.lower()
        
        if "Executable" in detected and extension not in ['.exe', '.dll', '.elf', '.bin', '']:
            suspicious.append(f"Extension mismatch: {extension} but detected as {detected}")
        
        # Double extension
        if self.path.stem.count('.') > 0:
            suspicious.append(f"Double extension detected: {self.path.name}")
        
        return suspicious
    
    def print_results(self):
        """Print analysis results"""
        r = self.results
        
        print(f"\n{C}{BRIGHT}═══ File Analysis: {r.get('name', 'Unknown')} ═══{RESET}")
        
        print(f"\n{Y}Basic Info:{RESET}")
        print(f"  Path:       {r.get('file', 'N/A')}")
        print(f"  Size:       {r.get('size_human', 'N/A')} ({r.get('size', 0):,} bytes)")
        print(f"  Type:       {r.get('file_type', 'N/A')}")
        print(f"  Modified:   {r.get('modified', 'N/A')}")
        print(f"  Executable: {'Yes' if r.get('is_executable') else 'No'}")
        
        print(f"\n{Y}Hashes:{RESET}")
        hashes = r.get('hashes', {})
        print(f"  MD5:    {hashes.get('md5', 'N/A')}")
        print(f"  SHA1:   {hashes.get('sha1', 'N/A')}")
        print(f"  SHA256: {hashes.get('sha256', 'N/A')}")
        
        print(f"\n{Y}Entropy:{RESET} {r.get('entropy', 0)} / 8.0")
        entropy = r.get('entropy', 0)
        if entropy > 7.5:
            print(f"  {R}⚠ High entropy - possible encryption/packing{RESET}")
        elif entropy > 6.0:
            print(f"  {Y}⚠ Moderate entropy - possibly compressed{RESET}")
        
        suspicious = r.get('suspicious', [])
        if suspicious:
            print(f"\n{R}⚠ Suspicious Indicators:{RESET}")
            for s in suspicious:
                print(f"  • {s}")


def interactive_mode():
    """Interactive file analysis"""
    clear_screen()
    print_banner("FILE ANALYZER", font="small", color="cyan")
    
    while True:
        print(f"\n{C}OPTIONS{RESET}")
        print(f"  {Y}[1]{RESET} Analyze File")
        print(f"  {Y}[2]{RESET} Calculate Hashes Only")
        print(f"  {Y}[3]{RESET} Extract Strings")
        print(f"  {Y}[4]{RESET} Check File Type")
        print(f"  {R}[0]{RESET} Back")
        
        choice = prompt("Select").strip()
        
        if choice == "0":
            break
        
        elif choice == "1":
            file_path = prompt("File path").strip().strip('"')
            if os.path.exists(file_path):
                analyzer = FileAnalyzer(file_path)
                analyzer.analyze()
                analyzer.print_results()
            else:
                error("File not found")
        
        elif choice == "2":
            file_path = prompt("File path").strip().strip('"')
            if os.path.exists(file_path):
                analyzer = FileAnalyzer(file_path)
                hashes = analyzer.calculate_hashes()
                print(f"\n{Y}Hashes:{RESET}")
                for algo, value in hashes.items():
                    print(f"  {algo.upper()}: {value}")
            else:
                error("File not found")
        
        elif choice == "3":
            file_path = prompt("File path").strip().strip('"')
            min_len = int(prompt("Min string length [4]").strip() or "4")
            
            if os.path.exists(file_path):
                analyzer = FileAnalyzer(file_path)
                strings = analyzer.extract_strings(min_len)
                print(f"\n{Y}Strings found: {len(strings)}{RESET}")
                for s in strings[:50]:
                    print(f"  {s}")
            else:
                error("File not found")
        
        elif choice == "4":
            file_path = prompt("File path").strip().strip('"')
            if os.path.exists(file_path):
                analyzer = FileAnalyzer(file_path)
                file_type = analyzer.detect_file_type()
                print(f"\n  Type: {G}{file_type}{RESET}")
            else:
                error("File not found")
    
    input(f"\n{C}Press Enter...{RESET}")


if __name__ == "__main__":
    interactive_mode()
