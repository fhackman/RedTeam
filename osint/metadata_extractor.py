#!/usr/bin/env python3
"""
Red Team Tools - Metadata Extractor
Extract metadata from documents and images
For educational and authorized security testing only
"""

import sys
import os
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import *

try:
    import exifread
    EXIF_AVAILABLE = True
except ImportError:
    EXIF_AVAILABLE = False

try:
    from PyPDF2 import PdfReader
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


class MetadataExtractor:
    """Extract metadata from various file types"""
    
    SUPPORTED_IMAGES = ['.jpg', '.jpeg', '.png', '.gif', '.tiff', '.bmp']
    SUPPORTED_DOCUMENTS = ['.pdf']
    
    def __init__(self):
        self.results: Dict = {}
    
    def extract_image_exif(self, file_path: str) -> Dict:
        """Extract EXIF data from image"""
        result = {"file": file_path, "type": "image", "exif": {}, "gps": {}, "basic": {}}
        
        if EXIF_AVAILABLE:
            try:
                with open(file_path, 'rb') as f:
                    tags = exifread.process_file(f)
                    for tag, value in tags.items():
                        if 'GPS' in tag:
                            result["gps"][tag] = str(value)
                        else:
                            result["exif"][tag] = str(value)
            except Exception as e:
                result["error"] = str(e)
        
        if PIL_AVAILABLE:
            try:
                img = Image.open(file_path)
                result["basic"] = {
                    "format": img.format, "mode": img.mode,
                    "size": f"{img.width}x{img.height}"
                }
                img.close()
            except:
                pass
        
        return result
    
    def extract_pdf_metadata(self, file_path: str) -> Dict:
        """Extract metadata from PDF file"""
        result = {"file": file_path, "type": "pdf", "metadata": {}, "pages": 0}
        
        if not PDF_AVAILABLE:
            result["error"] = "PyPDF2 not installed"
            return result
        
        try:
            reader = PdfReader(file_path)
            result["pages"] = len(reader.pages)
            result["encrypted"] = reader.is_encrypted
            
            if reader.metadata:
                for key, value in reader.metadata.items():
                    if value:
                        result["metadata"][key.replace('/', '')] = str(value)
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def extract_all(self, file_path: str) -> Dict:
        """Extract all available metadata from file"""
        path = Path(file_path)
        if not path.exists():
            return {"error": f"File not found: {file_path}"}
        
        stat = path.stat()
        result = {
            "file": str(path), "name": path.name,
            "size": stat.st_size, "size_human": bytes_to_human(stat.st_size),
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        }
        
        ext = path.suffix.lower()
        if ext in self.SUPPORTED_IMAGES:
            result.update(self.extract_image_exif(file_path))
        elif ext == '.pdf':
            result.update(self.extract_pdf_metadata(file_path))
        
        return result
    
    def print_result(self, result: Dict):
        """Print extraction result"""
        print(f"\n{C}{BRIGHT}═══ Metadata: {result.get('name', 'Unknown')} ═══{RESET}")
        print(f"  Size: {result.get('size_human', 'N/A')}")
        print(f"  Modified: {result.get('modified', 'N/A')}")
        
        if result.get("basic"):
            print(f"\n{Y}Image:{RESET} {result['basic'].get('size')} {result['basic'].get('format')}")
        
        if result.get("gps"):
            print(f"\n{R}⚠ GPS Data Found!{RESET}")
            for k, v in list(result["gps"].items())[:5]:
                print(f"  {k}: {v}")
        
        if result.get("metadata"):
            print(f"\n{Y}Document Metadata:{RESET}")
            for k, v in result["metadata"].items():
                print(f"  {k}: {v}")


def interactive_mode():
    """Interactive mode for metadata extraction"""
    clear_screen()
    print_banner("METADATA", font="small", color="cyan")
    
    extractor = MetadataExtractor()
    
    while True:
        print(f"\n{C}OPTIONS{RESET}")
        print(f"  {Y}[1]{RESET} Extract from File")
        print(f"  {R}[0]{RESET} Back")
        
        choice = prompt("Select").strip()
        if choice == "0":
            break
        elif choice == "1":
            file_path = prompt("File path").strip().strip('"')
            if os.path.exists(file_path):
                result = extractor.extract_all(file_path)
                extractor.print_result(result)
            else:
                error("File not found")
    
    input(f"\n{C}Press Enter...{RESET}")


if __name__ == "__main__":
    interactive_mode()
