#!/usr/bin/env python3
"""
Red Team Tools - Setup Script
Professional package installation with pip
For educational and authorized security testing only
"""

import os
import sys
from setuptools import setup, find_packages

# Read version from config
VERSION = "2.0.0"

# Read long description from README
def get_long_description():
    readme_path = os.path.join(os.path.dirname(__file__), "README.md")
    if os.path.exists(readme_path):
        with open(readme_path, "r", encoding="utf-8") as f:
            return f.read()
    return "Red Team Security Testing Toolkit"

# Core dependencies
INSTALL_REQUIRES = [
    "colorama>=0.4.6",
    "pyfiglet>=0.8.0",
    "rich>=13.0.0",
    "requests>=2.28.0",
    "beautifulsoup4>=4.11.0",
    "lxml>=4.9.0",
    "psutil>=5.9.0",
    "pycryptodome>=3.17.0",
    "cryptography>=39.0.0",
    "Pillow>=9.4.0",
    "dnspython>=2.3.0",
    "paramiko>=3.0.0",
]

# Optional dependencies for specific features
EXTRAS_REQUIRE = {
    "network": [
        "scapy>=2.5.0",
        "python-nmap>=0.7.1",
        "netifaces>=0.11.0",
        "netaddr>=0.8.0",
        "impacket>=0.10.0",
    ],
    "web": [
        "selenium>=4.8.0",
        "fake-useragent>=1.1.0",
    ],
    "osint": [
        "python-whois>=0.8.0",
        "exifread>=3.0.0",
        "PyPDF2>=3.0.0",
    ],
    "system": [
        "pynput>=1.7.6",
    ],
    "forensics": [
        "python-magic-bin>=0.4.14" if os.name == 'nt' else "python-magic>=0.4.27",
    ],
    "full": [],  # Will be populated below
}

# "full" includes everything
EXTRAS_REQUIRE["full"] = list(set(
    dep for deps in EXTRAS_REQUIRE.values() for dep in deps
))

# Platform-specific dependencies
if sys.platform == "win32":
    EXTRAS_REQUIRE["windows"] = ["pywin32>=305"]
elif sys.platform.startswith("linux"):
    EXTRAS_REQUIRE["linux"] = ["python-xlib>=0.33"]

# Development dependencies
EXTRAS_REQUIRE["dev"] = [
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
    "flake8>=6.0.0",
    "black>=23.0.0",
    "mypy>=1.0.0",
]

setup(
    name="red-team-tools",
    version=VERSION,
    author="Red Team Tools",
    author_email="security@example.com",
    description="Professional Red Team Security Testing Toolkit",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/example/red-team-tools",
    license="MIT",
    
    # Package configuration
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    
    # Python version requirement
    python_requires=">=3.8",
    
    # Dependencies
    install_requires=INSTALL_REQUIRES,
    extras_require=EXTRAS_REQUIRE,
    
    # Entry points for CLI commands
    entry_points={
        "console_scripts": [
            "redteam=main_menu:main",
            "redteam-install=installer:main",
            "portscan=network.port_scanner:main",
            "hashcrack=password.hash_cracker:interactive_mode",
            "dirbust=web.dir_bruteforcer:interactive_mode",
            "xssscan=web.xss_scanner:interactive_mode",
            "sqlitest=web.sqli_tester:interactive_mode",
        ],
    },
    
    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: Utilities",
    ],
    
    # Keywords
    keywords=[
        "security", "penetration-testing", "red-team", "ethical-hacking",
        "vulnerability-scanner", "network-security", "web-security",
        "password-cracking", "reconnaissance", "osint"
    ],
    
    # Project URLs
    project_urls={
        "Documentation": "https://github.com/example/red-team-tools#readme",
        "Source": "https://github.com/example/red-team-tools",
        "Bug Tracker": "https://github.com/example/red-team-tools/issues",
    },
)
