# scanner_presets.py

"""
Nmap scan category presets for different network management purposes.

Each category includes:
- A user-friendly description
- A tailored list of Nmap arguments
"""

SCAN_CATEGORIES = {
    "Inventory Management": {
        "description": "Host discovery, OS, and service fingerprinting",
        "nmap_args": ["-sS", "-O", "-sV", "-T4"]
    },
    "Security Auditing": {
        "description": "Detect known vulnerabilities and weak services",
        "nmap_args": ["-sS", "-sV", "--script=vuln", "-T4"]
    },
    "System Administration": {
        "description": "Firewall path tracing and service versioning",
        "nmap_args": ["-sS", "-sV", "--script=firewalk", "-T3"]
    },
    "Penetration Testing": {
        "description": "OS detection and web app surface analysis",
        "nmap_args": ["-sS", "-sV", "-O", "--script=http-enum", "-T4"]
    },
    "Compliance Monitoring": {
        "description": "Detect misconfigurations and access issues",
        "nmap_args": ["-sS", "-sV", "--script=auth,ssl-cert", "-T3"]
    }
}

