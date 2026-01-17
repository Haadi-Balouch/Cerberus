# 🛡️ Cerberus Security Scanner

<div align="center">

![Version](https://img.shields.io/badge/version-2.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-Educational-yellow.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**Professional Vulnerability Assessment Framework**

*Enterprise-Grade Network & Web Security Scanner with Automated CVE Detection*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation) • [Legal](#-legal-disclaimer)

---

</div>

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#%EF%B8%8F-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
  - [CLI Mode](#cli-mode)
  - [GUI Mode](#gui-mode)
  - [Scan Profiles](#scan-profiles)
- [Module Documentation](#-module-documentation)
- [Configuration Options](#-configuration-options)
- [Output Reports](#-output-reports)
- [Advanced Usage](#-advanced-usage)
- [Troubleshooting](#-troubleshooting)
- [Legal Disclaimer](#%EF%B8%8F-legal-disclaimer)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

**Cerberus** is an enterprise-grade security assessment framework designed for professional penetration testers, security researchers, and IT professionals. It combines network reconnaissance, port scanning, service fingerprinting, CVE vulnerability detection, and web application security testing into a unified, easy-to-use platform.

### 🌟 Why Cerberus?

- ✅ **Comprehensive**: All-in-one solution for network and web security testing
- ✅ **Professional**: Enterprise-grade PDF reports with risk scoring
- ✅ **User-Friendly**: Both CLI and modern web GUI interfaces
- ✅ **Automated**: Real-time CVE lookups from NIST NVD database
- ✅ **Safe**: Built-in authorization checks and risk warnings
- ✅ **Open Source**: Free and transparent security testing

### 🎥 Demo

```bash
# Quick scan example
python main.py --target example.com --profile quick

# Output:
# ╔═══════════════════════════════════════════╗
# ║          RECONNAISSANCE PHASE             ║
# ╠═══════════════════════════════════════════╣
# ║ ✓ Host Reachable: Yes                     ║
# ║ ✓ DNS Resolved: 93.184.216.34             ║
# ║ ✓ TCP Port 80: Open                       ║
# ╚═══════════════════════════════════════════╝
```

---

## ✨ Features

### 🔐 Network Security
| Feature | Description |
|---------|-------------|
| **Host Discovery** | ICMP ping, DNS resolution (forward/reverse) |
| **Port Scanning** | Multi-threaded TCP enumeration (50 workers) |
| **Service Detection** | Enhanced banner grabbing & fingerprinting |
| **CVE Lookup** | Automated NVD database queries with semantic versioning |
| **Risk Assessment** | Severity classification (Critical/High/Medium/Low) |

### 🌐 Web Application Security
| Feature | Description |
|---------|-------------|
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-XSS-Protection, Referrer-Policy |
| **Admin Discovery** | Common admin path enumeration |
| **XSS Detection** | 20+ reflected XSS payload variations |
| **SQL Injection** | Error-based and boolean-based SQLi testing |
| **Directory Enum** | Wordlist-based brute forcing with rate limiting |

### 📊 Reporting & Analysis
- 📄 **PDF Reports**: Professional security assessment documents
  - Executive summary with risk scoring (0-100)
  - Vulnerability distribution pie charts
  - Detailed CVE analysis with remediation steps
  - Web security findings with evidence
  - Color-coded severity indicators
- 📊 **JSON Output**: Machine-readable structured data
- 📝 **Activity Logging**: Comprehensive audit trail in `outputs/cerberus_log.txt`

### 💻 User Interfaces
- **Rich CLI**: Beautiful terminal UI with progress bars, tables, and colors
- **Web GUI**: Modern React-based interface with:
  - Real-time WebSocket updates
  - Live scan progress monitoring
  - Interactive vulnerability explorer
  - One-click report downloads

---

## 🏗️ Architecture

```
cerberus/
│
├── 📂 module/                    # Core scanning modules
│   ├── 📂 recon/                 # Reconnaissance
│   │   ├── host_discovery.py     # ICMP ping checks
│   │   ├── dns_resolver.py       # DNS forward/reverse lookup
│   │   └── tcp_check.py          # TCP connectivity tests
│   │
│   ├── 📂 ports/                 # Port scanning
│   │   ├── port_scanner.py       # Multi-threaded port enumeration
│   │   └── service_fingerprint.py # Service version detection
│   │
│   ├── 📂 cve/                   # Vulnerability database
│   │   └── cve_auto_fetcher.py   # NVD API integration
│   │
│   └── 📂 web/                   # Web security
│       ├── xss_scanner.py        # Cross-site scripting
│       ├── sql_scanner.py        # SQL injection
│       ├── headers.py            # Security headers
│       ├── admin_finder.py       # Admin panel discovery
│       └── dir_enum.py           # Directory enumeration
│
├── 📂 reporting/
│   └── pdf_report.py             # Professional PDF generation
│
├── 📂 utils/
│   └── logger.py                 # Activity logging
│
├── 📂 gui/
│   ├── backendAPI.py             # Flask + SocketIO API server
│   └── index.html                # React frontend (single page)
│
├── 📂 wordlists/
│   └── admin_paths.txt           # Common admin paths
│
├── 📂 outputs/                   # Generated reports & logs
│
├── 📄 main.py                    # CLI entry point
├── 📄 requirements.txt           # Python dependencies
└── 📄 README.md                  # This file
```

---

## 🚀 Installation

### Prerequisites

- **Python**: 3.8 or higher
- **pip**: Python package manager
- **Internet**: Required for CVE lookups
- **OS**: Windows, Linux, or macOS

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/cerberus.git
cd cerberus
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

**Required Packages:**
```txt
requests>=2.31.0          # HTTP requests
packaging>=23.0           # Version comparison
rich>=13.0.0              # Terminal UI
reportlab>=4.0.0          # PDF generation
flask>=3.0.0              # Web backend
flask-cors>=4.0.0         # CORS support
flask-socketio>=5.3.0     # WebSocket support
eventlet>=0.33.0          # Async server
```

### Step 3: Verify Installation

```bash
python main.py --help
```

Expected output:
```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║                ╔═╗╔═╗╦═╗╔╗ ╔═╗╦═╗╦ ╦╔═╗                   ║
║                ║  ║╣ ╠╦╝╠╩╗║╣ ╠╦╝║ ║╚═╗                   ║
║                ╚═╝╚═╝╩╚═╚═╝╚═╝╩╚═╚═╝╚═╝                   ║
║                                                           ║
║        Professional Vulnerability Scanner v2.0            ║
║           Network & Web Security Assessment               ║
║                Enterprise-Grade Security Framework        ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

---

## ⚡ Quick Start

### 1. Basic Scan (Domain)
```bash
python main.py --target example.com
```

### 2. Scan IP Address
```bash
python main.py --target 192.168.1.1
```

### 3. Scan Website (URL)
```bash
python main.py --target https://example.com
```

### 4. Quick Scan (Fast)
```bash
python main.py --target example.com --profile quick
```

### 5. Launch Web GUI
```bash
cd gui
python backendAPI.py
# Open browser to http://localhost:5000
```

---

## 📖 Usage

### CLI Mode

#### Basic Commands

```bash
# Standard scan (default)
python main.py --target example.com

# Quick scan (non-intrusive)
python main.py --target example.com --profile quick

# Aggressive scan (all modules)
python main.py --target example.com --profile aggressive

# Web-only scan
python main.py --target https://example.com --profile web-only

# Network-only scan
python main.py --target 192.168.1.1 --profile network-only

# Custom modules
python main.py --target example.com --modules xss,sqli,headers
```

#### Advanced Options

```bash
# With custom wordlist
python main.py --target example.com --wordlist /path/to/wordlist.txt

# With rate limiting (0.5s between requests)
python main.py --target example.com --rate 0.5

# With custom worker threads
python main.py --target example.com --workers 20

# Skip authorization check (lab only!)
python main.py --target example.com --skip-auth

# Dry run (preview only)
python main.py --target example.com --dry-run

# Skip PDF generation
python main.py --target example.com --no-pdf
```

### GUI Mode

#### Starting the Backend

```bash
cd gui
python backendAPI.py
```

Output:
```
🛡️ Cerberus Backend API Server
==================================================
Server running on: http://localhost:5000
WebSocket available for real-time updates
Press Ctrl+C to stop
==================================================
```

#### Using the Web Interface

1. **Open Browser**: Navigate to `http://localhost:5000` or open `gui/index.html`
2. **Enter Target**: Input IP, domain, or URL
3. **Select Profile**: Choose from quick, standard, aggressive, web-only, network-only, or custom
4. **Configure Options**: 
   - Adjust worker threads (1-50)
   - Set rate limit (0-5 seconds)
   - Select custom modules (if using custom profile)
5. **Start Scan**: Click "Start Scan" button
6. **Monitor Progress**: Watch real-time logs and progress bar
7. **View Results**: Switch to "Results" tab when complete
8. **Download Reports**: Click "Download JSON" or "Download PDF"

#### GUI Features

- ✅ Real-time scan progress with percentage
- ✅ Live log streaming via WebSocket
- ✅ Interactive vulnerability explorer
- ✅ One-click report downloads
- ✅ Connection status indicator
- ✅ Built-in authorization warnings
- ✅ Responsive design (mobile-friendly)

---

## 🎯 Scan Profiles

### 📋 Profile Comparison

| Profile | Modules | Risk Level | Duration | Use Case |
|---------|---------|------------|----------|----------|
| **Quick** | headers, admin, recon, ports | 🟢 SAFE | ~2-5 min | Initial assessment |
| **Standard** | headers, admin, xss, recon, ports, cve | 🟡 MODERATE | ~5-10 min | Regular audits |
| **Aggressive** | ALL modules | 🔴 AGGRESSIVE | ~15-30 min | Deep pentesting |
| **Web-Only** | headers, admin, xss, sqli, dir | 🟡 MODERATE | ~10-15 min | Web app testing |
| **Network-Only** | recon, ports, cve | 🟢 SAFE | ~5-10 min | Network audits |
| **Custom** | User-selected | 🔵 VARIES | Varies | Specific needs |

### Profile Details

#### Quick Scan 🟢
```bash
python main.py --target example.com --profile quick
```
- **Modules**: Security headers, admin panels, host discovery, port scanning
- **Safe for**: Production environments
- **Best for**: Permission verification, initial reconnaissance

#### Standard Scan 🟡 (Default)
```bash
python main.py --target example.com --profile standard
```
- **Modules**: Headers, admin, XSS detection, recon, ports, CVE lookup
- **Safe for**: Test environments
- **Best for**: Regular security audits, compliance checks

#### Aggressive Scan 🔴
```bash
python main.py --target example.com --profile aggressive
```
- **Modules**: ALL (includes SQL injection, directory brute force)
- **Warning**: May trigger IDS/IPS systems
- **Best for**: Authorized penetration testing only

#### Web-Only Scan 🟡
```bash
python main.py --target https://example.com --profile web-only
```
- **Modules**: All web security modules (no network scanning)
- **Best for**: Web application assessments

#### Network-Only Scan 🟢
```bash
python main.py --target 192.168.1.1 --profile network-only
```
- **Modules**: Recon, port scanning, CVE lookup
- **Best for**: Network infrastructure audits

---

## 🔧 Module Documentation

### 🔍 Reconnaissance (`recon`)

**Risk Level**: 🟢 SAFE

**Description**: Performs basic host discovery and DNS enumeration.

**Functions**:
- ICMP ping check (`host_discovery.py`)
- DNS forward lookup: domain → IP
- DNS reverse lookup: IP → domain (PTR record)
- TCP connectivity test on port 80

**Output Example**:
```
╔═══════════════════════════════════════╗
║ Host Reachable       │ ✓ Yes          ║
║ DNS Resolved         │ 93.184.216.34  ║
║ Reverse DNS          │ example.com    ║
║ TCP Port 80          │ ✓ Open         ║
╚═══════════════════════════════════════╝
```

**CLI Usage**:
```bash
python main.py --target example.com --modules recon
```

---

### 🚪 Port Scanning (`ports`)

**Risk Level**: 🟢 SAFE

**Description**: Multi-threaded TCP port enumeration with service detection.

**Scanned Ports**:
```
21   - FTP
22   - SSH
23   - Telnet
25   - SMTP
53   - DNS
80   - HTTP
110  - POP3
143  - IMAP
139  - NetBIOS
443  - HTTPS
445  - SMB
3306 - MySQL
3389 - RDP
5432 - PostgreSQL
8080 - HTTP-Alt
8443 - HTTPS-Alt
```

**Features**:
- Multi-threaded scanning (50 concurrent workers)
- Protocol-specific banner grabbing
- Enhanced service fingerprinting
- Version extraction with regex patterns

**Supported Services**:
- SSH (OpenSSH version detection)
- FTP (vsftpd, ProFTPD, Pure-FTPd)
- HTTP/HTTPS (Apache, Nginx, IIS)
- SMTP (Postfix, Sendmail, Exim)
- MySQL/MariaDB (handshake parsing)
- PostgreSQL (protocol detection)
- Samba/SMB

**Output Example**:
```
╔══════╦═══════════╦═══════════╦═══════╗
║ Port ║ Service   ║ Version   ║ CVEs  ║
╠══════╬═══════════╬═══════════╬═══════╣
║ 22   ║ OpenSSH   ║ 7.6p1     ║ 3     ║
║ 80   ║ Apache    ║ 2.4.29    ║ 12    ║
║ 3306 ║ MySQL     ║ 5.7.33    ║ 5     ║
╚══════╩═══════════╩═══════════╩═══════╝
```

---

### 🔐 CVE Lookup (`cve`)

**Risk Level**: 🟢 SAFE

**Description**: Automated vulnerability lookup from NIST National Vulnerability Database.

**Features**:
- Real-time NVD API queries
- Semantic version matching using `packaging` library
- Version range checking (versionStartIncluding, versionEndExcluding, etc.)
- Service alias mapping (e.g., "ssh" → "openssh")
- Rate limiting (600ms between requests)
- Severity classification (CVSS v2/v3)

**API Endpoint**:
```
https://services.nvd.nist.gov/rest/json/cves/2.0
```

**Severity Mapping**:
- **Critical**: CVSS ≥ 9.0 (🔴 Immediate action required)
- **High**: CVSS ≥ 7.0 (🟠 Urgent remediation)
- **Medium**: CVSS ≥ 4.0 (🟡 Scheduled fix)
- **Low**: CVSS < 4.0 (🟢 Best practice)

**Output Example**:
```json
{
  "cve": "CVE-2021-28041",
  "severity": "HIGH",
  "description": "OpenSSH 7.6 allows remote attackers to...",
  "recommendation": "Update to OpenSSH 8.5 or later"
}
```

**Supported Services**:
```python
openssh, apache, nginx, mysql, mariadb, postgresql,
vsftpd, proftpd, postfix, sendmail, exim, samba
```

---

### 🛡️ Security Headers (`headers`)

**Risk Level**: 🟢 SAFE

**Description**: Analyzes HTTP security headers for common misconfigurations.

**Checked Headers**:

| Header | Purpose | Risk if Missing |
|--------|---------|-----------------|
| `Content-Security-Policy` | Prevents XSS/injection attacks | 🔴 High |
| `Strict-Transport-Security` | Enforces HTTPS connections | 🟠 Medium |
| `X-Frame-Options` | Prevents clickjacking | 🟡 Medium |
| `X-XSS-Protection` | Enables browser XSS filtering | 🟡 Low |
| `Referrer-Policy` | Controls referrer information | 🟢 Low |

**Output Example**:
```
Security Headers Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✗ Content-Security-Policy    MISSING
✗ Strict-Transport-Security  MISSING
✓ X-Frame-Options            PRESENT
✓ X-XSS-Protection           PRESENT
✗ Referrer-Policy            MISSING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Status: ⚠️  INSECURE (3 headers missing)
```

---

### 🔓 Admin Panel Discovery (`admin`)

**Risk Level**: 🟢 SAFE

**Description**: Enumerates common admin panel paths.

**Default Wordlist** (`wordlists/admin_paths.txt`):
```
admin
login
administrator
wp-admin
cpanel
phpmyadmin
dashboard
manage
portal
user
config
backup
```

**Features**:
- HTTP status code detection (200, 301, 302, 403)
- Redirect following
- Timeout handling (4 seconds)
- No authentication attempts

**Output Example**:
```
Admin Panel Discovery
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ http://example.com/admin      200
✓ http://example.com/wp-admin   302
✓ http://example.com/phpmyadmin 403
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Found: 3 potential admin paths
```

---

### 💉 XSS Detection (`xss`)

**Risk Level**: 🟡 MODERATE

**Description**: Tests for reflected cross-site scripting vulnerabilities.

**Payloads** (20 variations):
```javascript
<script>alert(1)</script>
"><script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<iframe srcdoc='<script>alert(1)</script>'></iframe>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<input autofocus onfocus=alert(1)>
// ... and 12 more
```

**Detection Method**:
1. Inject payload into URL parameters
2. Check if payload appears unescaped in response
3. Verify payload is not HTML-encoded

**Output Example**:
```
XSS Detection Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  VULNERABLE: Parameter 'search'
    Payload: <script>alert(1)</script>
    Evidence: Payload reflected unescaped
    URL: http://example.com?search=<script>...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Status: 🔴 XSS DETECTED (3 findings)
```

---

### 🗄️ SQL Injection (`sqli`)

**Risk Level**: 🔴 AGGRESSIVE

**Description**: Tests for SQL injection vulnerabilities using error-based and boolean-based techniques.

**Error-Based Payloads**:
```sql
'
"
' OR '1'='1' --
') OR ('1'='1' --
' OR 1=1--
" OR 1=1--
```

**Boolean-Based Payloads**:
```sql
' OR '1'='1' --   (TRUE)
' OR '1'='2' --   (FALSE)

" OR "1"="1" --   (TRUE)
" OR "1"="2" --   (FALSE)
```

**SQL Error Patterns**:
```regex
you have an error in your sql syntax
mysql_fetch
mysqli_sql
pg_fetch
ORA-\d{4}
SQLite\/JDBCDriver
sqlstate
SQLITE_ERROR
```

**Detection Methods**:

1. **Error-Based**:
   - Inject SQL syntax errors
   - Check response for database error messages
   - Pattern matching against 15+ error signatures

2. **Boolean-Based**:
   - Inject TRUE condition → observe response
   - Inject FALSE condition → observe response
   - Compare response lengths/content
   - Difference > 3% indicates vulnerability

**Output Example**:
```
SQL Injection Testing
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔴 CRITICAL: Parameter 'id'
    Type: Error-Based
    Payload: ' OR '1'='1' --
    Evidence: "mysql_fetch_array() expects..."
    URL: http://example.com?id=' OR '1'='1' --
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Status: 🔴 SQL INJECTION DETECTED
```

---

### 📁 Directory Enumeration (`dir`)

**Risk Level**: 🟡 MODERATE

**Description**: Brute-forces directories and files using wordlists.

**Features**:
- Multi-threaded requests (default: 15 workers)
- Rate limiting support (0-5 seconds)
- Safe wordlist loading (max 50,000 entries)
- Content-length detection
- Redirect following

**Default Wordlist**:
```
admin, login, dashboard, upload, uploads,
backup, config, test, dev, staging,
wp-admin, wp-content, api, assets, css,
js, images, files, downloads, docs
```

**Custom Wordlist**:
```bash
python main.py --target example.com \
  --modules dir \
  --wordlist /usr/share/wordlists/dirb/common.txt
```

**Output Example**:
```
Directory Enumeration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ /admin        200  3.2 KB
✓ /backup       403  Forbidden
✓ /config.php   200  1.1 KB
✓ /uploads      301  Redirect
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Found: 4 accessible paths
```

---

## ⚙️ Configuration Options

### Command-Line Arguments

```bash
python main.py [OPTIONS]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--target` | string | **Required** | Target IP/Domain/URL |
| `--profile` | choice | `standard` | Scan profile (quick/standard/aggressive/web-only/network-only/custom) |
| `--modules` | string | Profile-based | Comma-separated modules (overrides profile) |
| `--wordlist` | path | None | Custom wordlist for directory enumeration |
| `--workers` | int | `15` | Number of worker threads (1-50) |
| `--rate` | float | `0.0` | Rate limit in seconds between requests |
| `--skip-auth` | flag | False | Skip authorization check (dangerous!) |
| `--dry-run` | flag | False | Show scan plan without executing |
| `--no-pdf` | flag | False | Skip PDF report generation |

### Environment Variables

```bash
# Set custom output directory
export CERBERUS_OUTPUT_DIR="/path/to/output"

# Set custom wordlist directory
export CERBERUS_WORDLIST_DIR="/path/to/wordlists"

# Set NVD API key (for higher rate limits)
export NVD_API_KEY="your-api-key-here"
```

### Configuration File (Future)

```yaml
# cerberus.yml
target: example.com
profile: standard
options:
  workers: 20
  rate_limit: 0.5
  skip_auth: false
modules:
  enabled:
    - recon
    - ports
    - cve
  disabled:
    - sqli
wordlists:
  admin: /path/to/admin.txt
  dir: /path/to/directories.txt
```

---

## 📊 Output Reports

### JSON Report Structure

**File**: `outputs/cerberus_output_YYYY-MM-DD_HH-MM-SS.json`

```

### PDF Report Sections

**File**: `outputs/report_YYYY-MM-DD_HH-MM-SS.pdf`

#### 1. Cover Page
- Target information
- Assessment date
- Overall risk score (0-100)
- Risk rating (Critical/High/Medium/Low)
- Color-coded visual indicator

#### 2. Executive Summary
- Scan overview paragraph
- Vulnerability distribution table
- Severity breakdown pie chart
- Key findings summary

#### 3. Reconnaissance Summary
- Host reachability status
- DNS information (IP, PTR)
- TCP connectivity results
- Network topology insights

#### 4. Port & Service Enumeration
- Open ports table with:
  - Port number
  - Service name
  - Version detected
  - Number of associated CVEs

#### 5. Vulnerability Findings
Grouped by severity:
- **Critical**: Red boxes, immediate action items
- **High**: Orange boxes, urgent remediation
- **Medium**: Yellow boxes, scheduled fixes
- **Low**: Blue boxes, best practice improvements

Each CVE includes:
- CVE ID with hyperlink
- Detailed description (truncated to 500 chars)
- Severity rating
- Recommended remediation steps

#### 6. Web Application Security
- Security headers analysis
- Admin panel discoveries
- XSS findings with payloads
- SQL injection evidence
- Directory enumeration results

#### 7. Remediation Recommendations
- Prioritized action items by severity
- Patching guidance
- Security best practices
- Compliance suggestions

