import re

def fingerprint_service(banner: str) -> dict:
    """
    Enhanced service fingerprinting with better detection
    """
    banner_lower = banner.lower()
    result = {
        "service": "unknown",
        "version": "unknown"
    }

    # === SSH Detection ===
    if "ssh" in banner_lower:
        result["service"] = "ssh"
        # Example: SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
        if "openssh" in banner_lower:
            # Extract version after openssh_
            match = re.search(r'openssh[_\s-]+([\d.]+[a-z]?\d*)', banner_lower)
            if match:
                result["version"] = match.group(1)

    # === FTP Detection ===
    elif "ftp" in banner_lower or "220" in banner:
        result["service"] = "ftp"
        
        # vsftpd detection
        #Example : vsftpd 2.3.4
        if "vsftpd" in banner_lower:
            result["service"] = "vsftpd"
            match = re.search(r'vsftpd[:\s]+v?([\d.]+)', banner_lower)
            if match:
                result["version"] = match.group(1)
            else:
                # Try alternative format
                match = re.search(r'([\d.]+)\)', banner)
                if match:
                    result["version"] = match.group(1)
        
        # ProFTPD detection
        elif "proftpd" in banner_lower:
            result["service"] = "proftpd"
            match = re.search(r'proftpd[:\s]+([\d.]+[a-z]?)', banner_lower)
            if match:
                result["version"] = match.group(1)
        
        # Pure-FTPd detection
        elif "pure-ftpd" in banner_lower:
            result["service"] = "pure-ftpd"
            match = re.search(r'pure-ftpd[:\s]+([\d.]+[a-z]?)', banner_lower)
            if match:
                result["version"] = match.group(1)
        
        # Generic FTP version extraction
        else:
            # Look for version pattern in banner
            match = re.search(r'\b(\d+\.\d+\.?\d*)\b', banner)
            if match:
                result["version"] = match.group(1)

    # === SMTP Detection ===
    elif any(x in banner_lower for x in ["smtp", "mail", "postfix", "sendmail", "exim", "esmtp"]):
        if "postfix" in banner_lower:
            result["service"] = "postfix"
            match = re.search(r'postfix[:\s]+([\d.]+)', banner_lower)
            if match:
                result["version"] = match.group(1)
        elif "sendmail" in banner_lower:
            result["service"] = "sendmail"
            match = re.search(r'sendmail[:\s]+([\d.]+)', banner_lower)
            if match:
                result["version"] = match.group(1)
        elif "exim" in banner_lower:
            result["service"] = "exim"
            match = re.search(r'exim[:\s]+([\d.]+)', banner_lower)
            if match:
                result["version"] = match.group(1)
        else:
            result["service"] = "smtp"

    # === Apache Detection ===
    elif "apache" in banner_lower:
        result["service"] = "apache"
        # Example: Apache/2.2.8 (Ubuntu)
        match = re.search(r'apache[/\s]+([\d.]+)', banner_lower)
        if match:
            result["version"] = match.group(1)

    # === Nginx Detection ===
    elif "nginx" in banner_lower:
        result["service"] = "nginx"
        #Example: nginx/1.18.0
        match = re.search(r'nginx[/\s]+([\d.]+)', banner_lower)
        if match:
            result["version"] = match.group(1)

    # === MySQL/MariaDB Detection ===
    elif "mysql" in banner_lower or "mariadb" in banner_lower:
        if "mariadb" in banner_lower:
            result["service"] = "mariadb"
            match = re.search(r'mariadb[:\s-]+([\d.]+)', banner_lower)
            if match:
                result["version"] = match.group(1)
        else:
            result["service"] = "mysql"
            # Extract version from banner (e.g., "5.0.51a-3ubuntu5")
            match = re.search(r'([\d.]+[a-z]?)-', banner)
            if match:
                result["version"] = match.group(1)
            else:
                match = re.search(r'\b(\d+\.\d+\.?\d*[a-z]?)\b', banner)
                if match:
                    result["version"] = match.group(1)

    # === PostgreSQL Detection ===
    elif "postgresql" in banner_lower or "postgres" in banner_lower:
        result["service"] = "postgresql"
        #Example :PostgreSQL 12.1
        match = re.search(r'postgresql[:\s]+([\d.]+)', banner_lower)
        if match:
            result["version"] = match.group(1)

    # === Samba/SMB Detection ===
    elif "samba" in banner_lower or "smb" in banner_lower:
        result["service"] = "samba"
        match = re.search(r'samba[:\s/]+([\d.]+[a-z]?)', banner_lower)
        if match:
            result["version"] = match.group(1)
        else:
            # Samba version is hard to detect from banner
            # Mark as detected but version unknown
            result["service"] = "samba"

    # === Telnet Detection ===
    elif "telnet" in banner_lower:
        result["service"] = "telnet"

    # === DNS Detection ===
    elif "dns" in banner_lower or "domain" in banner_lower:
        result["service"] = "dns"

    # === HTTP Detection (generic) ===
    elif "http" in banner_lower:
        result["service"] = "http"

    return result