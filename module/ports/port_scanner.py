import socket
import time
import re
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.close()
        return True
    except:
        return False

def scan_multiple_ports(ip: str, ports: list, max_workers: int=50) -> list:
    open_ports = []

    def check(port):
        if scan_port(ip, port):
            open_ports.append(port)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(check, ports)

    return open_ports

def grab_banner_enhanced(ip: str, port: int, timeout: float = 4.0) -> str:
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        banner = ""
        
        # === Port 21: FTP ===
        if port == 21:
            time.sleep(0.3)
            banner = sock.recv(2048).decode(errors="ignore").strip()
            
        # === Port 22: SSH ===
        elif port == 22:
            time.sleep(0.3)
            banner = sock.recv(1024).decode(errors="ignore").strip()
            
        # === Port 23: Telnet ===
        elif port == 23:
            time.sleep(1.5)  # Telnet needs more time
            banner = sock.recv(2048).decode(errors="ignore").strip()
            if not banner:
                # Sometimes telnet needs a nudge
                sock.send(b"\r\n")
                time.sleep(0.5)
                banner = sock.recv(2048).decode(errors="ignore").strip()
            
        # === Port 25: SMTP ===
        elif port == 25:
            time.sleep(0.5)
            banner = sock.recv(1024).decode(errors="ignore").strip()
            if not banner:
                sock.send(b"EHLO cerberus\r\n") #Sending this always forces SMTP to reply, even if it didn’t send anything initially.
                time.sleep(0.3)
                banner = sock.recv(1024).decode(errors="ignore").strip()
                
        # === Port 53: DNS ===
        elif port == 53:
            banner = "DNS service"
            
        # === Port 80/8080: HTTP ===
        elif port in [80, 8080, 8000]:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n") #We send a HEAD request that requests only metadata. The extra \r\n\r\n means: end of HTTP headers
            time.sleep(0.5)
            response = sock.recv(4096).decode(errors="ignore")
            for line in response.split('\n'):
                #Example : Server: Apache/2.2.8 (Ubuntu)
                if line.lower().startswith('server:'):
                    banner = line.split(':', 1)[1].strip()
                    break
            if not banner:
                banner = "HTTP service"
                
        # === Port 110/995: POP3 ===
        elif port in [110, 995]:
            time.sleep(0.5)
            banner = sock.recv(1024).decode(errors="ignore").strip()
            
        # === Port 143/993: IMAP ===
        elif port in [143, 993]:
            time.sleep(0.5)
            banner = sock.recv(1024).decode(errors="ignore").strip()
            
        # === Port 139/445: SMB/Samba ===
        elif port in [139, 445]:
            # SMB banner extraction is complex, use nmap or external tools
            banner = "Samba/SMB service"
            
        # === Port 3306: MySQL ===
        elif port == 3306:
            time.sleep(0.5)
            data = sock.recv(1024)
            if data:
                try:
                    # Parse MySQL handshake packet
                    if len(data) > 5:
                        protocol_version = data[4] #Index 4 → protocol version byte
                        version_end = data.find(b'\x00', 5)
                        if version_end > 5:
                            version = data[5:version_end].decode(errors="ignore") #05 35 2E 30 2E 35 31 00 → "5.0.51"
                            banner = f"MySQL {version}"
                        else:
                            banner = "MySQL service"
                    else:
                        banner = "MySQL service"
                except:
                    banner = "MySQL service"
            else:
                banner = "MySQL service"
                
        # === Port 5432: PostgreSQL ===
        elif port == 5432:
            # PostgreSQL version detection through startup message
            try:
                # Send SSLRequest first (common)
                ssl_request = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
                sock.send(ssl_request)
                time.sleep(0.3)
                response = sock.recv(1)
                
                # If 'S', server supports SSL, if 'N', it doesn't
                # Either way, we can try a regular connection
                
                # Send startup message to get version
                startup = (
                    b'\x00\x00\x00\x08'  # Length
                    b'\x04\xd2\x16\x2f'  # Protocol version
                )
                sock.send(startup)
                time.sleep(0.5)
                response = sock.recv(1024)
                
                if response:
                    # Try to find version in response
                    if b'PostgreSQL' in response:
                        banner = response.decode(errors="ignore")
                        # Extract version
                        match = re.search(r'(\d+\.\d+\.?\d*)', banner)
                        if match:
                            banner = f"PostgreSQL {match.group(1)}"
                        else:
                            banner = "PostgreSQL service"
                    else:
                        banner = "PostgreSQL service"
                else:
                    banner = "PostgreSQL service"
            except:
                banner = "PostgreSQL service"
                
        # === Generic ===
        else:
            time.sleep(0.5)
            banner = sock.recv(2048).decode(errors="ignore").strip()
        
        sock.close()
        return banner if banner else "No banner"
        
    except socket.timeout:
        return "Connection timeout"
    except ConnectionRefusedError:
        return "Connection refused"
    except Exception as e:
        return "No banner"

