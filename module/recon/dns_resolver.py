import socket

def resolve_dns(target: str) -> dict:
    result = {"domain": target, "ip": None, "reverse": None}

    try:
        ip = socket.gethostbyname(target)
        result["ip"] = ip
        try:
            rev = socket.gethostbyaddr(ip)[0]
            result["reverse"] = rev
        except:
            result["reverse"] = "No PTR record"
    except:
        result["ip"] = "Resolution failed"
    return result

"""Reverse DNS = convert IP back to a domain.

Example:

Forward lookup:
google.com → 142.250.182.14

Reverse lookup (PTR):
142.250.182.14 → maa03s48-in-f14.1e100.net

PTR = “Pointer Record”, used for:

✔ Email server validation
✔ Identifying servers
✔ Fingerprinting"""