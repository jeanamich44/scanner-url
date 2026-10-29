import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# --------------------------------------------------

def inspect_ssl(hostname: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    output: Dict[str, Any] = {
        "hostname": hostname,
        "port": port,
        "enabled": False,
        "valid": False,
        "error": None,
        "issuer": {},
        "subject": {},
        "version": None,
        "cipher": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "san": []
    }

    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher_info = ssock.cipher()
                version = ssock.version()

                output["enabled"] = True
                output["valid"] = True
                output["version"] = version
                output["cipher"] = cipher_info

                if cert:
                    if "issuer" in cert:
                        output["issuer"] = {item[0][0]: item[0][1] for item in cert["issuer"] if item}
                    if "subject" in cert:
                        output["subject"] = {item[0][0]: item[0][1] for item in cert["subject"] if item}
                    if "notBefore" in cert:
                        dt_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        output["not_before"] = dt_before.isoformat()
                    if "notAfter" in cert:
                        dt_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        output["not_after"] = dt_after.isoformat()
                        now = datetime.now(timezone.utc)
                        diff = dt_after - now
                        output["days_remaining"] = diff.days
                        if diff.total_seconds() < 0:
                            output["valid"] = False
                            output["error"] = "Certificat expiré"
                    if "subjectAltName" in cert:
                        output["san"] = [item[1] for item in cert["subjectAltName"] if len(item) > 1]
    except ssl.SSLError as e:
        output["enabled"] = True
        output["valid"] = False
        output["error"] = str(e)
    except Exception as e:
        output["enabled"] = False
        output["valid"] = False
        output["error"] = str(e)

    return output
