import socket
from typing import Any, Dict, List
import dns.resolver
import dns.reversename

# --------------------------------------------------

def inspect_dns(hostname: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        "hostname": hostname,
        "a": [],
        "aaaa": [],
        "mx": [],
        "ns": [],
        "txt": [],
        "cname": [],
        "soa": [],
        "reverse_ptr": []
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    for rtype in record_types:
        try:
            answers = resolver.resolve(hostname, rtype)
            for rdata in answers:
                if rtype == "MX":
                    results["mx"].append({
                        "preference": int(rdata.preference),
                        "exchange": str(rdata.exchange).rstrip(".")
                    })
                elif rtype == "TXT":
                    results["txt"].append(rdata.to_text().strip('"'))
                else:
                    results[rtype.lower()].append(str(rdata).rstrip("."))
        except Exception:
            pass

    if results["a"]:
        first_ip = results["a"][0]
        try:
            rev_name = dns.reversename.from_address(first_ip)
            ptr_answers = resolver.resolve(rev_name, "PTR")
            for ptr in ptr_answers:
                results["reverse_ptr"].append(str(ptr).rstrip("."))
        except Exception:
            pass

    return results
