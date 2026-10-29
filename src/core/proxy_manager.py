import os
import random
from typing import List, Optional

# --------------------------------------------------

def format_proxy_line(raw_proxy: str) -> str:
    raw = raw_proxy.strip()
    if not raw:
        return ""
    scheme = "http"
    for s in ["http://", "https://", "socks5://", "socks4://"]:
        if raw.lower().startswith(s):
            scheme = s[:-3].lower()
            raw = raw[len(s):]
            break
    if "@" in raw:
        try:
            auth, host_port = raw.split("@", 1)
            return f"{scheme}://{auth}@{host_port}"
        except ValueError:
            pass
    parts = raw.split(":")
    if len(parts) == 4:
        host, port, user, password = parts
        return f"{scheme}://{user}:{password}@{host}:{port}"
    elif len(parts) == 2:
        host, port = parts
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{raw}"

# --------------------------------------------------

class ProxyManager:
    def __init__(self, proxies: Optional[List[str]] = None):
        self._proxies: List[str] = []
        self._index: int = 0
        if proxies:
            self.load_list(proxies)

    # --------------------------------------------------

    def load_list(self, raw_list: List[str]) -> None:
        self._proxies = []
        for line in raw_list:
            formatted = format_proxy_line(line)
            if formatted:
                self._proxies.append(formatted)

    # --------------------------------------------------

    def load_file(self, filepath: str) -> None:
        if not os.path.exists(filepath):
            return
        loaded = []
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                l = line.strip()
                if l and not l.startswith("#"):
                    loaded.append(l)
        self.load_list(loaded)

    # --------------------------------------------------

    def get_proxy(self, rotate: bool = True) -> Optional[str]:
        if not self._proxies:
            return None
        if rotate:
            p = self._proxies[self._index % len(self._proxies)]
            self._index += 1
            return p
        return random.choice(self._proxies)

    # --------------------------------------------------

    def get_random_proxy(self) -> Optional[str]:
        if not self._proxies:
            return None
        return random.choice(self._proxies)

    # --------------------------------------------------

    def has_proxies(self) -> bool:
        return len(self._proxies) > 0

    # --------------------------------------------------

    def count(self) -> int:
        return len(self._proxies)
