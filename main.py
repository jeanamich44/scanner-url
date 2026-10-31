import asyncio
import json
import re
import sys
import threading
import time
import uuid
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

import uvicorn
from curl_cffi.requests import AsyncSession
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from src.core.scanner import UrlScanner
from src.core.endpoint_scanner import load_endpoints, probe_fast, _analyze_resp
from src.core.browser_profiles import get_browser_profile
from src.core.proxy_manager import ProxyManager, format_proxy_line
from src.core.database import (
    save_hit,
    fetch_all_hits,
    fetch_db_stats,
    delete_all_hits,
    delete_hit_by_id,
    delete_hits_by_ids,
)

# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# --------------------------------------------------

app = FastAPI(title="URL Scanner", version="5.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

JOBS: Dict[str, Dict[str, Any]] = {}
GLOBAL_HITS: List[Dict[str, Any]] = []

# --------------------------------------------------

class BatchRequest(BaseModel):
    urls: List[str]
    timeout: Optional[float] = 5.0
    top_endpoints: Optional[int] = 100
    bots: Optional[int] = 10
    url_bots: Optional[int] = 10
    endpoint_bots: Optional[int] = 1
    use_bypass: Optional[bool] = True
    use_mutations: Optional[bool] = True
    browser: Optional[str] = "chrome"
    proxies: Optional[List[str]] = None
    use_proxy: Optional[bool] = False

# --------------------------------------------------

class ConcurrencyRequest(BaseModel):
    url_bots: Optional[int] = None
    endpoint_bots: Optional[int] = None

# --------------------------------------------------

class DeleteBatchRequest(BaseModel):
    ids: List[int]

# --------------------------------------------------

@app.get("/")
def serve_ui():
    p = BASE_DIR / "static" / "ui.html"
    if not p.exists():
        raise HTTPException(404)
    return FileResponse(p, media_type="text/html")

# --------------------------------------------------

@app.get("/hits")
def serve_hits_ui():
    p = BASE_DIR / "static" / "hits.html"
    if not p.exists():
        raise HTTPException(404)
    return FileResponse(p, media_type="text/html")

# --------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}

# --------------------------------------------------

@app.get("/api/defaults")
def get_defaults():
    eps = load_endpoints()
    return {
        "endpoints_count": len(eps),
        "default_bots": 10,
        "default_url_bots": 10,
        "default_ep_bots": 1,
        "default_timeout": 5.0,
        "default_top_endpoints": 100,
        "default_browser": "chrome"
    }

# --------------------------------------------------

def _normalize_target(u: str) -> str:
    cleaned = u.strip()
    if not cleaned:
        return ""
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
    return cleaned.rstrip("/")

# --------------------------------------------------

def _extract_origin_and_prefix(raw: str) -> Tuple[str, str]:
    cleaned = raw.strip()
    if not cleaned:
        return ("", "/")
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
    parsed = urlparse(cleaned)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    if path == "/" or not path:
        return (origin, "/")
    parts = path.rstrip("/").split("/")
    if "." in parts[-1]:
        prefix = "/".join(parts[:-1]) + "/"
    else:
        prefix = path.rstrip("/") + "/"
    if not prefix or prefix == "/":
        prefix = "/"
    return (origin, prefix)

# --------------------------------------------------

LISTING_PATTERNS = [
    "index of /",
    "index of/",
    "directory listing for",
    "directory listing of",
    "[to parent directory]",
    ">parent directory</a>",
    'alt="[parentdir]"',
    "<title>directory:",
    "httpfileserver",
    "listing: /",
    "directory of /",
]

MAX_CRAWL_DEPTH = 4

# --------------------------------------------------

def _detect_listing(body: str, content_type: str = "") -> bool:
    if not body:
        return False
    body_lower = body.lower()
    ct = content_type.lower()
    for p in LISTING_PATTERNS:
        if p in body_lower:
            return True
    if "application/json" in ct:
        try:
            data = json.loads(body)
            if isinstance(data, list) and len(data) > 0:
                if any("type" in item and item["type"] in ("directory", "file") for item in data if isinstance(item, dict)):
                    return True
        except Exception:
            pass
    if ("application/xml" in ct or "text/xml" in ct):
        if "<list>" in body_lower and ("<directory>" in body_lower or "<file>" in body_lower):
            return True
    return False

# --------------------------------------------------

_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

def _parse_listing_links(body: str, base_url: str) -> Tuple[List[str], List[str]]:
    files = []
    dirs = []
    base_url = base_url.rstrip("/") + "/"
    for m in _HREF_RE.finditer(body):
        href = m.group(1)
        if href.startswith(("?", "#", "mailto:", "javascript:")):
            continue
        if href.startswith(("http://", "https://")):
            ph = urlparse(href)
            pb = urlparse(base_url)
            if ph.netloc != pb.netloc:
                continue
            href = ph.path
        if href in ("/", "../", "./"):
            continue
        ctx = body[max(0, m.start() - 80):m.end() + 20].lower()
        if "parent directory" in ctx:
            continue
        full = urljoin(base_url, href)
        if href.endswith("/"):
            dirs.append(full)
        else:
            files.append(full)
    return files, dirs

# --------------------------------------------------

async def _crawl_tree(
    session: AsyncSession,
    url: str,
    endpoint_basenames: Set[str],
    depth: int,
    headers: dict,
    timeout: float,
) -> List[Tuple[str, str]]:
    if depth > MAX_CRAWL_DEPTH:
        return []
    matches = []
    try:
        resp = await session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        body = resp.text or ""
        ct = resp.headers.get("content-type", "")
        if not _detect_listing(body, ct):
            return []
        files, dirs = _parse_listing_links(body, url)
        for f_url in files:
            fname = f_url.rstrip("/").split("/")[-1].lower()
            if fname in endpoint_basenames:
                rel = "/" + f_url.split("://", 1)[-1].split("/", 1)[-1] if "/" in f_url.split("://", 1)[-1] else "/"
                matches.append((f_url, rel))
        for d_url in dirs:
            sub = await _crawl_tree(session, d_url, endpoint_basenames, depth + 1, headers, timeout)
            matches.extend(sub)
    except Exception:
        pass
    return matches

# --------------------------------------------------

@app.post("/batch")
async def batch_scan(payload: BatchRequest):
    jid = str(uuid.uuid4())[:8]

    origin_map: Dict[str, Set[str]] = {}
    for raw in payload.urls:
        origin, prefix = _extract_origin_and_prefix(raw)
        if not origin:
            continue
        if origin not in origin_map:
            origin_map[origin] = set()
        origin_map[origin].add(prefix)

    targets = [(origin, sorted(prefixes)) for origin, prefixes in origin_map.items()]

    if not targets:
        raise HTTPException(400, "Aucune URL valide fournie.")

    top_n = payload.top_endpoints or 100
    all_endpoints = load_endpoints(top_n=top_n)
    if not all_endpoints:
        raise HTTPException(500, "Impossible de charger endpoints.json")

    full_dict_endpoints = load_endpoints()
    endpoint_basenames: Set[str] = set()
    for ep in full_dict_endpoints:
        parts = ep["endpoint"].rstrip("/").split("/")
        if parts:
            endpoint_basenames.add(parts[-1].lower())

    url_concurrency = max(1, min(payload.url_bots or payload.bots or 10, 300))
    ep_concurrency = max(1, min(payload.endpoint_bots or 1, 20))
    total_concurrency = url_concurrency * ep_concurrency
    timeout = max(1.0, min(payload.timeout or 5.0, 30.0))
    use_bypass = payload.use_bypass if payload.use_bypass is not None else True
    use_mutations = payload.use_mutations if payload.use_mutations is not None else True
    raw_browser = (payload.browser or "chrome").strip().lower()
    browser_choice = raw_browser if raw_browser in ["chrome", "firefox", "safari", "random"] else "chrome"

    proxy_mgr = ProxyManager()
    if payload.use_proxy:
        if payload.proxies:
            proxy_mgr.load_list(payload.proxies)
        else:
            local_proxy_file = BASE_DIR / "proxy.txt"
            if not local_proxy_file.exists():
                local_proxy_file = BASE_DIR / "proxies.txt"
            if local_proxy_file.exists():
                proxy_mgr.load_file(str(local_proxy_file))

    total_urls = len(targets)
    total_ep = len(all_endpoints)
    total_tasks = total_urls * total_ep

    JOBS[jid] = {
        "status": "running",
        "events": [],
        "cancel": False,
        "hits": [],
        "created_at": datetime.now().isoformat(),
        "url_concurrency": url_concurrency,
        "ep_concurrency": ep_concurrency,
    }

    def push(etype: str, data: Any):
        JOBS[jid]["events"].append({"t": etype, "d": data})

    async def runner():
        url_queue: asyncio.Queue = asyncio.Queue()
        for t in targets:
            url_queue.put_nowait(t)

        start_time = time.time()
        alive_targets = set()
        g = {
            "total_tasks": total_tasks,
            "done": 0,
            "hits": 0,
            "bad": 0,
            "errors": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "active_bots": 0,
            "checks_ts": [],
        }

        push("init", {
            "total_urls": total_urls,
            "total_ep": total_ep,
            "total_tasks": total_tasks,
            "url_bots": url_concurrency,
            "ep_bots": ep_concurrency,
            "bots": url_concurrency,
        })

        push("log", {
            "cls": "sys",
            "msg": f"Runner initialisé avec succès : {total_urls} URLs, {total_ep} endpoints ({total_tasks} vérifications). {url_concurrency} Bots URL × {ep_concurrency} Bots Endpoints ({total_concurrency} flux max). Profil: {browser_choice.upper()} | Proxys: {proxy_mgr.count()} actifs."
        })

        last_stats_emit = 0.0

        def emit_stats_now():
            nonlocal last_stats_emit
            now = time.time()
            last_stats_emit = now
            g["checks_ts"] = [t for t in g["checks_ts"] if now - t < 60]
            cpm = len(g["checks_ts"])
            elapsed = round(now - start_time, 1)
            to_check = max(0, g["total_tasks"] - g["done"])
            time_left = round((to_check / (cpm / 60)), 1) if cpm > 0 else 0
            pct = round((g["done"] / g["total_tasks"] * 100), 1) if g["total_tasks"] else 0

            push("stats", {
                "total": g["total_tasks"],
                "done": g["done"],
                "to_check": to_check,
                "pct": pct,
                "hits": g["hits"],
                "bad": g["bad"],
                "errors": g["errors"],
                "cpm": cpm,
                "elapsed": elapsed,
                "time_left": time_left,
                "active_bots": g["active_bots"],
                "total_bots": JOBS[jid].get("url_concurrency", url_concurrency),
                "endpoint_bots": JOBS[jid].get("ep_concurrency", ep_concurrency),
                "critical": g["critical"],
                "high": g["high"],
                "medium": g["medium"],
                "low": g["low"],
                "info": g["info"],
                "total_urls": total_urls,
                "alive_urls": len(alive_targets),
            })

        async def process_hit(wid, origin, ep_path, full_url, r, sev, status_code):
            g["hits"] += 1
            if sev in g:
                g[sev] += 1
            hit_obj = {
                "id": 0,
                "job_id": jid,
                "time": datetime.now().strftime("%H:%M:%S"),
                "bot": wid + 1,
                "url": origin,
                "ep": ep_path,
                "full_url": full_url,
                "status": status_code,
                "type": sev.upper(),
                "size": r.get("content_length", 0),
                "ms": r.get("response_time_ms", 0),
                "content_type": r.get("content_type", ""),
                "capture": ", ".join(r.get("sensitive_data", [])) or (f"{status_code} Accessible ({r.get('content_type', '')})" if r.get("content_type") else f"{status_code} Accessible"),
                "matches": r.get("sensitive_matches", []),
                "snippet": r.get("snippet", ""),
            }
            db_id = save_hit(hit_obj)
            if db_id:
                hit_obj["id"] = db_id
            JOBS[jid]["hits"].append(hit_obj)
            push("hit", hit_obj)
            push("log", {
                "cls": "hit",
                "msg": f"[HIT] Bot URL {wid+1} : {full_url} \u2192 {status_code} [{sev.upper()}] ({r.get('content_length')}b)"
            })

        async def url_worker(wid: int):
            impersonate_val, base_headers = get_browser_profile(browser_choice)
            worker_proxy = proxy_mgr.get_proxy() if proxy_mgr.has_proxies() else None
            proxy_arg = {"proxy": worker_proxy} if worker_proxy else {}

            async with AsyncSession(impersonate=impersonate_val, **proxy_arg) as session:
                while not JOBS[jid].get("cancel"):
                    target_ub = JOBS[jid].get("url_concurrency", url_concurrency)
                    if wid >= target_ub:
                        break
                    try:
                        origin, prefixes = url_queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break

                    g["active_bots"] += 1
                    push("bot", {
                        "id": wid,
                        "url": origin,
                        "ep": "Détection listing...",
                        "st": "<<< PROCESSING URL >>>",
                    })

                    listing_found = False
                    crawl_base = None

                    try:
                        resp_root = await session.get(origin + "/", headers=base_headers, timeout=timeout, allow_redirects=True)
                        body_root = resp_root.text or ""
                        ct_root = resp_root.headers.get("content-type", "")
                        if _detect_listing(body_root, ct_root):
                            listing_found = True
                            crawl_base = origin + "/"
                            alive_targets.add(origin)
                            push("log", {"cls": "sys", "msg": f"[BOT {wid+1}] {origin} \u2192 Directory Listing détecté (racine)"})
                    except Exception:
                        pass

                    if not listing_found:
                        for pfx in prefixes:
                            if pfx == "/" or JOBS[jid].get("cancel"):
                                continue
                            try:
                                pfx_url = origin + pfx
                                resp_pfx = await session.get(pfx_url, headers=base_headers, timeout=timeout, allow_redirects=True)
                                body_pfx = resp_pfx.text or ""
                                ct_pfx = resp_pfx.headers.get("content-type", "")
                                if _detect_listing(body_pfx, ct_pfx):
                                    listing_found = True
                                    crawl_base = pfx_url
                                    alive_targets.add(origin)
                                    push("log", {"cls": "sys", "msg": f"[BOT {wid+1}] {origin} \u2192 Directory Listing détecté ({pfx})"})
                                    break
                            except Exception:
                                pass

                    crawl_discovered = []
                    if listing_found and crawl_base:
                        push("bot", {
                            "id": wid,
                            "url": origin,
                            "ep": f"CRAWL: {crawl_base}",
                            "st": "<<< CRAWL MODE >>>",
                            "total_slots": ep_concurrency,
                        })

                        push("ep_branch", {
                            "bot_id": wid,
                            "slot_id": 0,
                            "url": origin,
                            "ep": "Crawl arbre en cours...",
                            "st": "PROCESSING",
                            "total_slots": ep_concurrency,
                        })

                        crawl_discovered = await _crawl_tree(session, crawl_base, endpoint_basenames, 0, base_headers, timeout)

                        unique_crawl = []
                        seen_crawl = set()
                        for f_url, rel in crawl_discovered:
                            low_u = f_url.lower()
                            if low_u not in seen_crawl:
                                seen_crawl.add(low_u)
                                unique_crawl.append((f_url, rel))
                        crawl_discovered = unique_crawl

                        crawl_ep_count = len(crawl_discovered)
                        push("log", {"cls": "sys", "msg": f"[BOT {wid+1}] {origin} \u2192 {crawl_ep_count} fichiers sensibles supplémentaires découverts via crawl"})

                    cur_ep = JOBS[jid].get("ep_concurrency", ep_concurrency)
                    push("bot", {
                        "id": wid,
                        "url": origin,
                        "ep": f"Brute-force ({cur_ep} flux)...",
                        "st": "<<< PROCESSING URL >>>",
                        "total_slots": cur_ep,
                    })

                    slot_queue = asyncio.Queue()
                    active_slots = set()
                    for s in range(cur_ep):
                        slot_queue.put_nowait(s)
                        active_slots.add(s)

                    def check_expand_slots():
                        target_eb = JOBS[jid].get("ep_concurrency", ep_concurrency)
                        if target_eb > len(active_slots):
                            for s in range(len(active_slots), target_eb):
                                active_slots.add(s)
                                slot_queue.put_nowait(s)

                    def release_slot(slot_id: int):
                        target_eb = JOBS[jid].get("ep_concurrency", ep_concurrency)
                        if slot_id < target_eb:
                            slot_queue.put_nowait(slot_id)
                        else:
                            active_slots.discard(slot_id)

                    async def scan_single_ep(base_u: str, ep: Dict[str, Any]):
                        check_expand_slots()
                        slot_id = await slot_queue.get()
                        try:
                            if JOBS[jid].get("cancel"):
                                return

                            cur_slots = JOBS[jid].get("ep_concurrency", ep_concurrency)
                            ep_path = ep["endpoint"]
                            score = ep.get("score", 0)

                            push("ep_branch", {
                                "bot_id": wid,
                                "slot_id": slot_id,
                                "url": base_u,
                                "ep": ep_path,
                                "st": "PROCESSING",
                                "total_slots": cur_slots,
                            })

                            push("bot", {
                                "id": wid,
                                "url": base_u,
                                "ep": ep_path,
                                "st": f"<<< REQ ({cur_slots} flux) >>>",
                                "total_slots": cur_slots,
                            })

                            try:
                                r = await probe_fast(
                                    session=session,
                                    base_url=base_u,
                                    endpoint=ep_path,
                                    score=score,
                                    timeout=timeout,
                                    use_bypass=use_bypass,
                                    use_mutations=use_mutations,
                                    headers=base_headers,
                                )
                            except Exception:
                                r = {
                                    "status": 0,
                                    "severity": "none",
                                    "accessible": False,
                                    "content_length": 0,
                                    "response_time_ms": 0,
                                    "sensitive_data": [],
                                    "sensitive_matches": [],
                                    "snippet": "",
                                }

                            g["done"] += 1
                            g["checks_ts"].append(time.time())

                            sev = r.get("severity", "none")
                            status_code = r.get("status")
                            st_branch = "IDLE"

                            if not status_code:
                                g["errors"] += 1
                                st_branch = "ERROR"
                            else:
                                alive_targets.add(base_u)
                                st_branch = f"STATUS: [{status_code}]"

                            if r.get("accessible"):
                                full_url = base_u.rstrip("/") + ep_path
                                await process_hit(wid, base_u, ep_path, full_url, r, sev, status_code)
                                st_branch = f"HIT: [{status_code}] {sev.upper()}"
                                push("bot", {
                                    "id": wid,
                                    "url": base_u,
                                    "ep": ep_path,
                                    "st": f"<<< SUCCESS: [{status_code}] HIT ({sev.upper()}) >>>",
                                    "total_slots": cur_slots,
                                })
                            else:
                                if status_code == 404:
                                    g["bad"] += 1
                                    st_branch = "404 MISS"
                                push("bot", {
                                    "id": wid,
                                    "url": base_u,
                                    "ep": ep_path,
                                    "st": f"<<< REQ ({cur_slots} flux) >>>",
                                    "total_slots": cur_slots,
                                })

                            push("ep_branch", {
                                "bot_id": wid,
                                "slot_id": slot_id,
                                "url": base_u,
                                "ep": ep_path,
                                "st": st_branch,
                                "status_code": status_code,
                                "total_slots": cur_slots,
                            })

                            now_tick = time.time()
                            if now_tick - last_stats_emit > 0.08:
                                emit_stats_now()

                        finally:
                            release_slot(slot_id)

                    async def probe_crawled(full_url: str, rel_path: str):
                        check_expand_slots()
                        slot_id = await slot_queue.get()
                        try:
                            if JOBS[jid].get("cancel"):
                                return

                            cur_slots = JOBS[jid].get("ep_concurrency", ep_concurrency)
                            push("ep_branch", {
                                "bot_id": wid,
                                "slot_id": slot_id,
                                "url": origin,
                                "ep": f"[CRAWL] {rel_path}",
                                "st": "PROCESSING",
                                "total_slots": cur_slots,
                            })

                            push("bot", {
                                "id": wid,
                                "url": origin,
                                "ep": f"[CRAWL] {rel_path}",
                                "st": "<<< PROBE CRAWL >>>",
                                "total_slots": cur_slots,
                            })

                            try:
                                t0 = time.time()
                                resp = await session.get(full_url, headers=base_headers, timeout=timeout, allow_redirects=False)
                                ms = round((time.time() - t0) * 1000, 1)
                                r = _analyze_resp(resp)
                                r["response_time_ms"] = ms
                            except Exception:
                                r = {
                                    "status": 0,
                                    "severity": "none",
                                    "accessible": False,
                                    "content_length": 0,
                                    "response_time_ms": 0,
                                    "sensitive_data": [],
                                    "sensitive_matches": [],
                                    "snippet": "",
                                }

                            g["done"] += 1
                            g["checks_ts"].append(time.time())

                            sev = r.get("severity", "none")
                            status_code = r.get("status")
                            st_branch = "IDLE"

                            if not status_code:
                                g["errors"] += 1
                                st_branch = "ERROR"
                            else:
                                st_branch = f"STATUS: [{status_code}]"

                            if r.get("accessible"):
                                await process_hit(wid, origin, f"[CRAWL] {rel_path}", full_url, r, sev, status_code)
                                st_branch = f"HIT: [{status_code}] {sev.upper()}"
                                push("bot", {
                                    "id": wid,
                                    "url": origin,
                                    "ep": f"[CRAWL] {rel_path}",
                                    "st": f"<<< SUCCESS: [{status_code}] HIT ({sev.upper()}) >>>",
                                    "total_slots": cur_slots,
                                })
                            else:
                                if status_code == 404:
                                    g["bad"] += 1
                                    st_branch = "404 MISS"

                            push("ep_branch", {
                                "bot_id": wid,
                                "slot_id": slot_id,
                                "url": origin,
                                "ep": f"[CRAWL] {rel_path}",
                                "st": st_branch,
                                "status_code": status_code,
                                "total_slots": cur_slots,
                            })

                            now_tick = time.time()
                            if now_tick - last_stats_emit > 0.08:
                                emit_stats_now()

                        finally:
                            release_slot(slot_id)

                    tested_crawl_urls = set()
                    if crawl_discovered:
                        g["total_tasks"] += len(crawl_discovered)
                        emit_stats_now()
                        crawl_tasks = []
                        for f_url, rel in crawl_discovered:
                            tested_crawl_urls.add(f_url.lower())
                            crawl_tasks.append(probe_crawled(f_url, rel))
                        await asyncio.gather(*crawl_tasks)

                    if not JOBS[jid].get("cancel"):
                        bf_tasks = []
                        for ep in all_endpoints:
                            full_ep_url = (origin.rstrip("/") + ep["endpoint"]).lower()
                            if full_ep_url not in tested_crawl_urls:
                                bf_tasks.append(scan_single_ep(origin, ep))
                        if bf_tasks:
                            await asyncio.gather(*bf_tasks)

                    url_queue.task_done()
                    g["active_bots"] = max(0, g["active_bots"] - 1)

                    end_slots = JOBS[jid].get("ep_concurrency", ep_concurrency)
                    for s in range(max(end_slots, len(active_slots))):
                        push("ep_branch", {
                            "bot_id": wid,
                            "slot_id": s,
                            "url": origin,
                            "ep": "—",
                            "st": "IDLE",
                            "total_slots": end_slots,
                        })

                end_slots = JOBS[jid].get("ep_concurrency", ep_concurrency)
                push("bot", {
                    "id": wid,
                    "url": "—",
                    "ep": "—",
                    "st": "<<< IDLE >>>",
                    "total_slots": end_slots,
                })
                for s in range(end_slots):
                    push("ep_branch", {
                        "bot_id": wid,
                        "slot_id": s,
                        "url": "—",
                        "ep": "—",
                        "st": "IDLE",
                        "total_slots": end_slots,
                    })

        worker_tasks: Dict[int, asyncio.Task] = {}

        def spawn_worker(w: int):
            t = asyncio.create_task(url_worker(w))
            worker_tasks[w] = t
            return t

        def set_concurrency(new_ub: Optional[int], new_eb: Optional[int]):
            if new_ub is not None:
                target_ub = max(1, min(new_ub, 300))
                old_ub = JOBS[jid].get("url_concurrency", url_concurrency)
                JOBS[jid]["url_concurrency"] = target_ub
                if target_ub > old_ub:
                    for w in range(target_ub):
                        if w not in worker_tasks or worker_tasks[w].done():
                            spawn_worker(w)
                push("log", {
                    "cls": "sys",
                    "msg": f"Concurrence ajustée en direct : {target_ub} Bots URL (précédent : {old_ub})"
                })
                emit_stats_now()

            if new_eb is not None:
                target_eb = max(1, min(new_eb, 20))
                old_eb = JOBS[jid].get("ep_concurrency", ep_concurrency)
                JOBS[jid]["ep_concurrency"] = target_eb
                push("log", {
                    "cls": "sys",
                    "msg": f"Flux Endpoints ajustés en direct : {target_eb} Ep/URL (précédent : {old_eb})"
                })
                emit_stats_now()

        JOBS[jid]["set_concurrency"] = set_concurrency

        for i in range(url_concurrency):
            spawn_worker(i)

        while not JOBS[jid].get("cancel"):
            all_done = all(t.done() for t in list(worker_tasks.values()))
            if all_done and url_queue.empty():
                break
            await asyncio.sleep(0.08)

        if JOBS[jid].get("cancel"):
            for t in list(worker_tasks.values()):
                if not t.done():
                    t.cancel()

        await asyncio.gather(*worker_tasks.values(), return_exceptions=True)

        emit_stats_now()
        is_cancelled = JOBS[jid].get("cancel", False)
        status_label = "Annulé" if is_cancelled else "Terminé avec succès"
        push("log", {
            "cls": "done",
            "msg": f"Scan {status_label} : {g['done']} tests effectués, {g['hits']} hits découverts."
        })
        push("done", {"cancelled": is_cancelled})
        JOBS[jid]["status"] = "done"

    asyncio.create_task(runner())
    return {"job_id": jid}

# --------------------------------------------------

@app.post("/api/jobs/{jid}/concurrency")
@app.post("/concurrency/{jid}")
async def update_concurrency(jid: str, payload: ConcurrencyRequest):
    job = JOBS.get(jid)
    if not job:
        raise HTTPException(404, "Job introuvable")
    fn = job.get("set_concurrency")
    if fn and job.get("status") == "running":
        fn(payload.url_bots, payload.endpoint_bots)
        return {
            "status": "ok",
            "url_bots": job.get("url_concurrency"),
            "endpoint_bots": job.get("ep_concurrency"),
        }
    return {"status": "ignored"}

# --------------------------------------------------

@app.post("/cancel/{jid}")
async def cancel_job(jid: str):
    job = JOBS.get(jid)
    if not job:
        raise HTTPException(404)
    job["cancel"] = True
    return {"status": "cancelling"}

# --------------------------------------------------

@app.get("/api/hits")
def get_all_hits():
    hits = fetch_all_hits()
    stats = fetch_db_stats()
    return {"hits": hits, "stats": stats, "total": len(hits)}

# --------------------------------------------------

@app.delete("/api/hits")
def clear_all_hits():
    delete_all_hits()
    for j in JOBS.values():
        j["hits"] = []
    return {"status": "cleared"}

# --------------------------------------------------

@app.delete("/api/hits/{hit_id}")
def delete_single_hit(hit_id: int):
    ok = delete_hit_by_id(hit_id)
    if not ok:
        raise HTTPException(404, "Hit introuvable")
    return {"status": "deleted", "id": hit_id}

# --------------------------------------------------

@app.post("/api/hits/delete-batch")
def delete_hits_batch(payload: DeleteBatchRequest):
    count = delete_hits_by_ids(payload.ids)
    return {"status": "deleted", "count": count}

# --------------------------------------------------

@app.get("/api/hits/{jid}")
def get_hits(jid: str):
    job = JOBS.get(jid)
    if not job:
        raise HTTPException(404)
    return {"hits": job.get("hits", [])}

# --------------------------------------------------

@app.get("/stream/{jid}")
async def stream(jid: str):
    job = JOBS.get(jid)
    if not job:
        raise HTTPException(404)

    async def gen():
        c = 0
        while True:
            evts = job["events"]
            if len(evts) > c:
                chunk = evts[c:len(evts)]
                for item in chunk:
                    yield f"data: {json.dumps(item, ensure_ascii=False, default=str)}\n\n"
                c = len(evts)
            if job["status"] == "done" and c >= len(evts):
                yield f"data: {json.dumps({'t': '__close__', 'd': {}})}\n\n"
                break
            await asyncio.sleep(0.04)

    return StreamingResponse(gen(), media_type="text/event-stream")

# --------------------------------------------------

def _open():
    webbrowser.open("http://127.0.0.1:8099")

# --------------------------------------------------

if __name__ == "__main__":
    threading.Timer(1.0, _open).start()
    uvicorn.run(app, host="127.0.0.1", port=8099)
