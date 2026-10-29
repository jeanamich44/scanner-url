import asyncio
import json
import sys
import threading
import time
import uuid
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from curl_cffi.requests import AsyncSession
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from src.core.scanner import UrlScanner
from src.core.endpoint_scanner import load_endpoints, probe_fast
from src.core.browser_profiles import get_browser_profile
from src.core.proxy_manager import ProxyManager, format_proxy_line

# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# --------------------------------------------------

app = FastAPI(title="URL Scanner", version="5.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

JOBS: Dict[str, Dict[str, Any]] = {}

# --------------------------------------------------

class BatchRequest(BaseModel):
    urls: List[str]
    timeout: Optional[float] = 5.0
    top_endpoints: Optional[int] = 100
    bots: Optional[int] = 10
    use_bypass: Optional[bool] = True
    use_mutations: Optional[bool] = True
    browser: Optional[str] = "chrome"
    proxies: Optional[List[str]] = None
    use_proxy: Optional[bool] = False

# --------------------------------------------------

@app.get("/")
def serve_ui():
    p = BASE_DIR / "static" / "ui.html"
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

@app.post("/batch")
async def batch_scan(payload: BatchRequest):
    jid = str(uuid.uuid4())[:8]
    targets = []
    seen = set()
    for raw in payload.urls:
        norm = _normalize_target(raw)
        if norm and norm not in seen:
            seen.add(norm)
            targets.append(norm)

    if not targets:
        raise HTTPException(400, "Aucune URL valide fournie.")

    top_n = payload.top_endpoints or 100
    all_endpoints = load_endpoints(top_n=top_n)
    if not all_endpoints:
        raise HTTPException(500, "Impossible de charger endpoints.json")

    concurrency = max(1, min(payload.bots or 10, 100))
    timeout = max(1.0, min(payload.timeout or 5.0, 30.0))
    use_bypass = payload.use_bypass if payload.use_bypass is not None else True
    use_mutations = payload.use_mutations if payload.use_mutations is not None else True
    browser_choice = payload.browser or "chrome"

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

    JOBS[jid] = {
        "status": "running",
        "events": [],
        "cancel": False,
        "hits": [],
        "created_at": datetime.now().isoformat(),
    }

    def push(etype: str, data: Any):
        JOBS[jid]["events"].append({"t": etype, "d": data})

    async def runner():
        total_urls = len(targets)
        total_ep = len(all_endpoints)
        total_tasks = total_urls * total_ep

        task_queue: asyncio.Queue = asyncio.Queue()
        for u in targets:
            for ep in all_endpoints:
                task_queue.put_nowait((u, ep))

        start_time = time.time()
        g = {
            "done": 0,
            "hits": 0,
            "bad": 0,
            "retries": 0,
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
            "bots": concurrency,
        })

        push("log", {
            "cls": "sys",
            "msg": f"Runner initialisé avec succès : {total_urls} URLs, {total_ep} endpoints ({total_tasks} vérifications), {concurrency} bots. Profil: {browser_choice.upper()} | Proxys: {proxy_mgr.count()} actifs."
        })

        last_stats_emit = 0.0

        def emit_stats_now():
            nonlocal last_stats_emit
            now = time.time()
            last_stats_emit = now
            g["checks_ts"] = [t for t in g["checks_ts"] if now - t < 60]
            cpm = len(g["checks_ts"])
            elapsed = round(now - start_time, 1)
            to_check = max(0, total_tasks - g["done"])
            time_left = round((to_check / (cpm / 60)), 1) if cpm > 0 else 0
            pct = round((g["done"] / total_tasks * 100), 1) if total_tasks else 0

            push("stats", {
                "total": total_tasks,
                "done": g["done"],
                "to_check": to_check,
                "pct": pct,
                "hits": g["hits"],
                "custom": 0,
                "bad": g["bad"],
                "retries": g["retries"],
                "cpm": cpm,
                "elapsed": elapsed,
                "time_left": time_left,
                "active_bots": g["active_bots"],
                "total_bots": concurrency,
                "critical": g["critical"],
                "high": g["high"],
                "medium": g["medium"],
                "low": g["low"],
                "info": g["info"],
                "total_urls": total_urls,
            })

        async def bot_worker(wid: int):
            impersonate_val, base_headers = get_browser_profile(browser_choice)
            bot_proxy = proxy_mgr.get_proxy() if proxy_mgr.has_proxies() else None
            proxy_arg = {"proxy": bot_proxy} if bot_proxy else {}

            async with AsyncSession(impersonate=impersonate_val, **proxy_arg) as session:
                while not JOBS[jid].get("cancel"):
                    try:
                        u, ep = task_queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break

                    g["active_bots"] += 1
                    ep_path = ep["endpoint"]
                    score = ep.get("score", 0)

                    push("bot", {
                        "id": wid,
                        "url": u,
                        "ep": ep_path,
                        "st": "<<< PROCESSING BLOCK: REQUEST (TRY) >>>",
                    })

                    try:
                        r = await probe_fast(
                            session=session,
                            base_url=u,
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
                        }

                    g["done"] += 1
                    g["checks_ts"].append(time.time())

                    sev = r.get("severity", "none")
                    status_code = r.get("status")

                    if r.get("accessible"):
                        g["hits"] += 1
                        if sev in g:
                            g[sev] += 1

                        hit_obj = {
                            "id": g["hits"],
                            "time": datetime.now().strftime("%H:%M:%S"),
                            "bot": wid + 1,
                            "url": u,
                            "ep": ep_path,
                            "status": status_code,
                            "type": sev.upper(),
                            "size": r.get("content_length", 0),
                            "ms": r.get("response_time_ms", 0),
                            "capture": ", ".join(r.get("sensitive_data", [])) or f"{status_code} OK",
                        }
                        JOBS[jid]["hits"].append(hit_obj)
                        push("hit", hit_obj)
                        push("bot", {
                            "id": wid,
                            "url": u,
                            "ep": ep_path,
                            "st": f"<<< SUCCESS: [{status_code}] HIT ({sev.upper()}) >>>",
                        })
                        push("log", {
                            "cls": "hit",
                            "msg": f"[HIT] Bot {wid+1} : {u}{ep_path} \u2192 {status_code} [{sev.upper()}] ({r.get('content_length')}b)"
                        })
                    else:
                        g["bad"] += 1
                        push("bot", {
                            "id": wid,
                            "url": u,
                            "ep": ep_path,
                            "st": f"<<< FAIL: [{status_code or 'ERR'}] MISS >>>",
                        })

                    g["active_bots"] = max(0, g["active_bots"] - 1)
                    task_queue.task_done()

                    now_tick = time.time()
                    if now_tick - last_stats_emit > 0.08:
                        emit_stats_now()

            push("bot", {
                "id": wid,
                "url": "—",
                "ep": "—",
                "st": "<<< IDLE >>>",
            })

        workers = [asyncio.create_task(bot_worker(i)) for i in range(concurrency)]
        await asyncio.gather(*workers)

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

@app.post("/cancel/{jid}")
async def cancel_job(jid: str):
    job = JOBS.get(jid)
    if not job:
        raise HTTPException(404)
    job["cancel"] = True
    return {"status": "cancelling"}

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
