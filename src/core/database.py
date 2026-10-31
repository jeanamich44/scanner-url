import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

# --------------------------------------------------

DB_PATH = Path(__file__).resolve().parents[2] / "data" / "hits.db"

# --------------------------------------------------

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# --------------------------------------------------

def save_hit(hit: Dict[str, Any]) -> int:
    conn = get_connection()
    try:
        cur = conn.cursor()
        matches_json = json.dumps(hit.get("matches", []), ensure_ascii=False)
        cur.execute("""
            INSERT INTO hits (
                created_at, target_url, endpoint, full_url, status_code,
                severity, capture, sensitive_matches, snippet, content_length,
                content_type, response_time_ms, bot_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(target_url, endpoint) DO UPDATE SET
                created_at = excluded.created_at,
                full_url = excluded.full_url,
                status_code = excluded.status_code,
                severity = excluded.severity,
                capture = excluded.capture,
                sensitive_matches = excluded.sensitive_matches,
                snippet = excluded.snippet,
                content_length = excluded.content_length,
                content_type = excluded.content_type,
                response_time_ms = excluded.response_time_ms,
                bot_id = excluded.bot_id
        """, (
            hit.get("time", ""),
            hit.get("url", ""),
            hit.get("ep", ""),
            hit.get("full_url", ""),
            int(hit.get("status", 0)),
            hit.get("type", "INFO"),
            hit.get("capture", ""),
            matches_json,
            hit.get("snippet", ""),
            int(hit.get("size", 0)),
            hit.get("content_type", ""),
            float(hit.get("ms", 0.0)),
            int(hit.get("bot", 1))
        ))
        conn.commit()
        return cur.lastrowid or 0
    finally:
        conn.close()

# --------------------------------------------------

def fetch_all_hits(limit: int = 5000) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        rows = cur.execute("""
            SELECT id, created_at, target_url, endpoint, full_url, status_code,
                   severity, capture, sensitive_matches, snippet, content_length,
                   content_type, response_time_ms, bot_id
            FROM hits
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        results = []
        for r in rows:
            matches = []
            if r["sensitive_matches"]:
                try:
                    matches = json.loads(r["sensitive_matches"])
                except Exception:
                    matches = []
            results.append({
                "id": r["id"],
                "time": r["created_at"],
                "url": r["target_url"],
                "ep": r["endpoint"],
                "full_url": r["full_url"],
                "status": r["status_code"],
                "type": r["severity"],
                "capture": r["capture"] or "",
                "matches": matches,
                "snippet": r["snippet"] or "",
                "size": r["content_length"] or 0,
                "content_type": r["content_type"] or "",
                "ms": r["response_time_ms"] or 0.0,
                "bot": r["bot_id"] or 1
            })
        return results
    finally:
        conn.close()

# --------------------------------------------------

def fetch_db_stats() -> Dict[str, int]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        total = cur.execute("SELECT COUNT(*) FROM hits").fetchone()[0]
        crit = cur.execute("SELECT COUNT(*) FROM hits WHERE severity = 'CRITICAL'").fetchone()[0]
        high = cur.execute("SELECT COUNT(*) FROM hits WHERE severity = 'HIGH'").fetchone()[0]
        med = cur.execute("SELECT COUNT(*) FROM hits WHERE severity = 'MEDIUM'").fetchone()[0]
        low = cur.execute("SELECT COUNT(*) FROM hits WHERE severity = 'LOW'").fetchone()[0]
        info = cur.execute("SELECT COUNT(*) FROM hits WHERE severity = 'INFO'").fetchone()[0]
        return {
            "total": total,
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
            "info": info
        }
    finally:
        conn.close()

# --------------------------------------------------

def delete_all_hits() -> None:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM hits")
        try:
            cur.execute("DELETE FROM sqlite_sequence WHERE name = 'hits'")
        except Exception:
            pass
        conn.commit()
    finally:
        conn.close()

# --------------------------------------------------

def delete_hit_by_id(hit_id: int) -> bool:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM hits WHERE id = ?", (hit_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()

# --------------------------------------------------

def delete_hits_by_ids(hit_ids: List[int]) -> int:
    if not hit_ids:
        return 0
    conn = get_connection()
    try:
        cur = conn.cursor()
        placeholders = ",".join("?" for _ in hit_ids)
        cur.execute(f"DELETE FROM hits WHERE id IN ({placeholders})", hit_ids)
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()
