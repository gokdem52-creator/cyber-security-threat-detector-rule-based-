"""Threat Detector: rule-based log analysis API + dashboard (FastAPI + SQLite)."""
import os
import random
import re
import sqlite3
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import unquote_plus

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel



# ======================================================================
# Log parsing
# ======================================================================

"""Parse raw log lines into normalized event dicts.

Supported formats:
  * Apache/Nginx "combined" access logs
  * OpenSSH auth logs (Failed/Accepted password|publickey)
"""

WEB_RE = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(.*?)\s+HTTP/[\d.]+"\s+(\d{3})\s+(\S+)'
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?'
)
SSH_RE = re.compile(
    r"^(\w{3})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)\s+\S+\s+sshd\[\d+\]:\s+"
    r"(Failed|Accepted)\s+\w+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)"
)


def parse_line(line: str) -> Optional[dict]:
    line = line.strip()
    if not line:
        return None
    m = WEB_RE.match(line)
    if m:
        ip, stamp, method, path, status, _size, _ref, ua = m.groups()
        try:
            ts = datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return None
        return {"type": "web", "ip": ip, "ts": ts, "method": method, "path": path,
                "status": int(status), "ua": ua or "", "raw": line}
    m = SSH_RE.match(line)
    if m:
        mon, day, clock, outcome, user, ip = m.groups()
        now = datetime.now(timezone.utc)
        try:
            ts = datetime.strptime(f"{now.year} {mon} {day} {clock}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        ts = ts.replace(tzinfo=timezone.utc)
        if ts > now + timedelta(days=1):  # log from late last year
            ts = ts.replace(year=ts.year - 1)
        return {"type": "ssh", "ip": ip, "ts": ts, "user": user,
                "success": outcome == "Accepted", "raw": line}
    return None


# ======================================================================
# Detection rules
# ======================================================================

"""Rule-based detection engine.

Two kinds of rules:
  * Signature rules   - regexes run against every request (SQLi, XSS, ...).
  * Behavioral rules  - sliding-window counters per source IP (brute force,
                        directory scanning, request floods).
Tune behavior with THRESHOLDS; add signatures to SIGNATURES.
"""

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

SIGNATURES = [
    ("SQL_INJECTION", "high", "SQL injection pattern in request",
     re.compile(r"(union(\s|\+|/\*.*?\*/)+(all\s+)?select|'\s*or\s+['\d]|\bor\s+1\s*=\s*1|"
                r"\bsleep\s*\(|benchmark\s*\(|information_schema|;\s*drop\s+table|xp_cmdshell)", re.I)),
    ("XSS", "medium", "Cross-site scripting payload in request",
     re.compile(r"(<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img[^>]+src)", re.I)),
    ("PATH_TRAVERSAL", "high", "Path traversal / sensitive file access attempt",
     re.compile(r"(\.\./|\.\.\\|/etc/(passwd|shadow)|c:\\windows|boot\.ini)", re.I)),
    ("COMMAND_INJECTION", "critical", "Shell command injection attempt",
     re.compile(r"((;|\||`|\$\()\s*(cat|ls|wget|curl|bash|sh|nc|whoami|id)\b|/bin/(ba)?sh)", re.I)),
]
SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|hydra|wpscan|acunetix|nessus)", re.I)
LOGIN_PATH = re.compile(r"/(login|signin|auth|wp-login)", re.I)

THRESHOLDS = {
    "ssh_fail": 5, "ssh_window": 60,
    "login_fail": 10, "login_window": 60,
    "scan_404": 15, "scan_window": 60,
    "flood_reqs": 100, "flood_window": 10,
}


def _decode(s: str) -> str:
    return unquote_plus(unquote_plus(s))  # twice: catches double-encoded payloads


def _alert(rule, severity, ip, ts, description, evidence):
    return {"rule": rule, "severity": severity, "ip": ip, "ts": ts.isoformat(),
            "description": description, "evidence": evidence[:300]}


class Detector:
    def __init__(self, thresholds=None):
        self.t = {**THRESHOLDS, **(thresholds or {})}
        self.win = defaultdict(lambda: defaultdict(deque))
        self.last = {}

    def _push(self, key, ip, ts, secs, item=None):
        dq = self.win[key][ip]
        dq.append((ts, item))
        self._prune(dq, ts, secs)
        return dq

    @staticmethod
    def _prune(dq, ts, secs):
        while dq and (ts - dq[0][0]).total_seconds() > secs:
            dq.popleft()

    def _cool(self, key, ip, ts, secs):
        """True at most once per `secs` for a (rule, ip) pair, to avoid alert spam."""
        last = self.last.get((key, ip))
        if last and (ts - last).total_seconds() < secs:
            return False
        self.last[(key, ip)] = ts
        return True

    def process(self, e):
        t, ip, ts, raw = self.t, e["ip"], e["ts"], e["raw"]
        out = []
        if e["type"] == "web":
            target = _decode(e["path"])
            for rule, sev, desc, rx in SIGNATURES:
                if rx.search(target):
                    out.append(_alert(rule, sev, ip, ts, desc, raw))
            m = SCANNER_UA.search(e["ua"])
            if m and self._cool("scanner", ip, ts, 300):
                out.append(_alert("SCANNER_USER_AGENT", "medium", ip, ts,
                                  f"Known attack tool user-agent: {m.group(1).lower()}", raw))
            dq = self._push("flood", ip, ts, t["flood_window"])
            if len(dq) >= t["flood_reqs"] and self._cool("flood", ip, ts, t["flood_window"]):
                out.append(_alert("REQUEST_FLOOD", "high", ip, ts,
                                  f"{len(dq)} requests in {t['flood_window']}s (possible DoS)", raw))
            if e["status"] == 404:
                dq = self._push("scan", ip, ts, t["scan_window"], e["path"])
                paths = {p for _, p in dq}
                if len(paths) >= t["scan_404"] and self._cool("scan", ip, ts, t["scan_window"]):
                    out.append(_alert("DIRECTORY_SCAN", "medium", ip, ts,
                                      f"{len(paths)} distinct 404 paths in {t['scan_window']}s", raw))
            if e["method"] == "POST" and LOGIN_PATH.search(e["path"]) and e["status"] in (401, 403):
                dq = self._push("login", ip, ts, t["login_window"])
                if len(dq) >= t["login_fail"] and self._cool("login", ip, ts, t["login_window"]):
                    out.append(_alert("WEB_LOGIN_BRUTE_FORCE", "high", ip, ts,
                                      f"{len(dq)} failed web logins in {t['login_window']}s", raw))
        else:  # ssh
            if not e["success"]:
                dq = self._push("ssh_fail", ip, ts, t["ssh_window"])
                if len(dq) >= t["ssh_fail"] and self._cool("ssh", ip, ts, t["ssh_window"]):
                    out.append(_alert("SSH_BRUTE_FORCE", "high", ip, ts,
                                      f"{len(dq)} failed SSH logins in {t['ssh_window']}s", raw))
            else:
                dq = self.win["ssh_fail"][ip]
                self._prune(dq, ts, t["ssh_window"])
                if len(dq) >= t["ssh_fail"]:
                    out.append(_alert("BRUTE_FORCE_SUCCESS", "critical", ip, ts,
                                      f"Successful SSH login as '{e['user']}' after {len(dq)} recent failures "
                                      "(possible compromise)", raw))
        return out


def analyze(events, thresholds=None):
    det = Detector(thresholds)
    alerts = []
    for e in sorted(events, key=lambda x: x["ts"]):
        alerts.extend(det.process(e))
    return alerts


# ======================================================================
# SQLite storage
# ======================================================================

def _path():
    return os.getenv("DB_PATH", "data/threats.db")


def conn():
    path = _path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    return c


def db_init():
    c = conn()
    with c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL, rule TEXT NOT NULL, severity TEXT NOT NULL,
            ip TEXT NOT NULL, description TEXT NOT NULL, evidence TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value INTEGER NOT NULL);
        """)
    c.close()


def db_save(alerts, lines):
    c = conn()
    with c:
        c.executemany(
            "INSERT INTO alerts(ts,rule,severity,ip,description,evidence) "
            "VALUES(:ts,:rule,:severity,:ip,:description,:evidence)", alerts)
        c.execute("INSERT INTO meta(key,value) VALUES('lines',?) "
                  "ON CONFLICT(key) DO UPDATE SET value=value+excluded.value", (lines,))
    c.close()


def db_query(severity=None, q=None, limit=200):
    sql, args = "SELECT * FROM alerts WHERE 1=1", []
    if severity:
        sql += " AND severity=?"; args.append(severity)
    if q:
        sql += " AND (ip LIKE ? OR rule LIKE ? OR description LIKE ?)"; args += [f"%{q}%"] * 3
    sql += " ORDER BY ts DESC, id DESC LIMIT ?"; args.append(limit)
    c = conn()
    try:
        return [dict(r) for r in c.execute(sql, args)]
    finally:
        c.close()


def db_stats():
    c = conn()
    try:
        lines = c.execute("SELECT value FROM meta WHERE key='lines'").fetchone()
        return {
            "lines_processed": lines[0] if lines else 0,
            "total_alerts": c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
            "by_severity": {r[0]: r[1] for r in c.execute(
                "SELECT severity, COUNT(*) FROM alerts GROUP BY severity")},
            "by_rule": [dict(r) for r in c.execute(
                "SELECT rule, severity, COUNT(*) AS count FROM alerts GROUP BY rule ORDER BY count DESC")],
            "top_ips": [dict(r) for r in c.execute(
                "SELECT ip, COUNT(*) AS count FROM alerts GROUP BY ip ORDER BY count DESC LIMIT 8")],
            "timeline": [dict(r) for r in c.execute(
                "SELECT substr(ts,1,15)||'0' AS bucket, COUNT(*) AS count FROM alerts "
                "GROUP BY bucket ORDER BY bucket")],
        }
    finally:
        c.close()


def db_clear():
    c = conn()
    with c:
        c.execute("DELETE FROM alerts")
        c.execute("DELETE FROM meta")
    c.close()


# ======================================================================
# Demo data generator
# ======================================================================

"""Generate realistic demo logs containing a mix of normal traffic and attacks."""

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
PAGES = ["/", "/index.html", "/about", "/products", "/products/42", "/contact", "/api/items", "/static/app.js"]


def _web(t, ip, path, status=200, method="GET", ua=UA):
    return t, f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S +0000}] "{method} {path} HTTP/1.1" {status} 512 "-" "{ua}"'


def _ssh(t, ip, user, ok, rnd):
    word = "Accepted" if ok else "Failed"
    inv = "" if ok or user == "root" else "invalid user "
    return t, (f"{t:%b} {t.day:2d} {t:%H:%M:%S} web01 sshd[{rnd.randint(1000, 9999)}]: "
               f"{word} password for {inv}{user} from {ip} port {rnd.randint(30000, 60000)} ssh2")


def generate(seed=7, now=None):
    rnd = random.Random(seed)
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    start = now - timedelta(hours=2)
    at = lambda s: start + timedelta(seconds=s)
    rows = []
    for _ in range(300):  # normal traffic
        ip = f"10.0.{rnd.randint(0, 3)}.{rnd.randint(2, 200)}"
        rows.append(_web(at(rnd.randint(0, 7200)), ip, rnd.choice(PAGES), rnd.choice([200] * 9 + [304])))
    for i in range(12):  # SSH brute force, then success
        rows.append(_ssh(at(600 + i * 3), "203.0.113.50", rnd.choice(["admin", "root", "test", "ubuntu"]), False, rnd))
    rows.append(_ssh(at(640), "203.0.113.50", "root", True, rnd))
    for i, p in enumerate(["/products?id=1' OR 1=1--", "/products?id=1 UNION SELECT username,password FROM users",
                           "/search?q=1;DROP TABLE users", "/item?id=1 AND sleep(5)"]):
        rows.append(_web(at(1500 + i * 4), "198.51.100.23", p, 500))
    for i, p in enumerate(["/search?q=<script>alert(1)</script>", "/comment?x=<img src=x onerror=alert(1)>"]):
        rows.append(_web(at(2200 + i * 5), "198.51.100.77", p))
    for i, p in enumerate(["/download?file=../../../../etc/passwd", "/view?page=%2e%2e%2f%2e%2e%2fetc%2fshadow"]):
        rows.append(_web(at(3000 + i * 5), "192.0.2.14", p, 403))
    rows.append(_web(at(3400), "192.0.2.15", "/ping?host=8.8.8.8;cat /etc/hosts", 200))
    for i in range(20):  # directory scan with a scanner UA
        name = rnd.choice(["admin", "backup", ".env", ".git/config", "phpmyadmin", "wp-admin"])
        rows.append(_web(at(4000 + i), "192.0.2.77", f"/{name}{i}", 404, ua="Nikto/2.5.0"))
    for i in range(14):  # web login brute force
        rows.append(_web(at(5000 + i * 2), "203.0.113.9", "/login", 401, "POST"))
    for i in range(130):  # request flood
        rows.append(_web(at(6000 + i // 20), "203.0.113.99", "/", 200))
    rows.sort(key=lambda r: r[0])
    return "\n".join(r[1] for r in rows)


# ======================================================================
# API
# ======================================================================

MAX_BYTES = 5_000_000
STATIC = Path(__file__).parent


@asynccontextmanager
async def lifespan(_):
    db_init()
    yield


app = FastAPI(title="Threat Detector", lifespan=lifespan)


class LogBatch(BaseModel):
    logs: str


def ingest(text: str) -> dict:
    if len(text) > MAX_BYTES:
        raise HTTPException(413, "Log batch too large (5 MB max)")
    lines = text.splitlines()
    events = [e for e in map(parse_line, lines) if e]
    alerts = analyze(events)
    db_save(alerts, len(lines))
    return {"lines": len(lines), "parsed": len(events), "alerts": len(alerts)}


@app.get("/")
def dashboard():
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/logs")
def upload_logs(batch: LogBatch):
    return ingest(batch.logs)


@app.post("/api/demo")
def demo():
    return ingest(generate())


@app.get("/api/alerts")
def alerts(severity: Optional[str] = Query(None, pattern="^(critical|high|medium|low)$"),
           q: Optional[str] = None, limit: int = Query(200, ge=1, le=1000)):
    return db_query(severity, q, limit)


@app.get("/api/stats")
def stats():
    return db_stats()


@app.delete("/api/alerts")
def clear():
    db_clear()
    return {"cleared": True}
