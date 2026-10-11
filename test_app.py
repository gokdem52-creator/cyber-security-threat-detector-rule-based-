"""Tests. Run with: pip install pytest httpx && pytest -q"""
import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

from app import app, analyze, generate, parse_line

T0 = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=1)
UA = "Mozilla/5.0"


def web(sec, ip, path="/", status=200, method="GET", ua=UA):
    t = T0 + timedelta(seconds=sec)
    return f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S +0000}] "{method} {path} HTTP/1.1" {status} 512 "-" "{ua}"'


def ssh(sec, ip, ok=False, user="admin"):
    t = T0 + timedelta(seconds=sec)
    word, inv = ("Accepted", "") if ok else ("Failed", "invalid user ")
    return f"{t:%b} {t.day:2d} {t:%H:%M:%S} host sshd[1234]: {word} password for {inv}{user} from {ip} port 5555 ssh2"


def test_parses_web_line():
    e = parse_line(web(0, "1.2.3.4", "/a?b=1", 404, "POST", "curl/8"))
    assert (e["type"], e["ip"], e["method"], e["path"], e["status"], e["ua"]) == \
        ("web", "1.2.3.4", "POST", "/a?b=1", 404, "curl/8")


def test_parses_ssh_failure_and_success():
    bad = parse_line(ssh(0, "5.6.7.8", ok=False, user="bob"))
    good = parse_line(ssh(1, "5.6.7.8", ok=True, user="root"))
    assert bad["type"] == "ssh" and bad["success"] is False and bad["user"] == "bob"
    assert good["success"] is True and good["user"] == "root"


def test_garbage_and_blank_lines_ignored():
    assert parse_line("") is None
    assert parse_line("this is not a log line") is None


def run(lines):
    return analyze([e for e in map(parse_line, lines) if e])


def rules(lines):
    return {a["rule"] for a in run(lines)}


def test_benign_traffic_has_no_alerts():
    assert run([web(i, "10.0.0.1", p) for i, p in enumerate(["/", "/about", "/products?id=5"])]) == []


def test_sql_injection():
    assert "SQL_INJECTION" in rules([web(0, "1.1.1.1", "/p?id=1' OR 1=1--")])
    assert "SQL_INJECTION" in rules([web(0, "1.1.1.1", "/p?id=1%20UNION%20SELECT%20pass%20FROM%20users")])


def test_xss():
    assert "XSS" in rules([web(0, "1.1.1.1", "/s?q=%3Cscript%3Ealert(1)%3C/script%3E")])


def test_path_traversal_including_double_encoding():
    assert "PATH_TRAVERSAL" in rules([web(0, "1.1.1.1", "/f?x=../../etc/passwd")])
    assert "PATH_TRAVERSAL" in rules([web(0, "1.1.1.1", "/f?x=%252e%252e%252fetc")])


def test_command_injection_is_critical():
    a = run([web(0, "1.1.1.1", "/ping?h=1;cat /etc/hosts")])
    assert any(x["rule"] == "COMMAND_INJECTION" and x["severity"] == "critical" for x in a)


def test_scanner_user_agent_alerts_once():
    a = run([web(i, "2.2.2.2", "/", ua="sqlmap/1.7") for i in range(5)])
    assert [x["rule"] for x in a].count("SCANNER_USER_AGENT") == 1


def test_ssh_brute_force_below_threshold_is_quiet():
    assert run([ssh(i, "3.3.3.3") for i in range(4)]) == []


def test_ssh_brute_force_and_compromise():
    lines = [ssh(i, "3.3.3.3") for i in range(6)] + [ssh(10, "3.3.3.3", ok=True, user="root")]
    found = rules(lines)
    assert {"SSH_BRUTE_FORCE", "BRUTE_FORCE_SUCCESS"} <= found


def test_failures_outside_window_do_not_count():
    assert run([ssh(i * 30, "3.3.3.3") for i in range(6)]) == []


def test_directory_scan():
    assert "DIRECTORY_SCAN" in rules([web(i, "4.4.4.4", f"/x{i}", 404) for i in range(16)])


def test_web_login_brute_force():
    assert "WEB_LOGIN_BRUTE_FORCE" in rules([web(i, "5.5.5.5", "/login", 401, "POST") for i in range(11)])


def test_request_flood():
    assert "REQUEST_FLOOD" in rules([web(i // 20, "6.6.6.6") for i in range(120)])


def test_demo_data_triggers_every_rule():
    found = rules(generate().splitlines())
    assert {"SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "COMMAND_INJECTION", "SCANNER_USER_AGENT",
            "SSH_BRUTE_FORCE", "BRUTE_FORCE_SUCCESS", "DIRECTORY_SCAN",
            "WEB_LOGIN_BRUTE_FORCE", "REQUEST_FLOOD"} <= found


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "t.db"))
    with TestClient(app) as c:
        yield c


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_dashboard_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "Threat Detector" in r.text


def test_upload_and_query_alerts(client):
    r = client.post("/api/logs", json={"logs": web(0, "9.9.9.9", "/p?id=1' OR 1=1--")})
    assert r.json() == {"lines": 1, "parsed": 1, "alerts": 1}
    alerts = client.get("/api/alerts").json()
    assert alerts[0]["rule"] == "SQL_INJECTION" and alerts[0]["ip"] == "9.9.9.9"


def test_filters(client):
    client.post("/api/demo")
    crit = client.get("/api/alerts", params={"severity": "critical"}).json()
    assert crit and all(a["severity"] == "critical" for a in crit)
    assert all("203.0.113.50" == a["ip"] for a in client.get("/api/alerts", params={"q": "203.0.113.50"}).json())
    assert client.get("/api/alerts", params={"severity": "bogus"}).status_code == 422


def test_stats_and_clear(client):
    client.post("/api/demo")
    s = client.get("/api/stats").json()
    assert s["total_alerts"] > 0 and s["lines_processed"] > 300
    assert s["by_rule"] and s["top_ips"] and s["timeline"]
    client.delete("/api/alerts")
    assert client.get("/api/stats").json()["total_alerts"] == 0


def test_rejects_bad_body(client):
    assert client.post("/api/logs", json={"nope": 1}).status_code == 422
