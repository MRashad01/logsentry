from datetime import datetime, timedelta

from logsentry.detect import (
    analyze,
    detect_error_bursts,
    detect_scanner_agents,
    detect_ssh_bruteforce,
    detect_web_probes,
)
from logsentry.parsers import AuthEvent, WebEvent


def _auth(ip: str, outcome: str, minute: int, user: str = "root") -> AuthEvent:
    ts = datetime(2026, 1, 12, 3, minute, 0)
    return AuthEvent(ts, ip, user, outcome, raw=f"{ip} {outcome} {minute}")


def _web(ip: str, path: str, status: int = 200, agent: str = "Mozilla/5.0",
         second: int = 0) -> WebEvent:
    ts = datetime(2026, 1, 12, 10, 0, second)
    return WebEvent(ts, ip, "GET", path, status, agent, raw=f"{ip} {path}")


def test_bruteforce_detected_within_window():
    events = [_auth("203.0.113.9", "failed", m) for m in range(5)]
    findings = detect_ssh_bruteforce(events, threshold=5, window_minutes=10)
    assert len(findings) == 1
    assert findings[0].ip == "203.0.113.9"
    assert findings[0].severity == "medium"


def test_bruteforce_followed_by_success_is_high():
    events = [_auth("203.0.113.9", "failed", m) for m in range(5)]
    events.append(_auth("203.0.113.9", "accepted", 6))
    findings = detect_ssh_bruteforce(events, threshold=5)
    assert findings[0].severity == "high"


def test_slow_failures_outside_window_not_flagged():
    base = datetime(2026, 1, 12, 0, 0, 0)
    events = [
        AuthEvent(base + timedelta(hours=i), "203.0.113.9", "root", "failed", "raw")
        for i in range(5)
    ]
    assert detect_ssh_bruteforce(events, threshold=5, window_minutes=10) == []


def test_probe_paths_detected():
    events = [_web("1.2.3.4", p) for p in ("/.env", "/wp-admin/", "/.git/config")]
    findings = detect_web_probes(events, threshold=3)
    assert len(findings) == 1
    assert findings[0].rule == "web-probe-paths"


def test_scanner_agent_detected():
    events = [_web("1.2.3.4", "/", agent="sqlmap/1.7")]
    findings = detect_scanner_agents(events)
    assert len(findings) == 1
    assert "sqlmap" in findings[0].summary


def test_error_burst_detected():
    events = [_web("1.2.3.4", f"/x{i}", status=404, second=i % 60) for i in range(25)]
    findings = detect_error_bursts(events, threshold=20)
    assert len(findings) == 1
    assert findings[0].rule == "4xx-burst"


def test_analyze_sorts_by_severity():
    auth = [_auth("203.0.113.9", "failed", m) for m in range(5)]
    auth.append(_auth("203.0.113.9", "accepted", 6))
    web = [_web("1.2.3.4", f"/x{i}", status=404) for i in range(25)]
    findings = analyze(auth, web)
    assert findings[0].severity == "high"
    assert findings[-1].severity == "low"
