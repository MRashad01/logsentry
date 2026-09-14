"""Detection rules over parsed log events."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from logsentry.parsers import AuthEvent, WebEvent

# Paths probed by common vulnerability scanners and bots.
PROBE_PATHS = (
    "/.env", "/.git", "/wp-login.php", "/wp-admin", "/xmlrpc.php",
    "/phpmyadmin", "/admin", "/config.php", "/.aws", "/actuator",
    "/etc/passwd", "/cgi-bin", "/shell", "/vendor/phpunit",
)

# User-agent substrings of well-known scanning tools.
SCANNER_AGENTS = ("sqlmap", "nikto", "nmap", "masscan", "dirbuster",
                  "gobuster", "wpscan", "nuclei", "zgrab", "acunetix")


@dataclass
class Finding:
    rule: str
    severity: str  # "low" | "medium" | "high"
    ip: str
    summary: str
    count: int
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "ip": self.ip,
            "summary": self.summary,
            "count": self.count,
            "evidence": self.evidence[:5],
        }


def detect_ssh_bruteforce(events: list[AuthEvent], *, threshold: int = 5,
                          window_minutes: int = 10) -> list[Finding]:
    """Flag IPs with >= threshold failed logins inside a sliding time window."""
    findings: list[Finding] = []
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        if e.outcome in ("failed", "invalid_user"):
            by_ip[e.ip].append(e)

    window = timedelta(minutes=window_minutes)
    for ip, fails in by_ip.items():
        fails.sort(key=lambda e: e.timestamp)
        lo = 0
        best = 0
        for hi in range(len(fails)):
            while fails[hi].timestamp - fails[lo].timestamp > window:
                lo += 1
            best = max(best, hi - lo + 1)
        if best >= threshold:
            users = sorted({e.user for e in fails})
            succeeded = any(
                e.ip == ip and e.outcome == "accepted" for e in events
            )
            severity = "high" if succeeded else "medium"
            note = " — followed by a SUCCESSFUL login" if succeeded else ""
            findings.append(Finding(
                rule="ssh-bruteforce", severity=severity, ip=ip,
                summary=(f"{len(fails)} failed SSH logins "
                         f"({best} within {window_minutes} min), "
                         f"users tried: {', '.join(users[:8])}{note}"),
                count=len(fails),
                evidence=[e.raw for e in fails],
            ))
    return findings


def detect_web_probes(events: list[WebEvent], *, threshold: int = 3) -> list[Finding]:
    """Flag IPs requesting known scanner/exploit paths."""
    findings: list[Finding] = []
    by_ip: dict[str, list[WebEvent]] = defaultdict(list)
    for e in events:
        if any(p in e.path.lower() for p in PROBE_PATHS):
            by_ip[e.ip].append(e)
    for ip, hits in by_ip.items():
        if len(hits) >= threshold:
            paths = sorted({e.path for e in hits})
            findings.append(Finding(
                rule="web-probe-paths", severity="medium", ip=ip,
                summary=f"probed {len(paths)} sensitive paths: {', '.join(paths[:6])}",
                count=len(hits),
                evidence=[e.raw for e in hits],
            ))
    return findings


def detect_scanner_agents(events: list[WebEvent]) -> list[Finding]:
    """Flag IPs whose User-Agent matches a known scanning tool."""
    findings: list[Finding] = []
    by_ip: dict[str, list[WebEvent]] = defaultdict(list)
    for e in events:
        agent = e.user_agent.lower()
        if any(tool in agent for tool in SCANNER_AGENTS):
            by_ip[e.ip].append(e)
    for ip, hits in by_ip.items():
        agents = sorted({e.user_agent for e in hits})
        findings.append(Finding(
            rule="scanner-user-agent", severity="medium", ip=ip,
            summary=f"scanner user-agent detected: {', '.join(agents[:3])}",
            count=len(hits),
            evidence=[e.raw for e in hits],
        ))
    return findings


def detect_error_bursts(events: list[WebEvent], *, threshold: int = 20) -> list[Finding]:
    """Flag IPs generating many 4xx responses (directory brute forcing, fuzzing)."""
    findings: list[Finding] = []
    by_ip: dict[str, list[WebEvent]] = defaultdict(list)
    for e in events:
        if 400 <= e.status < 500:
            by_ip[e.ip].append(e)
    for ip, hits in by_ip.items():
        if len(hits) >= threshold:
            findings.append(Finding(
                rule="4xx-burst", severity="low", ip=ip,
                summary=f"{len(hits)} client-error responses — likely path fuzzing",
                count=len(hits),
                evidence=[e.raw for e in hits],
            ))
    return findings


_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def analyze(auth_events: list[AuthEvent] | None = None,
            web_events: list[WebEvent] | None = None) -> list[Finding]:
    """Run every applicable detection rule and return findings, most severe first."""
    findings: list[Finding] = []
    if auth_events:
        findings += detect_ssh_bruteforce(auth_events)
    if web_events:
        findings += detect_web_probes(web_events)
        findings += detect_scanner_agents(web_events)
        findings += detect_error_bursts(web_events)
    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], -f.count))
    return findings
