"""Parsers for common server log formats.

Supported:
- OpenSSH sshd lines from syslog-style auth logs (``auth.log``, ``secure``)
- Combined Log Format web access logs (nginx / Apache defaults)
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime

# --- SSH auth log ---------------------------------------------------------

# e.g. "Jan 12 03:14:07 web1 sshd[1234]: Failed password for invalid user admin
#       from 203.0.113.9 port 51022 ssh2"
_SSH_LINE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>[\d:]{8})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<message>.*)$"
)
_SSH_FAILED = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.]+)"
)
_SSH_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"
)
_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


@dataclass
class AuthEvent:
    timestamp: datetime
    ip: str
    user: str
    outcome: str  # "failed" | "accepted" | "invalid_user"
    raw: str


def _syslog_timestamp(month: str, day: str, time_s: str, year: int) -> datetime:
    h, m, s = (int(x) for x in time_s.split(":"))
    return datetime(year, _MONTHS[month], int(day), h, m, s)


def parse_auth_log(lines: Iterable[str], year: int | None = None) -> Iterator[AuthEvent]:
    """Yield AuthEvents from sshd syslog lines; non-matching lines are skipped.

    Syslog timestamps carry no year, so ``year`` defaults to the current year.
    """
    year = year or datetime.now().year
    for line in lines:
        m = _SSH_LINE.match(line.strip())
        if not m:
            continue
        ts = _syslog_timestamp(m["month"], m["day"], m["time"], year)
        msg = m["message"]
        if fm := _SSH_FAILED.search(msg):
            yield AuthEvent(ts, fm["ip"], fm["user"], "failed", line.rstrip())
        elif am := _SSH_ACCEPTED.search(msg):
            yield AuthEvent(ts, am["ip"], am["user"], "accepted", line.rstrip())
        elif im := _SSH_INVALID.search(msg):
            yield AuthEvent(ts, im["ip"], im["user"], "invalid_user", line.rstrip())


# --- Web access log (Combined Log Format) ---------------------------------

# e.g. '203.0.113.9 - - [12/Jan/2026:03:14:07 +0000] "GET /wp-login.php HTTP/1.1"
#       404 153 "-" "sqlmap/1.7"'
_WEB_LINE = re.compile(
    r'^(?P<ip>[\d.]+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+'
    r'(?P<status>\d{3})\s+\S+\s+"[^"]*"\s+"(?P<agent>[^"]*)"'
)


@dataclass
class WebEvent:
    timestamp: datetime
    ip: str
    method: str
    path: str
    status: int
    user_agent: str
    raw: str


def parse_web_log(lines: Iterable[str]) -> Iterator[WebEvent]:
    """Yield WebEvents from Combined Log Format lines; non-matching lines are skipped."""
    for line in lines:
        m = _WEB_LINE.match(line.strip())
        if not m:
            continue
        ts = datetime.strptime(m["ts"].split()[0], "%d/%b/%Y:%H:%M:%S")
        yield WebEvent(ts, m["ip"], m["method"], m["path"],
                       int(m["status"]), m["agent"], line.rstrip())
