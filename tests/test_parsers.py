from logsentry.parsers import parse_auth_log, parse_web_log

AUTH_LINES = [
    "Jan 12 03:14:01 web1 sshd[1201]: Failed password for invalid user admin "
    "from 203.0.113.9 port 51022 ssh2",
    "Jan 12 08:22:10 web1 sshd[2100]: Accepted publickey for deploy "
    "from 198.51.100.20 port 40122 ssh2",
    "Jan 12 03:14:08 web1 sshd[1204]: Invalid user oracle from 203.0.113.9 port 51025",
    "Jan 12 03:15:00 web1 CRON[999]: pam_unix(cron:session): session opened",  # noise
    "not a log line at all",
]

WEB_LINES = [
    '203.0.113.50 - - [12/Jan/2026:10:02:01 +0000] "GET /.env HTTP/1.1" 404 153 '
    '"-" "Mozilla/5.0 zgrab/0.x"',
    '198.51.100.14 - - [12/Jan/2026:11:15:20 +0000] "POST /login HTTP/1.1" 200 512 '
    '"https://example.com" "Mozilla/5.0"',
    "garbage line",
]


def test_auth_parser_extracts_events_and_skips_noise():
    events = list(parse_auth_log(AUTH_LINES, year=2026))
    assert len(events) == 3
    assert events[0].outcome == "failed"
    assert events[0].ip == "203.0.113.9"
    assert events[0].user == "admin"
    assert events[1].outcome == "accepted"
    assert events[2].outcome == "invalid_user"
    assert events[0].timestamp.year == 2026


def test_web_parser_extracts_fields_and_skips_noise():
    events = list(parse_web_log(WEB_LINES))
    assert len(events) == 2
    assert events[0].ip == "203.0.113.50"
    assert events[0].path == "/.env"
    assert events[0].status == 404
    assert "zgrab" in events[0].user_agent
    assert events[1].method == "POST"
