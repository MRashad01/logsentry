from datetime import datetime
import pytest

from logsentry.cli import main, parse_timestamp


def test_parse_timestamp_valid_formats():
    assert parse_timestamp("2026-01-12 15:30:00") == datetime(2026, 1, 12, 15, 30, 0)
    assert parse_timestamp("2026-01-12 15:30") == datetime(2026, 1, 12, 15, 30, 0)
    assert parse_timestamp("2026-01-12") == datetime(2026, 1, 12, 0, 0, 0)
    assert parse_timestamp("2026-01-12T15:30:00") == datetime(2026, 1, 12, 15, 30, 0)


def test_parse_timestamp_invalid_format():
    with pytest.raises(ValueError):
        parse_timestamp("invalid-date")


def test_cli_requires_input_files(capsys):
    rc = main([])
    assert rc == 2
    captured = capsys.readouterr()
    assert "error: provide --auth and/or --web" in captured.err


def test_cli_rejects_since_after_until(capsys, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("Jan 12 03:14:01 web1 sshd[1201]: Failed password for root from 1.2.3.4\n")
    rc = main(["--auth", str(log), "--since", "2026-01-15", "--until", "2026-01-10"])
    assert rc == 2
    captured = capsys.readouterr()
    assert "--since must be before or equal to --until" in captured.err


def test_cli_time_filtering_auth_log(tmp_path, capsys):
    lines = [
        "Jan 12 01:00:00 web1 sshd[100]: Failed password for root from 203.0.113.9 port 50000",
        "Jan 12 03:14:00 web1 sshd[101]: Failed password for root from 203.0.113.9 port 50001",
        "Jan 12 03:14:01 web1 sshd[102]: Failed password for root from 203.0.113.9 port 50002",
        "Jan 12 03:14:02 web1 sshd[103]: Failed password for root from 203.0.113.9 port 50003",
        "Jan 12 03:14:03 web1 sshd[104]: Failed password for root from 203.0.113.9 port 50004",
        "Jan 12 03:14:04 web1 sshd[105]: Failed password for root from 203.0.113.9 port 50005",
        "Jan 12 08:00:00 web1 sshd[106]: Failed password for root from 203.0.113.9 port 50006",
    ]
    log = tmp_path / "auth.log"
    log.write_text("\n".join(lines), encoding="utf-8")

    current_year = datetime.now().year

    # 1. Filter with a window that excludes the burst: Jan 12 05:00 to 09:00 (only 1 event)
    rc = main([
        "--auth", str(log),
        "--since", f"{current_year}-01-12 05:00:00",
        "--until", f"{current_year}-01-12 09:00:00",
    ])
    assert rc == 0  # No findings because 1 event is below threshold
    captured = capsys.readouterr()
    assert "no findings — logs look clean" in captured.out

    # 2. Filter with a window that includes the burst: Jan 12 03:00 to 04:00
    rc = main([
        "--auth", str(log),
        "--since", f"{current_year}-01-12 03:00:00",
        "--until", f"{current_year}-01-12 04:00:00",
    ])
    assert rc == 3  # Finding detected!
    captured = capsys.readouterr()
    assert "ssh-bruteforce" in captured.out


def test_cli_time_filtering_web_log(tmp_path, capsys):
    lines = [
        '1.2.3.4 - - [10/Jan/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 153 "-" "agent"',
        '1.2.3.4 - - [12/Jan/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 153 "-" "agent"',
        '1.2.3.4 - - [12/Jan/2026:10:01:00 +0000] "GET /.git/config HTTP/1.1" 404 153 "-" "agent"',
        '1.2.3.4 - - [12/Jan/2026:10:02:00 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 153 "-" "agent"',
        '1.2.3.4 - - [15/Jan/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 153 "-" "agent"',
    ]
    log = tmp_path / "access.log"
    log.write_text("\n".join(lines), encoding="utf-8")

    # Filter strictly to Jan 12: 3 probe paths within range (triggers web-probe-paths threshold=3)
    rc = main([
        "--web", str(log),
        "--since", "2026-01-12 00:00",
        "--until", "2026-01-12 23:59",
    ])
    assert rc == 3
    captured = capsys.readouterr()
    assert "web-probe-paths" in captured.out

    # Filter to Jan 14-16: only 1 request, does not trigger
    rc = main([
        "--web", str(log),
        "--since", "2026-01-14 00:00",
        "--until", "2026-01-16 00:00",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    assert "no findings — logs look clean" in captured.out
