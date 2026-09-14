# logsentry

[![CI](https://github.com/MRashad01/logsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/MRashad01/logsentry/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)

Blue-team log analysis engine: parses SSH auth logs and web access logs, then runs detection rules to surface attack patterns — pure Python, zero dependencies.

Built to answer the first questions of incident triage fast: *who is attacking, how, and did they get in?*

## Detection rules

| Rule | Signal | Severity |
|---|---|---|
| `ssh-bruteforce` | ≥5 failed SSH logins from one IP within a 10-minute sliding window | medium — **high** if a later login from the same IP *succeeded* |
| `web-probe-paths` | Requests for known scanner targets (`/.env`, `/.git`, `/wp-login.php`, `/phpmyadmin`, …) | medium |
| `scanner-user-agent` | User-Agent of known tools (sqlmap, nikto, nuclei, gobuster, …) | medium |
| `4xx-burst` | ≥20 client-error responses from one IP — path fuzzing / dir brute force | low |

## Supported formats

- **SSH**: OpenSSH `sshd` lines in syslog format (`/var/log/auth.log`, `/var/log/secure`)
- **Web**: Combined Log Format (nginx and Apache defaults)

## Install

```bash
git clone https://github.com/MRashad01/logsentry
cd logsentry
pip install .
```

## Usage

```bash
# Analyze both log types at once
logsentry --auth /var/log/auth.log --web /var/log/nginx/access.log

# JSON for pipelines / SIEM ingestion
logsentry --auth auth.log --json

# Show the raw log lines behind each finding
logsentry --web access.log --evidence
```

Try it immediately on the bundled sample logs:

```bash
logsentry --auth sample_logs/auth.log --web sample_logs/access.log --evidence
```

Example output:

```
3 finding(s)

[MEDIUM] ssh-bruteforce       203.0.113.9      7 failed SSH logins (7 within 10 min), users tried: admin, oracle, root, test
[MEDIUM] web-probe-paths      203.0.113.50     probed 4 sensitive paths: /.env, /.git/config, /phpmyadmin/index.php, /wp-login.php
[MEDIUM] scanner-user-agent   203.0.113.77     scanner user-agent detected: sqlmap/1.7.2#stable (https://sqlmap.org)
```

Exit codes are script-friendly: `0` clean, `3` findings exist — so you can wire it into cron:

```bash
logsentry --auth /var/log/auth.log --json > findings.json || notify-team
```

## Design notes

- The brute-force rule uses a **sliding window** over sorted timestamps, so slow drip attacks spread over hours don't false-positive, while tight bursts do.
- A brute-force burst followed by a **successful** login from the same IP escalates to `high` — that's the finding you page someone for.
- Parsers skip lines they don't understand instead of crashing: real logs are messy.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## License

MIT — see [LICENSE](LICENSE).
