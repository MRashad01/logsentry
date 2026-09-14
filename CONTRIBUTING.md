# Contributing to logsentry

Thanks for considering a contribution. This project is small and dependency-free on purpose — keep that in mind for any change.

## Setup

```bash
git clone https://github.com/MRashad01/logsentry
cd logsentry
pip install -e ".[dev]"
```

## Before opening a PR

```bash
pytest
ruff check .
```

Both run in CI on every PR — please make sure they pass locally first.

## Guidelines

- No new runtime dependencies without discussion — the zero-dependency design is a feature.
- New detection rules belong in `logsentry/detect.py` as a `detect_*` function returning `list[Finding]`, wired into `analyze()`.
- New parsers belong in `logsentry/parsers.py`; skip lines you don't understand instead of raising — real logs are messy.
- Add a test with representative log lines for any new rule or parser.

## Good first issues

Check the [issue tracker](https://github.com/MRashad01/logsentry/issues) for anything labeled `good first issue`.
