"""logsentry — find attack patterns in server logs.

Parses SSH auth logs and web access logs, then runs detection rules for
brute-force attempts, vulnerability-scanner probes, and suspicious clients.
"""

__version__ = "0.1.0"

from logsentry.detect import Finding, analyze
from logsentry.parsers import AuthEvent, WebEvent, parse_auth_log, parse_web_log

__all__ = [
    "AuthEvent",
    "Finding",
    "WebEvent",
    "__version__",
    "analyze",
    "parse_auth_log",
    "parse_web_log",
]
