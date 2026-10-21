"""Shared command and text redaction. Values that can authenticate are masked.

The replacement stops before a closing quote so shlex can still parse the line.
Collectors that run without this package keep a fallback copy of the same rules.
"""
import re

_PATTERNS = (
    (re.compile(r'(?i)(Bearer\s+)[^\s"\']+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)((?:password|passwd|pwd|api[_-]?key|token|secret|cookie)\s*[=:]\s*)[^\s"\']+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)(--(?:api[_-]?key|token|password|passwd|secret|with-token)(?:\s+|=))[^\s"\']+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)(-u\s+[^\s:]+:)[^\s"\']+'), r'\1[REDACTED]'),
    # mysql -pSecret (attached). A bare -p is a prompt and is left alone.
    (re.compile(r'(?i)(?<=\s)-p(?![\s-])[^\s"\']+'), '-p[REDACTED]'),
    (re.compile(r'(?i)(aws_secret_access_key\s*[=:]\s*)[^\s"\']+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)([A-Za-z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD)\s*=\s*)[^\s"\']+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)\b((?:sk|ghp|gho|ghu|github_pat|xox[baprs]|AKIA)[A-Za-z0-9_\-]{8,})\b'), '[REDACTED]'),
    (re.compile(r'(https?://[^\s/:"\']+:)[^@/\s"\']+@'), r'\1[REDACTED]@'),
)


def redact_text(value):
    if not isinstance(value, str):
        return value
    value = value[:16000]
    for pattern, repl in _PATTERNS:
        value = pattern.sub(repl, value)
    return value
