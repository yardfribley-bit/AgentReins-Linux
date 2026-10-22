"""Shared command and text redaction. Values that can authenticate are masked.

The replacement stops before a closing quote so shlex can still parse the line.
Collectors that run without this package keep a fallback copy of the same rules.
"""
import hashlib
import re

_PATTERNS = (
    ('bearer', re.compile(r'(?i)(Bearer\s+)[^\s"\']+'), r'\1[REDACTED]'),
    # Quoted JSON fields are how tool arguments carry a key. The closing quote stays.
    ('credential_assignment', re.compile(r'(?i)((?:password|passwd|pwd|api[_-]?key|token|secret|cookie)["\']?\s*[=:]\s*["\'])([^"\'\s\\]{6,})'), r'\1[REDACTED]'),
    ('credential_assignment', re.compile(r'(?i)((?:password|passwd|pwd|api[_-]?key|token|secret|cookie)\s*[=:]\s*)[^\s"\']+'), r'\1[REDACTED]'),
    ('cli_secret', re.compile(r'(?i)(--(?:api[_-]?key|token|password|passwd|secret|with-token)(?:\s+|=))[^\s"\']+'), r'\1[REDACTED]'),
    ('user_pass', re.compile(r'(?i)(-u\s+[^\s:]+:)[^\s"\']+'), r'\1[REDACTED]'),
    # mysql -pSecret (attached). A bare -p is a prompt and is left alone.
    ('mysql_password', re.compile(r'(?i)(?<=\s)-p(?![\s-])[^\s"\']+'), '-p[REDACTED]'),
    ('aws_secret', re.compile(r'(?i)(aws_secret_access_key\s*[=:]\s*)[^\s"\']+'), r'\1[REDACTED]'),
    ('env_secret', re.compile(r'(?i)([A-Za-z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD)\s*=\s*)[^\s"\']+'), r'\1[REDACTED]'),
    ('token_prefix', re.compile(r'(?i)\b((?:sk|ghp|gho|ghu|github_pat|xox[baprs]|AKIA)[A-Za-z0-9_\-]{8,})\b'), '[REDACTED]'),
    ('url_userinfo', re.compile(r'(https?://[^\s/:"\']+:)[^@/\s"\']+@'), r'\1[REDACTED]@'),
)


def redact_text(value):
    if not isinstance(value, str):
        return value
    value = value[:16000]
    for _category, pattern, repl in _PATTERNS:
        value = pattern.sub(repl, value)
    return value


def secret_findings(value):
    """Categories and digests for text that redact_text would mask.

    The matched span is hashed and discarded. Callers must not persist it.
    """
    if not isinstance(value, str) or not value:
        return []
    text = value[:16000]
    found = []
    seen = set()
    for category, pattern, _repl in _PATTERNS:
        for match in pattern.finditer(text):
            span = match.group(0)
            if not span or '[REDACTED]' in span:
                continue
            item = (category, hashlib.sha256(span.encode()).hexdigest())
            if item in seen:
                continue
            seen.add(item)
            found.append({'category': category, 'digest': item[1]})
            if len(found) >= 16:
                return found
    return found
