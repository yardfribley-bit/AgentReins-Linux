from __future__ import annotations

from policy.ir import Policy
from policy.natural_language import NaturalLanguageCompiler
from policy.validator import validate_policy


def compile_policy(text: str, *, mode: str = "observe") -> Policy:
    return validate_policy(NaturalLanguageCompiler().compile(text, mode=mode))
