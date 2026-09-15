from __future__ import annotations

import hashlib
import re

from policy.ir import Action, Enforcement, Policy, Rule, Scope


class NaturalLanguageCompiler:
    """Deterministic v1 compiler for a deliberately small Chinese/English vocabulary.

    An LLM may suggest a structured draft later, but this compiler and the validator
    remain the authority that decides what can become an executable policy.
    """

    _agent = re.compile(r"(?:监控|管理|保护|observe|manage|protect)\s*([\w.-]+)", re.I)

    def compile(self, text: str, *, mode: str = "observe") -> Policy:
        normalized = " ".join(text.strip().split())
        match = self._agent.search(normalized)
        executable = match.group(1) if match else "tat_agent"
        rules: list[Rule] = []

        if self._has(normalized, "命令", "shell", "command", "执行"):
            rules.append(Rule(Action.PROCESS_EXEC, Enforcement.RECORD, reason="record command execution"))
        if self._has(normalized, "文件", "file", "读取"):
            rules.append(Rule(Action.FILE_READ, Enforcement.RECORD, reason="record file reads"))
        if self._has(normalized, "修改", "写入", "write"):
            enforcement = Enforcement.REQUIRE_APPROVAL if self._has(normalized, "批准", "确认", "approval") else Enforcement.RECORD
            rules.append(Rule(Action.FILE_WRITE, enforcement, {"path_class": "system"}, "control system-file writes"))
        if self._has(normalized, "密码", "凭据", "credential", "secret"):
            rules.append(Rule(Action.FILE_READ, Enforcement.DENY, {"data_class": "credential"}, "protect credentials"))
        if self._has(normalized, "网络", "连接", "传输", "network"):
            rules.append(Rule(Action.NETWORK_CONNECT, Enforcement.RECORD, reason="record network connections"))
        if self._has(normalized, "明文", "tls", "流量内容"):
            rules.append(Rule(Action.TLS_PLAINTEXT, Enforcement.RECORD, reason="record application-boundary payload evidence"))

        digest = hashlib.sha256(normalized.encode()).hexdigest()[:12]
        return Policy(f"nl-{digest}", normalized, Scope(executable), tuple(rules), mode=mode)

    @staticmethod
    def _has(text: str, *terms: str) -> bool:
        lowered = text.lower()
        return any(term.lower() in lowered for term in terms)
