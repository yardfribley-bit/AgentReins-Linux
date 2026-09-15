from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Action(str, Enum):
    PROCESS_EXEC = "process.exec"
    FILE_READ = "file.read"
    FILE_WRITE = "file.write"
    NETWORK_CONNECT = "network.connect"
    TLS_PLAINTEXT = "tls.plaintext"


class Enforcement(str, Enum):
    OBSERVE = "observe"
    RECORD = "record"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class Scope:
    executable: str


@dataclass(frozen=True)
class Rule:
    action: Action
    enforcement: Enforcement
    conditions: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


@dataclass(frozen=True)
class Policy:
    policy_id: str
    source_text: str
    scope: Scope
    rules: tuple[Rule, ...]
    mode: str = "observe"
    schema_version: str = "agentreins.policy/v1alpha1"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
