# Natural-Language Agent Control

AgentReins accepts a human intent, compiles it into a typed policy, validates its
effects, and only then makes it eligible for a host enforcement backend.

```text
human intent
  -> deterministic vocabulary compiler
  -> AgentReins Policy IR
  -> safety and conflict validation
  -> AgentSpec-compatible audit view
  -> backend capability check
  -> preview / approve / activate
  -> kernel and application evidence
```

The language model is never the enforcement authority. It may help normalize an
open-ended request in a future compiler, but the resulting IR must pass the same
deterministic schema, validation, capability, approval, and audit stages.

## Initial TAT policy

The first target is Tencent Cloud `tat_agent`. The initial vocabulary recognizes
command execution, file reads and writes, network connections, credential access,
approval requirements, and TLS plaintext evidence.

Blocking is intentionally not wired to the live host in v1alpha1. The control
plane must first demonstrate stable compilation, explicit operator approval,
backend capability checks, dry-run evidence, versioning, and rollback.
