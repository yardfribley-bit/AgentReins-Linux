# Tencent Agent Command-and-Control Evidence — 2026-09-15

## Assessment conclusion

Tencent agents on `43.153.166.155` do receive control-plane instructions.
The evidence supports three different control models and they must not be merged
into one generic "command" category.

## TAT — confirmed remote shell execution

The local TAT log confirms this lifecycle on 2026-08-30:

```text
WebSocket kick
  -> invocation task ID
  -> DescribeTasks
  -> Base64 SHELL task, user root, working directory /root
  -> ReportTaskStart
  -> local child PID
  -> command completion
  -> ReportTaskFinish: SUCCESS, exit code 0
```

The historical command modified account and SSH authentication state. AgentReins
retains the decoded script and execution metadata while masking authentication
secrets. This is direct evidence that TAT is a privileged remote-command channel,
not only a telemetry agent.

The same log shows periodic `CheckUpdate` requests to
`https://invoke.tat-tc.tencent.cn`, including kernel, OS, architecture, and agent
version. The sampled agent version was 1.2.2.

The kernel sensor was installed after the historical task, so there is no corresponding
kernel `execve` evidence for that execution. Future TAT tasks should produce both
TAT lifecycle evidence and independent kernel evidence.

## YunJing/YDService — confirmed remote policy reception

YDService logs explicitly record receipt of dynamic policy/configuration. The
received policies configure:

- Process monitoring.
- Sensitive system-file monitoring, including content/diff collection settings.
- SSH authorization and persistence-related file monitoring.
- System binary integrity monitoring.
- DNS packet collection and five-tuple reporting.
- DRDoS-oriented UDP request/response sampling.
- Dynamic firewall and login-protection behavior.

This confirms receipt of security policy. Policy fields requesting content or
packet reporting show intended collection capability, but do not by themselves
prove that every configured value was transmitted. Outbound report events must
be correlated separately.

## Stargate — confirmed local management instructions

Stargate executes the Barad `trystart.sh` health/start script approximately every
minute and refreshes module installation state periodically. This is confirmed by
both Stargate logs and AgentReins `SYS_EXECVE` evidence. The current sample supports
a local management-loop classification, not an arbitrary remote shell
classification.

## Required AgentReins control-chain model

```text
control connection
  -> control message type
  -> task/policy identity
  -> local process lineage
  -> kernel exec/file/network effects
  -> result/report connection
  -> confidence and missing evidence
```

Public output must contain only redacted command categories, result, evidence
confidence, and impact. Raw command payloads, passwords, tokens, full sensitive
file content, and full packet bodies must remain on the protected host.
