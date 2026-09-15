# Tencent Host Live Assessment — 2026-09-15

## Scope and safety

Target: Tencent Cloud CVM `43.153.166.155`.

The assessment was read-only. No service was restarted, no policy was applied,
and no configuration or agent file was changed.

## Host facts

- Ubuntu 22.04.5 LTS, Linux 5.15.0-181-generic, x86-64, Tencent Cloud CVM.
- The root filesystem reported 100% use (`40G`, approximately `38G` used).
- `/var/log` occupied approximately 14G; systemd journals occupied about 800M.
- The AgentReins kernel sensor runs in systemd mode with BPF-LSM active.
- Host policy and visibility are enabled for process, file, network, and capabilities.
- All default host postures are audit, not block.

## Observed Tencent agent identities

| Component | Executable | Process model | SHA-256 |
| --- | --- | --- | --- |
| TAT | `/usr/local/qcloud/tat_agent/tat_agent` | PID 832, parent systemd | `8aff9c5c01c9bdcdcac405ff8b4e64bd2802a8c28e1c3ebf6950938ea13eb3ee` |
| Stargate | `/usr/local/qcloud/stargate/bin/sgagent64` | PID 1871, parent systemd | `7772596f66b3edf5b2aa3af89a2ad623a442de657948270895d73d1a92bcc8a4` |
| YunJing supervisor | `/usr/local/qcloud/YunJing/YDLive/YDLive` | PID 1905, parent systemd | `edb13cb41f5a49aab227f74a5154ce05336c6c6e56b528e65e9c5c239854dfad` |
| YunJing service | `/usr/local/qcloud/YunJing/YDEyes/YDService` | PID 1914, child of YDLive | `d022c2ec479c454b09caf8425f73c837ac7589206ec60e3cc13f88af34b313fb` |
| Barad monitor | `/usr/local/qcloud/monitor/python26/bin/python` | PIDs 1955/1962/1963 | `ed6f126aa97395f929f535c0526ec75c7d274a46ecdb7c5280109c825dfb5a7d` |

Every observed component ran as root with the full effective capability mask,
`NoNewPrivs=0`, and `Seccomp=0`. This makes exact identity and lineage tracking a
priority: a compromised component has broad host authority.

## Runtime behavior confirmed by AgentReins

The available feed covered roughly the preceding 12 hours. Representative event
counts included:

- Barad Python: 22,107 file events and 8,889 network events.
- YDService: 8,336 file events, 226 network events, and 12 direct process events.
- TAT: 1,424 file events and 6 network events.
- Stargate: 97 network events and 24 file events.

Confirmed command chains included:

- `YDService -> /sbin/iptables --version`
- `YDService -> /sbin/iptables -t filter -S YJ-FIREWALL-INPUT --wait 20`
- `YDService -> /sbin/iptables -t filter -A/-D ... -j REJECT`
- `YDService -> /sbin/iptables -D INPUT -j YJ-FIREWALL-INPUT`
- `YDService -> /sbin/iptables -I INPUT 1 -j YJ-FIREWALL-INPUT`
- `YDService -> /sbin/iptables -nvL YJ-FIREWALL-INPUT`
- `YDService -> /sbin/iptables -Z YJ-FIREWALL-INPUT`
- `sgagent64 -> /bin/sh -c ../../monitor/barad/admin/trystart.sh`, approximately once per minute.
- `YDLive -> YDService -verNum`, approximately once per ten minutes in the sampled window.

These are confirmed executions because the events include process name, parent
process, PID lineage, command resource, and `SYS_EXECVE`.

## Network behavior confirmed

- `YDService` maintained connections to `169.254.0.55:5574` and used netlink sockets.
- `tat_agent` maintained a connection to `169.254.0.138:8186`.
- Barad Python repeatedly connected to `169.254.0.4:80`.
- `sgagent64` performed DNS through `127.0.0.53:53` and connected to `169.254.0.15:80`.

This proves endpoints and connection activity, not the contents of reports. Exact
report fields remain unknown until local agent logs/queues or pre-TLS evidence are
correlated.

## Existing audit pipeline defects

The active host audit policy provides process, file, network and capability visibility. General host visibility emits
useful raw events, but the events sampled during this assessment had no
`PolicyName`, so the current design relies on downstream text filtering rather
than stable agent identity.

`qcloud-agent-audit.service` filters the complete journal stream with:

```text
grep -E "qcloud|barad_agent"
```

This has three problems:

1. It can include unrelated commands whose arguments merely mention qcloud.
2. It is not a durable identity/lineage filter.
3. Its output file does not reopen correctly after log rotation.

The visible `/var/log/qcloud_agents_audit.log` was empty. The filter process still
held a deleted rotated file of 757,611,184 bytes, preventing that space from being
released. The compressed rotated file was approximately 1.5M.

## Next implementation slice

1. Replace text filtering with structured JSON identity and descendant-lineage filtering.
2. Persist normalized events with agent ID, executable hash, PID/PPID, operation, resource, result, and evidence confidence.
3. Separate command executions from file and socket noise.
4. Aggregate remote endpoint frequency and correlate local reads before each outbound connection.
5. Fix bounded retention and rotation before increasing collection duration.
6. Keep enforcement disabled while building the 48–72 hour baseline.
