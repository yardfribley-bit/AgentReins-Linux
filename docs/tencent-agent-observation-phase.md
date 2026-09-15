# Tencent Agent Observation Phase

## Safety boundary

The first production-host phase is read-only and audit-only. It must not apply a
blocking KubeArmor policy, restart a Tencent service, modify an agent file, or
intercept TLS traffic.

## Questions to answer

For each Tencent Cloud agent:

1. What service and executable represent it?
2. Who starts it and with which Linux privileges?
3. Which commands and child processes does it execute?
4. Which files, kernel interfaces, and local sockets does it access?
5. Which remote destinations does it contact, and how much data moves?
6. Which reporting fields are confirmed by local logs or queues?
7. Which relationships are inferred rather than confirmed?

## Evidence phases

### Phase 0 — Static discovery

Run `scripts/discover-tencent-agents.sh` and preserve its stdout locally. This
establishes process, service, package, executable, privilege, descriptor, socket,
and KubeArmor identities without changing the host.

### Phase 1 — Runtime audit

Enable host visibility for process, file, network, and capabilities. Consume the
KubeArmor telemetry stream without applying blocking policies. Correlate events
by executable identity, PID lineage, cgroup, service, and timestamp.

### Phase 2 — Reporting analysis

Map reads of local files and kernel interfaces to subsequent outbound flows.
Classify evidence as confirmed, inferred, or unknown. TLS destination and byte
counts do not prove payload contents. Exact payload claims require agent logs,
local queues, documented APIs, or a separately approved test-host instrument.

### Phase 3 — Baseline and detection

After at least 48–72 hours, define normal executable hashes, child commands,
file access, capabilities, destinations, and update behavior. Alert on deviations.
Blocking remains a separate, explicitly approved phase.
