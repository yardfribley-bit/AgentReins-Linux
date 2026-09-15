# AgentReins Linux Architecture

AgentReins Linux treats every protected host as an evidence graph rather than a stream of unrelated alerts.

## Evidence planes

### Control plane

Parses task notifications, policy delivery, task identifiers, execution parameters and result reporting from supported host agents.

### Application plane

Observes data at the application encryption boundary so encrypted connections can be attributed to their actual request or response content.

### Kernel plane

Captures process lineage, file operations, sockets, network destinations and privilege use with host-level identity.

### Correlation plane

Joins events by component identity, executable, PID/PPID, timestamp, task identifier and connection. Raw evidence remains attached to every normalized event.

## Event lifecycle

```text
collect → normalize → protect secrets → deduplicate → correlate → persist → present
```

The public presentation layer is read-only. Ingestion uses an independent credential, and authentication secrets are not stored in source control.
