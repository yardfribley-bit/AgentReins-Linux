# Nginx Kernel Correlation Baseline — 43.153.166.155

## Observed runtime

- Nginx `1.18.0-6ubuntu14.20`, binary `/usr/sbin/nginx`.
- Binary SHA-256: `5e5dc7f0216ac8d87ba6f0db414dfd7ba0fb2bc4eda59bd2d3d371a428a1aa2f`.
- Master PID 924 runs as root in `/system.slice/nginx.service`.
- Worker PIDs 936 and 937 run as `www-data` (UID/GID 33).
- Workers have no effective capabilities, but retain a full bounding set.
- Neither master nor workers use seccomp or `NoNewPrivileges`.
- Nginx listens on IPv4/IPv6 port 80 and proxies the default site to
  `127.0.0.1:8000`.
- Port 443 belongs to Caddy, not Nginx.
- The default site is protected by HTTP Basic Authentication and most sampled
  public requests were rejected with status 401.

## Kernel evidence already confirmed

The AgentReins kernel sensor recorded `kprobe=tcp_accept` events for Nginx worker PID 936.
Each event includes event time, worker PID, source executable, remote address,
local port, protocol, and result.

The kernel evidence stream also records configuration and module file access through
`SYS_OPENAT`. The assessment commands `nginx -t` and `nginx -T` generated their
own file events and must not be confused with long-running worker behavior.

## Current correlation limit

Nginx access records contain request time, client address, method/path, status,
response bytes, referrer, and user agent. Kernel accept events contain event time,
worker PID, and connection endpoint. They do not currently share a stable request
identifier or socket cookie.

Correlation by timestamp and client address is therefore **inferred**, not
confirmed. It becomes ambiguous when one client reuses connections, sends
concurrent requests, or when workers use upstream keepalive.

## Required request-chain identity

The target correlation key is:

```text
host ID + boot ID + worker PID/TGID + socket cookie + TCP tuple + request ID
```

The resulting chain should be:

```text
tcp_accept
  -> nginx worker
  -> request ID / method / redacted path
  -> file open or upstream connect
  -> response status and bytes
  -> tcp close
```

## Next implementation slice

1. Add a privacy-safe Nginx log format with request ID, connection ID, connection
   request count, request time, upstream address, upstream time, status, and bytes.
2. Validate with `nginx -t` and use a graceful reload only after approval.
3. Add an AgentReins correlator that parses access records and structured
   kernel events without persisting raw client addresses.
4. Add socket lifecycle collection for accept/connect/close and stable socket
   identity. Kernel visibility alone does not provide the complete key.
5. Publish only aggregated/redacted request chains to the `/agentsec/` console.
