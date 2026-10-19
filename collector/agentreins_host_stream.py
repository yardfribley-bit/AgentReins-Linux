#!/usr/bin/env python3
"""AgentReins Linux — host agent observation mode.

Watches a high-privilege agent running on this host (default: PentAGI) and turns
its runtime behaviour into one correlated evidence chain:

    container lifecycle   (control plane  — docker events from the runtime)
      -> process exec/exit  (kernel plane — netlink proc connector)
      -> container attribution (correlation — /proc/<pid>/cgroup)
      -> file access        (kernel plane — inotify)
      -> egress connections (network plane — nf LOG + socket inode→pid attribution)

The observer runs on the host, so processes inside agent sandboxes are visible in
the host PID namespace. That is what makes kernel-state behaviour auditable
without installing anything inside the container.

Correlation conclusions are labelled CONFIRMED or CROSS_LAYER_CORRELATION.
Missing evidence is reported as unknown, never guessed.

Usage:
    sudo python3 agentreins_host_stream.py --agent pentagi --watch /opt/pentagi/data
"""
from __future__ import annotations

from activity_policy import policy as persistence_policy
import argparse
import ctypes
import hashlib
import json
import os
import queue
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from collections import deque

events: "queue.Queue[dict]" = queue.Queue(maxsize=20000)
seen: "deque[str]" = deque(maxlen=20000)


# ---------------------------------------------------------------------------
# event plumbing
# ---------------------------------------------------------------------------

def mask_passwords(text: str) -> str:
    """Keep commands verbatim, redact only values that can authenticate."""
    text = re.sub(r"(?im)^([ \t]*#\s*root\s*\n[ \t]*#\s*)\S+", r"\1******", text)
    text = re.sub(r"(?i)\b(password|passwd|pwd)(\s*[:=]\s*)(?![$(])([^\s\"']+)", r"\1\2******", text)
    text = re.sub(r"(?i)(Authorization:\s*(?:Bearer|Basic)\s+)\S+", r"\1******", text)
    text = re.sub(r"(?i)(https?://[^\s/:]+:)[^@/\s]+@", r"\1******@", text)
    return text


def event_key(event: dict) -> str:
    raw = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def emit(event: dict) -> None:
    if not persistence_policy.keep(event):
        return
    event["eventKey"] = event_key(event)
    try:
        events.put(event, timeout=1)
    except queue.Full:
        pass


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def read_cmdline(pid: int) -> str:
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as fh:
            return fh.read(4096).replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return ""


def read_ppid(pid: int) -> int:
    try:
        with open("/proc/%d/stat" % pid) as fh:
            return int(fh.read().rsplit(")", 1)[1].split()[1])
    except (OSError, IndexError, ValueError):
        return 0


def container_of(pid: int) -> str:
    """Return the container id owning a pid, or "" for host processes."""
    try:
        with open("/proc/%d/cgroup" % pid) as fh:
            body = fh.read()
    except OSError:
        return ""
    for line in body.splitlines():
        match = re.search(r"([0-9a-f]{64})|docker[_-]([0-9a-f]{12,64})", line)
        if match:
            return (match.group(1) or match.group(2))[:12]
    return ""


# A short-lived command inside a container can exit before /proc/<pid> is read
# back, and it is not yet in the container cgroup when the fork event arrives.
# Snapshotting cgroup.procs keeps a short-lived pid→container map that survives
# both races. Two generations are kept so a pid that died since the last sweep
# can still be attributed.
pid_map: dict[int, str] = {}
pid_map_previous: dict[int, str] = {}
pid_map_lock = threading.Lock()
CGROUP_SYSTEM_SLICE = "/sys/fs/cgroup/system.slice"


def refresh_pid_map() -> None:
    while True:
        current: dict[int, str] = {}
        try:
            for entry in os.listdir(CGROUP_SYSTEM_SLICE):
                if not (entry.startswith("docker-") and entry.endswith(".scope")):
                    continue
                cid = entry[len("docker-"):-len(".scope")][:12]
                try:
                    with open(os.path.join(CGROUP_SYSTEM_SLICE, entry, "cgroup.procs")) as fh:
                        for line in fh:
                            line = line.strip()
                            if line.isdigit():
                                current[int(line)] = cid
                except OSError:
                    continue
        except OSError:
            pass
        with pid_map_lock:
            pid_map_previous.clear()
            pid_map_previous.update(pid_map)
            pid_map.clear()
            pid_map.update(current)
        time.sleep(1.5)


def container_for_pid(pid: int) -> str:
    with pid_map_lock:
        return pid_map.get(pid) or pid_map_previous.get(pid) or ""


# ---------------------------------------------------------------------------
# control plane — container runtime events
# ---------------------------------------------------------------------------

containers: dict[str, str] = {}          # container id -> "name (image)"
container_lock = threading.Lock()


def container_stream(cfg: argparse.Namespace) -> None:
    """Track container lifecycle: what the agent starts and tears down."""
    def refresh():
        try:
            out = subprocess.run(["docker", "ps", "--format", "{{.ID}}|{{.Names}}|{{.Image}}"],
                                 capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            return
        with container_lock:
            for line in out.splitlines():
                parts = line.split("|")
                if len(parts) == 3:
                    containers[parts[0]] = "%s (%s)" % (parts[1], parts[2])

    refresh()
    threading.Thread(target=lambda: [refresh() or time.sleep(5) for _ in iter(int, 1)],
                     daemon=True).start()

    # Health probes dominate a compose stack; they are filtered unless asked for.
    noise = re.compile(r"pg_isready|healthcheck|/healthz|health\s*-", re.I)
    cmd = ["docker", "events", "--format", "{{json .}}",
           "--filter", "event=create", "--filter", "event=start",
           "--filter", "event=die", "--filter", "event=destroy",
           "--filter", "event=exec_create"]
    while True:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True,
                                    errors="replace", bufsize=1)
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                actor = rec.get("Actor", {})
                attrs = actor.get("Attributes", {})
                action = str(rec.get("Action") or rec.get("status") or "")
                if action.startswith("exec_") and not cfg.include_probe and noise.search(action):
                    continue
                cid = str(actor.get("ID", ""))[:12]
                with container_lock:
                    cname = containers.get(cid, attrs.get("name", ""))
                emit({
                    "time": now_iso(), "component": cfg.component,
                    "category": "control-plane",
                    "operation": "CONTAINER_" + action.split(":")[0].strip().upper().replace(" ", "_"),
                    "process": "docker", "pid": 0, "containerId": cid, "container": cname,
                    "resource": attrs.get("image", "") or action,
                    "data": json.dumps({"name": attrs.get("name", ""),
                                        "command": action.split(":", 1)[1].strip() if ":" in action else ""},
                                       ensure_ascii=False),
                    "result": "CAPTURED", "source": "container runtime events API",
                    "evidence": rec,
                })
        except (OSError, subprocess.SubprocessError):
            time.sleep(5)


# ---------------------------------------------------------------------------
# kernel plane — process execution
# ---------------------------------------------------------------------------

NETLINK_CONNECTOR = 11
CN_IDX_PROC = 1
CN_VAL_PROC = 1
PROC_CN_MCAST_LISTEN = 1
NLMSG_DONE = 3
NLM_F_REQUEST = 0x0001
NLM_F_ACK = 0x0004
PROC_EVENT_FORK = 0x00000001
PROC_EVENT_EXEC = 0x00000002
PROC_EVENT_EXIT = 0x80000000


def proc_connector_socket() -> socket.socket:
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
    sock.bind((os.getpid(), CN_IDX_PROC))
    payload = struct.pack("=IHHII", 16 + 20 + 4, NLMSG_DONE, NLM_F_REQUEST | NLM_F_ACK, 1, os.getpid())
    payload += struct.pack("=IIIIHH", CN_IDX_PROC, CN_VAL_PROC, 1, 0, 4, 0)
    payload += struct.pack("=I", PROC_CN_MCAST_LISTEN)
    sock.send(payload)
    return sock


def proc_stream(cfg: argparse.Namespace) -> None:
    sock = proc_connector_socket()
    tracked: dict[int, dict] = {}            # pid -> {cmdline, container}
    forks: dict[int, dict] = {}              # child pid -> {parent, parent_cmd, container}
    while True:
        try:
            data = sock.recv(65535)
        except OSError:
            time.sleep(2)
            continue
        offset = 0
        while offset + 16 <= len(data):
            (nl_len, nl_type, _f, _s, _p) = struct.unpack_from("=IHHII", data, offset)
            if nl_len < 16 or offset + nl_len > len(data):
                break
            body = data[offset + 16:offset + nl_len]
            offset += nl_len
            # The kernel proc connector delivers its events with nlmsg_type
            # NLMSG_DONE, so only NLMSG_ERROR (0x2) may be skipped here.
            if nl_type == 0x2 or len(body) < 36:
                continue
            (what, _cpu, ts_ns) = struct.unpack_from("=IIQ", body, 20)
            payload = body[36:]

            if what == PROC_EVENT_FORK and len(payload) >= 16:
                # A fork is the only moment guaranteed to still have a live parent,
                # so it is where container attribution is captured for short-lived
                # commands that exit before exec can be read back.
                _ppid, ptgid, cpid, _ctgid = struct.unpack_from("=IIII", payload, 0)
                cid = container_for_pid(cpid) or container_of(ptgid) or container_of(cpid)
                if not cid:
                    continue
                forks[cpid] = {"parent": ptgid, "parent_cmd": read_cmdline(ptgid),
                               "container": cid}
                if len(forks) > 5000:
                    for stale in list(forks)[:1000]:
                        forks.pop(stale, None)
                continue

            if what == PROC_EVENT_EXEC and len(payload) >= 8:
                pid, _tgid = struct.unpack_from("=II", payload, 0)
                cmdline = read_cmdline(pid)
                fork = forks.get(pid, {})
                cid = container_for_pid(pid) or container_of(pid) or fork.get("container", "")
                interesting = (cid or cfg.agent in cmdline
                               or any(k in cmdline for k in cfg.keywords)
                               or cfg.agent in fork.get("parent_cmd", ""))
                if not interesting:
                    continue
                tracked[pid] = {"cmdline": cmdline, "container": cid}
                with container_lock:
                    cname = containers.get(cid, cid)
                parent_cmd = fork.get("parent_cmd", "")
                shown = cmdline or "(cmdline unavailable; parent=%s)" % parent_cmd
                emit({
                    "time": now_iso(), "component": cfg.component,
                    "category": "kernel", "operation": "EXEC",
                    "process": (cmdline or parent_cmd).split(" ", 1)[0] or "unknown",
                    "pid": pid, "ppid": read_ppid(pid) or fork.get("parent", 0),
                    "containerId": cid, "container": cname,
                    "resource": mask_passwords(shown),
                    "data": "ts_ns=%d parent=%s" % (ts_ns, mask_passwords(parent_cmd)),
                    "result": "CAPTURED" if cmdline else "PARTIAL_EVIDENCE",
                    "source": "netlink proc connector · PROC_EVENT_EXEC",
                    "evidence": {"cmdline": mask_passwords(cmdline), "pid": pid,
                                 "parent_cmd": mask_passwords(parent_cmd),
                                 "container_id": cid, "container": cname},
                })
            elif what == PROC_EVENT_EXIT and len(payload) >= 16:
                pid, _tgid, code, sig = struct.unpack_from("=IIII", payload, 0)
                info = tracked.pop(pid, None) or {}
                extra = forks.pop(pid, {})
                cmdline = info.get("cmdline") or extra.get("parent_cmd", "")
                if not cmdline and not info:
                    continue
                emit({
                    "time": now_iso(), "component": cfg.component,
                    "category": "kernel", "operation": "EXIT",
                    "process": cmdline.split(" ", 1)[0] or "unknown", "pid": pid,
                    "containerId": info.get("container") or extra.get("container", ""),
                    "resource": "", "data": "exit_code=%d signal=%d" % (code, sig),
                    "result": "EXITED", "source": "netlink proc connector · PROC_EVENT_EXIT",
                    "evidence": {"exit_code": code, "exit_signal": sig,
                                 "cmdline": mask_passwords(cmdline)},
                })


# ---------------------------------------------------------------------------
# kernel plane — file access
# ---------------------------------------------------------------------------

IN_ACCESS, IN_MODIFY, IN_OPEN, IN_CREATE, IN_DELETE = 0x1, 0x2, 0x20, 0x100, 0x200
WATCH_MASK = IN_ACCESS | IN_MODIFY | IN_OPEN | IN_CREATE | IN_DELETE
OP_NAMES = {IN_ACCESS: "FILE_ACCESS", IN_MODIFY: "FILE_MODIFY", IN_OPEN: "FILE_OPEN",
            IN_CREATE: "FILE_CREATE", IN_DELETE: "FILE_DELETE"}


def inotify_stream(cfg: argparse.Namespace) -> None:
    if not cfg.watch:
        return
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = libc.inotify_init1(0)
    if fd < 0:
        return
    if libc.inotify_add_watch(fd, cfg.watch.encode(), WATCH_MASK) < 0:
        return
    while True:
        try:
            buf = os.read(fd, 8192)
        except OSError:
            time.sleep(1)
            continue
        pos = 0
        while pos + 16 <= len(buf):
            _wd, mask, _cookie, length = struct.unpack_from("=iIII", buf, pos)
            name = buf[pos + 16:pos + 16 + length].split(b"\0", 1)[0].decode("utf-8", "replace")
            pos += 16 + length
            emit({
                "time": now_iso(), "component": cfg.component,
                "category": "kernel", "operation": OP_NAMES.get(mask, "FILE_EVENT"),
                "process": cfg.agent, "pid": 0, "containerId": "",
                "resource": os.path.join(cfg.watch, name), "data": "mask=0x%x" % mask,
                "result": "CAPTURED", "source": "inotify on agent data path",
                "evidence": {"watch": cfg.watch, "name": name, "mask": mask},
            })


# ---------------------------------------------------------------------------
# network plane — egress audit
# ---------------------------------------------------------------------------

def socket_inode_owner() -> dict[str, int]:
    """Map socket inode -> pid by scanning /proc/<pid>/fd (best-effort)."""
    mapping: dict[str, int] = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        fd_dir = "/proc/%s/fd" % entry
        try:
            for fd in os.listdir(fd_dir):
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                except OSError:
                    continue
                if target.startswith("socket:["):
                    mapping[target[8:-1]] = int(entry)
        except OSError:
            continue
    return mapping


def tcp_endpoint_map() -> dict[str, int]:
    """Map "local:port-remote:port" -> pid for established tcp sockets."""
    owners = socket_inode_owner()
    result: dict[str, int] = {}
    try:
        with open("/proc/net/tcp") as fh:
            next(fh)
            for line in fh:
                parts = line.split()
                local, remote, state, _tx, _rx, _tr, _tm, _retr, _uid, _to, inode = parts[:11]
                if state != "01" or inode == "0":
                    continue
                result["%s-%s" % (local, remote)] = owners.get(inode, 0)
    except OSError:
        pass
    return result


def is_local_noise(dst: str) -> bool:
    """Drop loopback, broadcast and multicast from the egress audit."""
    first = int(dst.split(".")[0]) if dst[:1].isdigit() else 0
    return dst.startswith("127.") or dst == "255.255.255.255" or 224 <= first <= 239


def classify_destination(dst: str, dpt: str, cfg: argparse.Namespace) -> str:
    if dst in cfg.targets:
        return "AUTHORIZED_TARGET"
    if dst.startswith("172.") or dst.startswith("10.") or dst.startswith("192.168."):
        return "INTERNAL"
    return "EXTERNAL_EGRESS"


def egress_stream(cfg: argparse.Namespace) -> None:
    """Parse kernel nf LOG lines for new outbound connections."""
    cmd = ["journalctl", "-k", "-f", "-n", "0", "-o", "cat"]
    pattern = re.compile(r"SRC=(\S+)\s+DST=(\S+).*?SPT=(\d+)\s+DPT=(\d+)")
    while True:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True,
                                    errors="replace", bufsize=1)
            for line in proc.stdout:
                if cfg.log_prefix not in line:
                    continue
                match = pattern.search(line)
                if not match:
                    continue
                src, dst, spt, dpt = match.groups()
                if is_local_noise(dst):
                    continue
                endpoints = tcp_endpoint_map()
                pid = endpoints.get("%s:%s-%s:%s" % (src, spt, dst, dpt), 0) or \
                      endpoints.get("%s:%04X-%s:%04X" % (src, int(spt), dst, int(dpt)), 0)
                classification = classify_destination(dst, dpt, cfg)
                emit({
                    "time": now_iso(), "component": cfg.component,
                    "category": "network", "operation": "EGRESS_CONNECT",
                    "process": read_cmdline(pid).split(" ", 1)[0] if pid else "",
                    "pid": pid, "containerId": container_of(pid) if pid else "",
                    "resource": "%s:%s -> %s:%s" % (src, spt, dst, dpt),
                    "data": json.dumps({"classification": classification}, ensure_ascii=False),
                    "result": "CAPTURED",
                    "source": "netfilter LOG · conntrack NEW",
                    "evidence": {"src": src, "sport": spt, "dst": dst, "dport": dpt,
                                 "pid": pid, "classification": classification,
                                 "raw": line.strip()[:400]},
                })
        except (OSError, subprocess.SubprocessError):
            time.sleep(5)


# ---------------------------------------------------------------------------
# sink
# ---------------------------------------------------------------------------

def sink_loop(cfg: argparse.Namespace) -> None:
    token = ""
    if cfg.ingest_url and cfg.ingest_token_file and os.path.exists(cfg.ingest_token_file):
        try:
            token = open(cfg.ingest_token_file, encoding="utf-8").read().strip()
        except OSError:
            token = ""
    handle = None
    if cfg.out:
        os.makedirs(os.path.dirname(cfg.out) or ".", exist_ok=True)
        handle = open(cfg.out, "a", encoding="utf-8")
    pending: list[dict] = []
    while True:
        try:
            pending.append(events.get(timeout=2))
        except queue.Empty:
            pass
        if not pending:
            continue
        while len(pending) < 100:
            try:
                pending.append(events.get_nowait())
            except queue.Empty:
                break
        for event in pending:
            if event["eventKey"] in seen:
                continue
            seen.append(event["eventKey"])
            line = json.dumps(event, ensure_ascii=False)
            # Canonical JSONL only; avoid a complete duplicate in journald.
            if handle:
                handle.write(line + "\n")
                handle.flush()
        if token and cfg.ingest_url:
            body = json.dumps({"events": pending}, ensure_ascii=False).encode()
            request = urllib.request.Request(cfg.ingest_url, data=body, method="POST",
                                             headers={"Content-Type": "application/json",
                                                      "Authorization": "Bearer " + token,
                                                      "User-Agent": "AgentReins-Linux/1.0"})
            try:
                with urllib.request.urlopen(request, timeout=15):
                    pass
            except Exception:
                time.sleep(5)
        pending.clear()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="AgentReins host agent observation stream")
    p.add_argument("--agent", default=os.environ.get("AGENTREINS_AGENT", "pentagi"))
    p.add_argument("--watch", default=os.environ.get("AGENTREINS_WATCH", "/opt/pentagi/data"))
    p.add_argument("--component", default=os.environ.get("AGENTREINS_COMPONENT", "PentAGI"))
    p.add_argument("--keywords", default=os.environ.get(
        "AGENTREINS_KEYWORDS", "docker,containerd,kali,nmap,sqlmap,nikto,curl,python"))
    p.add_argument("--targets", default=os.environ.get("AGENTREINS_TARGETS", ""),
                   help="comma separated authorized target IPs, classified AUTHORIZED_TARGET")
    p.add_argument("--log-prefix", default=os.environ.get("AGENTREINS_LOG_PREFIX", "AGENTREINS_EGRESS"))
    p.add_argument("--include-probe", action="store_true", default=bool(
        os.environ.get("AGENTREINS_INCLUDE_PROBE")),
        help="also record container health probes (noisy on compose stacks)")
    p.add_argument("--out", default=os.environ.get("AGENTREINS_OUT",
                                                   "/var/log/agentreins/host.jsonl"))
    p.add_argument("--ingest-url", default=os.environ.get("AGENTREINS_INGEST_URL", ""))
    p.add_argument("--ingest-token-file", default=os.environ.get("AGENTREINS_INGEST_TOKEN_FILE", ""))
    cfg = p.parse_args()
    cfg.keywords = [k.strip() for k in cfg.keywords.split(",") if k.strip()]
    cfg.targets = [t.strip() for t in cfg.targets.split(",") if t.strip()]
    return cfg


def main() -> None:
    if os.geteuid() != 0:
        sys.exit("host observation requires root (netlink proc connector, inotify)")
    cfg = parse_args()
    threading.Thread(target=refresh_pid_map, daemon=True).start()
    for target in (container_stream, proc_stream, inotify_stream, egress_stream, sink_loop):
        threading.Thread(target=target, args=(cfg,), daemon=True).start()
    print("AgentReins host observer active: agent=%s watch=%s targets=%s"
          % (cfg.agent, cfg.watch, cfg.targets or "-"), flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
