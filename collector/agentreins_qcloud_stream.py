#!/usr/bin/env python3
"""Stream Tencent Cloud agent runtime evidence to AgentReins Intelligence."""
import base64, hashlib, json, os, queue, re, subprocess, threading, time, urllib.request

ENDPOINT = os.environ.get("AGENTREINS_INGEST_URL", "https://www.chuhaijian.com/api/agentsec/ingest")
TOKEN_FILE = os.environ.get("AGENTREINS_INGEST_TOKEN_FILE", "/etc/agentreins/ingest.token")
TAT_LOG = "/usr/local/qcloud/tat_agent/log/tat_agent.log"
events = queue.Queue(maxsize=10000)

AGENTS = {
    "tat_agent": "TAT Agent", "sgagent": "Stargate", "sgagent64": "Stargate",
    "YDLive": "YunJing Live", "YDService": "YunJing Service", "python": "Barad Monitor",
    "python26": "Barad Monitor", "barad_agent": "Barad Monitor"
}

def component(text):
    if "/usr/local/qcloud/monitor/" in text or "barad_agent" in text: return "Barad Monitor"
    for needle, name in AGENTS.items():
        if needle in ("python", "python26", "barad_agent"): continue
        if needle.lower() in text.lower(): return name
    return "Tencent Cloud Agent"

def mask_passwords(text):
    # Preserve the command verbatim except values that can authenticate or take over the host.
    text = re.sub(r'(?im)^([ \t]*#\s*root\s*\n[ \t]*#\s*)\S+', r'\1******', text)
    text = re.sub(r'(?i)\b(password|passwd|pwd)(\s*[:=]\s*)(?![$(])([^\s\"\']+)', r'\1\2******', text)
    text = re.sub(r'(?i)(Authorization:\s*(?:Bearer|Basic)\s+)\S+', r'\1******', text)
    text = re.sub(r'(?i)(https?://[^\s/:]+:)[^@/\s]+@', r'\1******@', text)
    return text

def event_key(event):
    raw = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()

def emit(event):
    event["eventKey"] = event_key(event)
    try: events.put(event, timeout=1)
    except queue.Full: pass

def kubearmor_stream():
    cmd = ["journalctl", "-u", "agentz-kubearmor-feed.service", "-f", "-n", "0", "-o", "cat"]
    while True:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, errors="replace", bufsize=1)
        for line in process.stdout:
            try: raw = json.loads(line)
            except json.JSONDecodeError: continue
            searchable = " ".join(str(raw.get(k, "")) for k in ("ProcessName","ParentProcessName","Source","Resource"))
            if "/opt/agentreins/" in searchable or "agentz-kubearmor-feed.service" in searchable: continue
            if not any(x in searchable.lower() for x in ("qcloud", "barad_agent", "tat_agent", "ydservice", "ydlive", "sgagent")): continue
            emit({"time":raw.get("UpdatedTime"), "component":component(searchable), "category":"kernel",
                  "operation":raw.get("Operation"), "process":raw.get("ProcessName"),
                  "parentProcess":raw.get("ParentProcessName"), "pid":raw.get("HostPID"), "ppid":raw.get("HostPPID"),
                  "resource":raw.get("Resource"), "data":raw.get("Data"), "result":raw.get("Result"),
                  "source":raw.get("Source"), "evidence":raw})
        time.sleep(2)

def tat_event(line):
    parts = line.rstrip().split("|", 3)
    if len(parts) != 4: return None
    timestamp, code_source, level, message = parts
    item = {"time":timestamp, "component":"TAT Agent", "category":"control-plane",
            "operation":"TAT_LOG", "process":"/usr/local/qcloud/tat_agent/tat_agent",
            "source":code_source, "result":level, "data":mask_passwords(message),
            "evidence":{"level":level,"source":code_source,"message":mask_passwords(message)}}
    task = re.search(r'invt-[A-Za-z0-9]+', message)
    if task: item["taskId"] = task.group(0)
    if "response text " in message:
        try:
            response = json.loads(message.split("response text ", 1)[1])
            tasks = response.get("Response", {}).get("InvocationNormalTaskSet", [])
            if tasks:
                task_data = tasks[0].copy()
                encoded = task_data.pop("Cmd", "")
                decoded = base64.b64decode(encoded).decode("utf-8", "replace") if encoded else ""
                decoded = mask_passwords(decoded)
                item.update({"operation":"RECEIVE_COMMAND", "taskId":task_data.get("InvocationTaskId", ""),
                             "resource":decoded, "data":json.dumps(task_data, ensure_ascii=False)})
                item["evidence"] = {"transport":"HTTPS response/application log", "task":task_data, "decodedCommand":decoded}
        except Exception: pass
    elif "receive `kick`" in message: item["operation"] = "RECEIVE_KICK"
    elif "ReportTaskStart" in message: item["operation"] = "REPORT_TASK_START"
    elif "ReportTaskFinish" in message: item["operation"] = "REPORT_TASK_FINISH"
    elif "execute begin" in message or "start running" in message: item["operation"] = "EXECUTE"
    return item

def tat_stream():
    # Replay the current retained log once so a fresh console immediately has a
    # provable task chain; event keys keep restarts idempotent.
    try:
        with open(TAT_LOG, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                item = tat_event(line)
                if item: emit(item)
    except OSError: pass
    process = subprocess.Popen(["tail", "-F", "-n", "0", TAT_LOG], stdout=subprocess.PIPE, text=True, errors="replace", bufsize=1)
    for line in process.stdout:
        item = tat_event(line)
        if item: emit(item)

def agentsight_stream():
    cmd = ["journalctl", "-u", "agentsight-tat-tls.service", "-f", "-n", "0", "-o", "cat"]
    while True:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, errors="replace", bufsize=1)
        for line in process.stdout:
            try:
                outer = json.loads(line)
                content = outer.get("data", line) if isinstance(outer, dict) else line
            except json.JSONDecodeError: content = line
            if "AGENTSIGHT|TLS_" not in content: continue
            content = content[content.index("AGENTSIGHT|TLS_"):]
            parts = content.split("|", 4)
            if len(parts) != 5: continue
            _, direction, pid, tid, plaintext = parts
            plaintext = mask_passwords(plaintext)
            task = re.search(r'invt-[A-Za-z0-9]+', plaintext)
            emit({"time":time.strftime("%Y-%m-%dT%H:%M:%S%z"), "component":"TAT Agent",
                  "category":"tls-plaintext", "operation":direction, "process":"tat_agent",
                  "pid":int(pid), "resource":plaintext, "data":f"thread={tid}",
                  "result":"CAPTURED", "taskId":task.group(0) if task else "",
                  "source":"AgentSight uprobe · embedded OpenSSL",
                  "evidence":{"direction":direction,"pid":int(pid),"tid":int(tid),"plaintext":plaintext}})
        time.sleep(2)

def send_loop():
    token = open(TOKEN_FILE, encoding="utf-8").read().strip()
    pending = []
    while True:
        try: pending.append(events.get(timeout=2))
        except queue.Empty: pass
        if not pending: continue
        while len(pending) < 100:
            try: pending.append(events.get_nowait())
            except queue.Empty: break
        body = json.dumps({"events":pending}, ensure_ascii=False).encode()
        request = urllib.request.Request(ENDPOINT, data=body, method="POST",
            headers={"Content-Type":"application/json", "Authorization":"Bearer " + token, "User-Agent":"AgentReins-Linux/1.0"})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                if response.status == 202: pending.clear()
        except Exception: time.sleep(5)

for target in (kubearmor_stream, tat_stream, agentsight_stream, send_loop):
    threading.Thread(target=target, daemon=True).start()
while True: time.sleep(3600)
