#!/usr/bin/env python3
"""Host JSONL adapter. Bounded spool; independent heartbeat; registered workloads only."""
import collections,datetime,hashlib,ipaddress,json,os,re,shlex,socket,subprocess,threading,time,urllib.parse
from pathlib import Path
try:from .gate_client import Client
except ImportError:from gate_client import Client
VERSION='runtime-1.0'
def proc_key(pid):
 try:
  s=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split();return {'startTicks':s[19],'ppid':int(s[1])}
 except (OSError,IndexError,ValueError):return {}
def timestamp(value):
 try:return datetime.datetime.fromisoformat(value).timestamp()
 except (TypeError,ValueError):return time.time()
class Adapter:
 def __init__(self,config):self.config=config;self.containers={};self.last_docker=0;self.boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();self.identities={};self.lock=threading.Lock();self.stats=collections.Counter();self.last_event=None
 def identities_refresh(self):
  now=time.time()
  if now-self.last_docker<5:return
  self.last_docker=now
  try:
   rows=subprocess.check_output(['docker','ps','--no-trunc','--format','{{.ID}}|{{.Names}}'],text=True,timeout=3).splitlines();self.containers={cid:name for line in rows for cid,_,name in [line.partition('|')] if any(re.fullmatch(p,name) for p in self.config['containerPatterns'])}
  except (OSError,subprocess.SubprocessError):pass
 def identity(self,r):
  self.identities_refresh();pid=int(r.get('pid') or 0);ppid=int(r.get('ppid') or 0);cid=r.get('containerId') or (r.get('evidence') or {}).get('containerId') or '';p=proc_key(pid) if pid else {};workload=None;basis=None
  for known,name in self.containers.items():
   if cid and (known.startswith(cid) or cid.startswith(known)):workload=name;basis='已登记容器 ID 与主机事件 cgroup 一致';break
  # Executor labels are bounded and explicitly registered in config; no arbitrary process-name match.
  lab=Path(self.config.get('labIdentity','/var/lib/agentreins-runtime/lab-identity.json'))
  try:
   v=json.loads(lab.read_text());current=proc_key(v['pid'])
   if current.get('startTicks')==v['startTicks']:
    if pid==v['pid'] or ppid==v['pid']:workload='runtime-lab';basis='受控实验父 PID 与 /proc 启动时刻匹配'
  except (OSError,ValueError,KeyError):pass
  if not workload and ppid in self.identities:
   parent=self.identities[ppid]
   if time.time()-parent['seen']<120 and proc_key(ppid).get('startTicks')==parent['startTicks']:workload=parent['workload'];basis='已登记父进程与启动时刻匹配'
  if not workload:return None
  ident={'bootId':self.boot,'pid':pid,'startTicks':p.get('startTicks'),'containerId':cid or None,'basis':basis}
  if pid and p.get('startTicks'):self.identities[pid]={'workload':workload,'startTicks':p['startTicks'],'seen':time.time()}
  if len(self.identities)>2000:self.identities={k:v for k,v in self.identities.items() if time.time()-v['seen']<120}
  return workload,ident
 def normalize(self,r):
  if r.get('operation') not in ('AUDIT_EXEC','EXEC','AUDIT_FILE','AUDIT_CONNECT','AUDIT_SENDTO'):return None
  if time.time()-timestamp(r.get('time'))>120:self.stats['staleSkipped']+=1;return None
  identity=self.identity(r)
  if not identity:return None
  workload,ident=identity;op=r.get('operation','');ev=r.get('evidence') or {};e={'id':r.get('eventKey') or hashlib.sha256(json.dumps(r,sort_keys=True).encode()).hexdigest(),'time':timestamp(r.get('time')),'workload':workload,'identity':ident,'pid':int(r.get('pid') or 0),'ppid':int(r.get('ppid') or 0),'containerId':r.get('containerId'),'operation':op,'sourceEvidence':{'source':r.get('source'),'auditSerial':ev.get('auditSerial'),'syscall':ev.get('syscall'),'exit':ev.get('exit')},'result':'success' if r.get('result')=='SUCCESS' else 'attempt','policy':self.config.get('policies',{}).get(workload,{})}
  if op in ('AUDIT_EXEC','EXEC'):
   e.update(kind='process',command=r.get('resource',''));e['execPaths']=[]
   try:
    argv=shlex.split(e['command']);e['execPaths']=[x for x in argv if x.startswith('/')]
    if any(Path(x).name in ('curl','wget') for x in argv):
     for flag in ('-o','-O','--output','--output-document'):
      if flag in argv and argv.index(flag)+1<len(argv):e['downloadPath']=argv[argv.index(flag)+1]
     e['destination']=next((x for x in argv if x.startswith(('http://','https://'))),None)
   except ValueError:pass
  elif op=='AUDIT_FILE' and ev.get('access')=='read_open':
   e.update(kind='file',path=(ev.get('paths') or [r.get('resource','')])[-1],access='read_open',result='success' if r.get('result')=='SUCCESS' else 'denied')
  elif op in ('AUDIT_CONNECT','AUDIT_SENDTO') and ev.get('destination'):
   e.update(kind='network',destination=ev['destination'],port=ev.get('port'))
  else:return None
  if workload=='runtime-lab':
   try:e['runId']=json.loads(Path(self.config.get('labIdentity','/var/lib/agentreins-runtime/lab-identity.json')).read_text()).get('runId')
   except (OSError,ValueError):pass
  self.last_event=time.time();self.stats['normalized']+=1;return e
 def heartbeat(self):
  def service(name):
   try:return subprocess.run(['systemctl','is-active',name],capture_output=True,text=True,timeout=2).stdout.strip()
   except Exception:return 'unknown'
  audit={}
  try:audit=dict(line.split(None,1) for line in subprocess.check_output(['auditctl','-s'],text=True,timeout=2).splitlines() if len(line.split(None,1))==2)
  except Exception:pass
  host=service('agentreins-host-stream');aud=service('agentreins-audit-bridge');gateway=service('agentreins-semantic-gateway');active=host=='active' and aud=='active'
  return {'host':socket.gethostname(),'version':VERSION,'bootId':self.boot,'layers':{'process':'active' if active else 'unavailable','network':'active' if aud=='active' else 'unavailable','file':'watched_paths_only' if aud=='active' else 'unavailable','model':'gateway_available_unlinked' if gateway=='active' else 'not_connected','tool':'REA analyze boundary only'},'drop':int(audit['lost']) if audit.get('lost','').isdigit() else None,'auditBacklog':audit.get('backlog'),'counters':dict(self.stats),'lastEvent':self.last_event,'workloads':self.containers,'fileWatchScope':self.config.get('fileWatchScope',[]),'serviceState':{'host':host,'audit':aud},'policyStatus':{'S05':'per-workload; disabled if no allowedNetworks configured'}}
def main():
 client=Client();config=client.config;adapter=Adapter(config);queue=collections.deque(maxlen=500);log=Path(config.get('log','/var/log/agentreins/host.jsonl'));cursor=Path(config.get('cursor','/var/lib/agentreins-runtime/cursor.json'));cursor.parent.mkdir(parents=True,exist_ok=True);stop=threading.Event()
 def heartbeat_loop():
  while not stop.is_set():
   try:client.call('heartbeat',adapter.heartbeat())
   except Exception:adapter.stats['heartbeatErrors']+=1
   stop.wait(10)
 threading.Thread(target=heartbeat_loop,daemon=True).start();handle=None;inode=None;last_send=0;last_offset=0
 while True:
  try:
   stat=log.stat()
   if handle is None or stat.st_ino!=inode:
    if handle:handle.close()
    handle=log.open();inode=stat.st_ino
    try:
     saved=json.loads(cursor.read_text())
     if saved['inode']==inode and saved['offset']<=stat.st_size:handle.seek(saved['offset'])
     else:handle.seek(0,2)
    except (OSError,ValueError,KeyError):handle.seek(0,2)
   if handle.tell()>stat.st_size:handle.seek(0)
   for _ in range(5000):
    offset=handle.tell();line=handle.readline(1024*1024)
    if not line:break
    if not line.endswith('\n'):
     if len(line)>=1024*1024:
      while line and not line.endswith('\n'):line=handle.readline(1024*1024)
      adapter.stats['oversizeDropped']+=1;continue
     handle.seek(offset);break
    try:e=adapter.normalize(json.loads(line))
    except (ValueError,TypeError,KeyError):adapter.stats['parseErrors']+=1;continue
    if e:
     if len(queue)==queue.maxlen:adapter.stats['spoolDropped']+=1
     queue.append(e)
   if time.monotonic()-last_send>1 and queue:
    while queue and time.time()-queue[0]['time']>290:queue.popleft();adapter.stats['expiredDropped']+=1
    batch=list(queue)[:50]
    try:
     client.call('ingest',{'events':batch})
     for _ in batch:queue.popleft()
     cursor.write_text(json.dumps({'inode':inode,'offset':handle.tell()}))
    except Exception:adapter.stats['sendErrors']+=1
    last_send=time.monotonic()
   if not queue:cursor.write_text(json.dumps({'inode':inode,'offset':handle.tell()}))
  except OSError:adapter.stats['logErrors']+=1
  time.sleep(.4)
if __name__=='__main__':main()
