#!/usr/bin/env python3
"""Host JSONL adapter. Bounded spool; independent heartbeat; registered workloads only."""
import collections,datetime,hashlib,ipaddress,json,os,re,shlex,socket,subprocess,threading,time,urllib.parse
from pathlib import Path
try:from .gate_client import Client
except ImportError:from gate_client import Client
try:from .command_parse import parse as parse_command
except ImportError:from command_parse import parse as parse_command
try:from .agents_config import load_agents, agent_for_container, session_from_container, role_for_container
except ImportError:from agents_config import load_agents, agent_for_container, session_from_container, role_for_container
VERSION='runtime-1.5-s23'
SEMANTIC_OPS={'MODEL_REQUEST','MODEL_RESPONSE','TOOL_CALL','TOOL_RESULT','TOOL_DEFINITIONS'}
ENRICHMENT_ATTRIBUTION={'DIRECT_API_EVENT','DIRECT_API_STATE','EXECUTOR_RUNTIME_ID'}
# Plain-process deploys have no systemd unit. Coverage still needs to see whether the collector is running.
COLLECTOR_MARKERS={'agentreins-host-stream':'agentreins_host_stream.py','agentreins-audit-bridge':'audit_bridge.py','agentreins-semantic-gateway':'semantic_gateway.py'}
def process_matches(marker, proc_root='/proc'):
 root=Path(proc_root)
 if not marker or not root.is_dir():return False
 for entry in root.iterdir():
  if not entry.name.isdigit():continue
  try:raw=(entry/'cmdline').read_bytes()
  except OSError:continue
  if marker.encode() in raw.replace(b'\x00',b' '):return True
 return False
def service_state(name, proc_root='/proc'):
 """active when systemd says so or the collector process is visible. inactive when this unit is known and absent."""
 reported=''
 try:reported=subprocess.run(['systemctl','is-active',name],capture_output=True,text=True,timeout=2).stdout.strip()
 except Exception:reported=''
 marker=COLLECTOR_MARKERS.get(name)
 if marker and process_matches(marker, proc_root):return 'active'
 if reported:return reported
 return 'inactive' if marker else 'unknown'
def layer_status(gateway_active, agents_loaded, semantic_age, host_linked=False):
 """Coverage labels for the model and tool layers. semantic_age is seconds since the last routed semantic event."""
 if not gateway_active:model='not_connected'
 elif not agents_loaded:model='gateway_unbound'
 elif semantic_age is not None and semantic_age<=300:model='linked'
 else:model='gateway_bound'
 if host_linked:tool='host_linked'
 elif agents_loaded:tool='semantic_linked'
 else:tool='rea_only'
 return model,tool
def file_fingerprint(path, limit=1024*1024):
 """Hash a regular file without following symlinks. Sensitive contents are not returned."""
 info={}
 try:st=os.lstat(path)
 except OSError:return info
 info['size']=st.st_size;info['mode']=oct(st.st_mode & 0o777)
 if not stat_is_regular(st.st_mode):
  info['skipped']='not_regular';return info
 if st.st_size>limit:
  info['skipped']='too_large';return info
 try:
  import hashlib as _hashlib
  flags=os.O_RDONLY
  if hasattr(os,'O_NOFOLLOW'):flags|=os.O_NOFOLLOW
  fd=os.open(path,flags)
 except OSError:
  info['skipped']='unreadable';return info
 try:
  digest=_hashlib.sha256()
  while True:
   block=os.read(fd,65536)
   if not block:break
   digest.update(block)
  info['sha256']=digest.hexdigest()
 finally:os.close(fd)
 return info
def stat_is_regular(mode):
 import stat
 return stat.S_ISREG(mode)
def lab_workload(pid, ppid, record, current_ticks):
 """True when this pid is the registered lab process or a child it just spawned.

 Short-lived commands can exit before /proc still has a ppid. The lab process may
 list those pids in recentPids; that list is an explicit registration, not a guess.
 """
 if not record or str(current_ticks)!=str(record.get('startTicks')):return False
 try:recent={int(x) for x in (record.get('recentPids') or [])}
 except (TypeError,ValueError):recent=set()
 return pid==int(record.get('pid') or 0) or ppid==int(record.get('pid') or 0) or pid in recent or ppid in recent
def proc_key(pid):
 try:
  s=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split();return {'startTicks':s[19],'ppid':int(s[1])}
 except (OSError,IndexError,ValueError):return {}
def timestamp(value):
 try:return datetime.datetime.fromisoformat(value).timestamp()
 except (TypeError,ValueError):return time.time()
class Adapter:
 def __init__(self,config):
  self.config=config;self.containers={};self.last_docker=0;self.boot=self._boot();self.identities={};self.lock=threading.Lock();self.stats=collections.Counter();self.last_event=None;self.last_semantic=None;self.file_hashes={};self.container_agents={}
  self.agents=self._load_agents()
 def _boot(self):
  try:return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  except OSError:return 'unknown-boot'
 def _load_agents(self):
  inline=self.config.get('agents')
  if inline:return load_agents(data={'agents':inline} if isinstance(inline,list) else inline)
  return load_agents(self.config.get('agentsFile'))
 def identities_refresh(self):
  now=time.time()
  if now-self.last_docker<5:return
  self.last_docker=now
  try:
   rows=subprocess.check_output(['docker','ps','--no-trunc','--format','{{.ID}}|{{.Names}}'],text=True,timeout=3).splitlines();self.containers={};self.container_agents={}
   for line in rows:
    cid,_,name=line.partition('|')
    if not name:continue
    listed=any(re.fullmatch(p,name) for p in self.config.get('containerPatterns') or [])
    agent=agent_for_container(self.agents,name)
    if listed or agent:
     self.containers[cid]=name
     if agent:self.container_agents[cid]=agent['id']
  except (OSError,subprocess.SubprocessError):pass
 def identity(self,r):
  self.identities_refresh();pid=int(r.get('pid') or 0);ppid=int(r.get('ppid') or 0);cid=r.get('containerId') or (r.get('evidence') or {}).get('containerId') or '';p=proc_key(pid) if pid else {};workload=None;basis=None
  for known,name in self.containers.items():
   if cid and (known.startswith(cid) or cid.startswith(known)):workload=name;basis='已登记容器 ID 与主机事件 cgroup 一致';break
  # Executor labels are bounded and explicitly registered in config; no arbitrary process-name match.
  lab=Path(self.config.get('labIdentity','/var/lib/agentreins-runtime/lab-identity.json'))
  try:
   v=json.loads(lab.read_text());current=proc_key(v['pid'])
   if lab_workload(pid, ppid, v, current.get('startTicks')):workload='runtime-lab';basis='受控实验父 PID 与 /proc 启动时刻匹配'
  except (OSError,ValueError,KeyError):pass
  if not workload and ppid in self.identities:
   parent=self.identities[ppid]
   if time.time()-parent['seen']<120 and proc_key(ppid).get('startTicks')==parent['startTicks']:workload=parent['workload'];basis='已登记父进程与启动时刻匹配'
  if not workload:return None
  agent=None
  for known,name in self.containers.items():
   if cid and (known.startswith(cid) or cid.startswith(known)):
    agent=agent_for_container(self.agents,name);break
  if agent is None:agent=agent_for_container(self.agents,workload)
  parent_agent=self.identities.get(ppid) or {}
  ident={'bootId':self.boot,'pid':pid,'startTicks':p.get('startTicks'),'containerId':cid or None,'basis':basis}
  if agent:
   ident['agentId']=agent['id'];session=session_from_container(workload);ident['sessionId']=session
   if session:ident['basis']=basis+'；容器名解析出 PentAGI flowId'
  elif parent_agent.get('agentId'):
   ident['agentId']=parent_agent['agentId']
   if parent_agent.get('sessionId'):ident['sessionId']=parent_agent['sessionId'];ident['basis']=basis+'；父进程已登记的 agent'
  if pid and p.get('startTicks'):self.identities[pid]={'workload':workload,'startTicks':p['startTicks'],'seen':time.time(),'agentId':agent['id'] if agent else None,'sessionId':session_from_container(workload)}
  if len(self.identities)>2000:self.identities={k:v for k,v in self.identities.items() if time.time()-v['seen']<120}
  return workload,ident
 def _decorate_agent(self,e,agent):
  if not agent:return
  policy=dict(e.get('policy') or {})
  for key in ('allowedNetworks','hostGateways','allowedTools','webServers'):
   if agent.get(key) and key not in policy:policy[key]=agent[key]
  peers=[]
  for other in self.agents:
   if other.get('id')!=agent.get('id'):peers.extend(other.get('internalNetworks') or [])
  if peers and 'peerInternalNetworks' not in policy:policy['peerInternalNetworks']=peers
  if policy:e['policy']=policy
  role=role_for_container(agent,e.get('workload'))
  if role:e['containerRole']=role
 def normalize(self,r):
  if r.get('operation')=='HTTP_SUMMARY' or r.get('category')=='http':
   return self.normalize_http(r)
  if r.get('category')=='semantic' or r.get('operation') in SEMANTIC_OPS|{'MODEL_REASONING','MODEL_INTERRUPTED','MODEL_ERROR','MODEL_REJECTED','DIFY_EXECUTION_STATE'}:
   return self.normalize_semantic(r)
  if r.get('operation') not in ('AUDIT_EXEC','EXEC','AUDIT_FILE','AUDIT_CONNECT','AUDIT_SENDTO'):return None
  identity=self.identity(r)
  if not identity:return None
  workload,ident=identity;op=r.get('operation','');ev=r.get('evidence') or {};e={'id':r.get('eventKey') or hashlib.sha256(json.dumps(r,sort_keys=True).encode()).hexdigest(),'time':timestamp(r.get('time')),'workload':workload,'identity':ident,'pid':int(r.get('pid') or 0),'ppid':int(r.get('ppid') or 0),'containerId':r.get('containerId'),'operation':op,'sourceEvidence':{'source':r.get('source'),'auditSerial':ev.get('auditSerial'),'syscall':ev.get('syscall'),'exit':ev.get('exit')},'result':'success' if r.get('result')=='SUCCESS' else 'attempt','policy':self.config.get('policies',{}).get(workload,{})}
  if op in ('AUDIT_EXEC','EXEC'):
   e.update(kind='process',command=r.get('resource',''),cwd=ev.get('cwd') or r.get('cwd'))
   e.update(parse_command(e['command'],e['cwd']))
  elif op=='AUDIT_FILE' and ev.get('access') in ('read_open','metadata_or_write','write'):
   access='read_open' if ev.get('access')=='read_open' else 'write'
   path=(ev.get('paths') or [r.get('resource','')])[-1]
   e.update(kind='file',path=path,access=access,result='success' if r.get('result')=='SUCCESS' else 'denied')
   if access=='write':
    e['sha256Before']=ev.get('sha256Before') if ev.get('sha256Before') is not None else self.file_hashes.get(path)
    finger=file_fingerprint(path) if path else {}
    e['sha256After']=ev.get('sha256After') or finger.get('sha256')
    e['size']=ev.get('size',finger.get('size'))
    if e.get('sha256After'):
     self.file_hashes[path]=e['sha256After']
     if len(self.file_hashes)>5000:self.file_hashes=dict(list(self.file_hashes.items())[-2500:])
  elif op in ('AUDIT_CONNECT','AUDIT_SENDTO') and ev.get('destination'):
   e.update(kind='network',destination=ev['destination'],port=ev.get('port'))
  else:return None
  if ident.get('agentId'):
   e['agentId']=ident['agentId'];e['confidence']='observed'
   if ident.get('sessionId'):e['sessionId']=ident['sessionId']
   agent=agent_for_container(self.agents,workload)
   self._decorate_agent(e,agent)
  if workload=='runtime-lab':
   try:e['runId']=json.loads(Path(self.config.get('labIdentity','/var/lib/agentreins-runtime/lab-identity.json')).read_text()).get('runId')
   except (OSError,ValueError):pass
  self.last_event=time.time();self.stats['normalized']+=1;return e
 def normalize_http(self,r):
  if r.get('operation')!='HTTP_SUMMARY':return None
  ev=r.get('evidence') or {}
  agent=ev.get('agentId') or r.get('agentId')
  if not agent:return None
  e={'id':r.get('eventKey') or hashlib.sha256(json.dumps({'op':'HTTP_SUMMARY','a':agent,'w':ev.get('windowStart'),'s':ev.get('logSource')},sort_keys=True).encode()).hexdigest(),'time':timestamp(r.get('time')),'workload':'http:'+str(agent),'agentId':str(agent),'kind':'http','operation':'HTTP_SUMMARY','identity':{'basis':'入站访问日志映射','bootId':self.boot,'pid':0,'containerId':None,'agentId':str(agent)},'pid':0,'ppid':0,'containerId':None,'result':'success','confidence':'observed','windowStart':ev.get('windowStart'),'windowSeconds':ev.get('windowSeconds') or 60,'logSource':ev.get('logSource') or r.get('resource') or '','clients':ev.get('clients') or [],'totals':ev.get('totals') or {},'categoryHits':ev.get('categoryHits') or [],'sourceEvidence':{'source':r.get('source')}}
  self.last_event=time.time();self.stats['normalized']+=1;self.stats['http']+=1;return e
 def normalize_semantic(self,r):
  ev=r.get('evidence') or {}
  if ev.get('attribution') in ENRICHMENT_ATTRIBUTION or r.get('component') in ('DifyAPIObserver','DifyLiveObserver','REAExecutor'):
   self.stats['semanticEnrichmentSkipped']+=1;return None
  op=r.get('operation')
  if op not in SEMANTIC_OPS:return None
  agent=ev.get('agentId') or r.get('agentId')
  if not agent or ev.get('confidence')=='unknown' or ev.get('chainConfidence')=='unknown':
   self.stats['semanticUnbound']+=1;return None
  kind='tool' if op in ('TOOL_CALL','TOOL_RESULT') else 'model'
  e={'id':r.get('eventKey') or hashlib.sha256(json.dumps({'op':op,'t':r.get('time'),'a':agent,'r':ev.get('requestId'),'tool':ev.get('toolCallId')},sort_keys=True).encode()).hexdigest(),'time':timestamp(r.get('time')),'workload':'gateway:'+str(agent),'agentId':agent,'kind':kind,'operation':op,'identity':{'basis':ev.get('routeBasis') or '网关路由绑定','bootId':self.boot,'pid':0,'containerId':None,'agentId':agent},'pid':0,'ppid':0,'containerId':None,'result':'success','confidence':'observed','chainId':ev.get('chainId'),'runId':ev.get('chainId'),'requestId':ev.get('requestId'),'toolCallId':ev.get('toolCallId'),'toolName':ev.get('toolName'),'argsDigest':ev.get('argsDigest'),'argsEntities':ev.get('argsEntities') or {},'untrustedSegments':ev.get('untrustedSegments') or [],'chainHasUntrusted':bool(ev.get('chainHasUntrusted')),'textExcerpt':(ev.get('textExcerpt') or '')[:2048],'sessionId':ev.get('sessionId'),'policy':{},'sourceEvidence':{'source':r.get('source'),'peer':ev.get('peer'),'attribution':ev.get('attribution') or 'CLIENT_CONNECTION'}}
  if ev.get('secretFindings'):e['secretFindings']=ev.get('secretFindings')
  if op=='TOOL_DEFINITIONS':
   e['toolDefinitions']=ev.get('toolDefinitions') or []
   e['toolBaseline']=ev.get('toolBaseline') or {}
   if not e['toolBaseline']:
    for item in self.agents:
     if item['id']==agent and item.get('toolDefinitionBaseline'):
      e['toolBaseline']=item['toolDefinitionBaseline'];break
  for item in self.agents:
   if item['id']==agent:self._decorate_agent(e,item);break
  self.last_event=time.time();self.last_semantic=self.last_event;self.stats['normalized']+=1;self.stats['semantic']+=1;return e
 def heartbeat(self):
  def service(name):
   return service_state(name)
  audit={}
  try:audit=dict(line.split(None,1) for line in subprocess.check_output(['auditctl','-s'],text=True,timeout=2,stderr=subprocess.DEVNULL).splitlines() if len(line.split(None,1))==2)
  except Exception:pass
  host=service('agentreins-host-stream');aud=service('agentreins-audit-bridge');gateway=service('agentreins-semantic-gateway');active=host=='active' and aud=='active'
  semantic_age=None if self.last_semantic is None else time.time()-self.last_semantic
  model,tool=layer_status(gateway=='active',bool(self.agents),semantic_age)
  return {'host':socket.gethostname(),'version':VERSION,'bootId':self.boot,'layers':{'process':'active' if active else 'unavailable','network':'active' if aud=='active' else 'unavailable','file':'watched_paths_only' if aud=='active' else 'unavailable','model':model,'tool':tool},'auditLost':int(audit['lost']) if audit.get('lost','').isdigit() else None,'drop':(int(audit['lost'])+sum(self.stats[k] for k in ('spoolDropped','expiredDropped','oversizeDropped','parseErrors','staleSkipped','rejectedEvents','rotationLost'))) if audit.get('lost','').isdigit() else None,'auditBacklog':audit.get('backlog'),'counters':dict(self.stats),'lastEvent':self.last_event,'lastSemantic':self.last_semantic,'workloads':self.containers,'agentRoutes':[a['id'] for a in self.agents],'fileWatchScope':self.config.get('fileWatchScope',[]),'fileWatchCategories':self.config.get('fileWatchCategories',{}),'persistWatchCategories':self.config.get('persistWatchCategories',{}),'unwatchedCategories':self.config.get('unwatchedCategories',[]),'serviceState':{'host':host,'audit':aud,'gateway':gateway},'policyStatus':{'S05':'per-workload; disabled if no allowedNetworks configured','S02':'requires untrusted segment plus exact destination match','S03':'semantic stage then host confirmation','S08':'alert only; no restore','S13':'tool args; category and digest only','S16':'IP literals outside allowedNetworks; empty allowlist still matches metadata and loopback','S17':'60s http summary; per client','S19':'login path 401/403 burst','S23':'tool definition hash after the later of 10 requests and 10 minutes; pinned hash wins; disappearance is info'},'limitations':['同一 Dify 实例的多个应用无法按容器拆开','Dify bridge 只作旁路，不触发 S02/S03','volume 与 bind mount 不在容器 upperdir','内核不阻断','入站 HTTP 只接收 60 秒汇总，原始行留在本机','入站 Web 与模型链路只按 agent 和时间窗并排，关联为 inferred','工具定义只在请求带 tools 或 functions 时比较；省略该字段不算工具消失']}
class LogPump:
 """At-least-once log delivery: bounded pending batch, cursor advances only on ACK."""
 def __init__(self,client,adapter,config):
  self.client=client;self.adapter=adapter;self.log=Path(config.get('log','/var/log/agentreins/host.jsonl'));self.cursor=Path(config.get('cursor','/var/lib/agentreins-runtime/cursor.json'));self.cursor.parent.mkdir(parents=True,exist_ok=True);self.handle=None;self.inode=None;self.pending=[];self.end=0;self.start=0;self.max_batch=100
  try:
   self.saved=json.loads(self.cursor.read_text());self.adapter.stats.update(self.saved.get('counters',{}))
  except (OSError,ValueError):self.saved={}
 def checkpoint(self):
  tmp=self.cursor.with_suffix('.new');tmp.write_text(json.dumps({'inode':self.inode,'offset':self.end,'counters':dict(self.adapter.stats)}));tmp.replace(self.cursor)
 def open_log(self):
  st=self.log.stat()
  if self.handle is None:
   self.handle=self.log.open();self.inode=st.st_ino
   if self.saved.get('inode')==self.inode and self.saved.get('offset',0)<=st.st_size:self.handle.seek(self.saved['offset'])
   elif self.saved:
    self.adapter.stats['rotationLost']+=1 # unknown interval; do not invent exact count
   self.end=self.handle.tell()
  elif self.inode!=st.st_ino and not self.pending and self.handle.tell()==os.fstat(self.handle.fileno()).st_size:
   self.handle.close();self.handle=self.log.open();self.inode=st.st_ino;self.end=0
  elif self.inode==st.st_ino and self.handle.tell()>st.st_size:
   self.adapter.stats['rotationLost']+=1;self.handle.seek(0);self.end=0
 def step(self):
  self.open_log()
  if not self.pending:
   self.start=self.handle.tell()
   for _ in range(5000):
    offset=self.handle.tell();line=self.handle.readline(1024*1024)
    if not line:break
    if not line.endswith('\n'):
     if len(line)>=1024*1024:
      while line and not line.endswith('\n'):line=self.handle.readline(1024*1024)
      self.adapter.stats['oversizeDropped']+=1;continue
     self.handle.seek(offset);break
    try:e=self.adapter.normalize(json.loads(line))
    except (ValueError,TypeError,KeyError):self.adapter.stats['parseErrors']+=1;continue
    if e:self.pending.append(e)
    if len(self.pending)>=self.max_batch:break # backpressure: never overwrite pending events
   self.end=self.handle.tell()
  self.adapter.stats['pending']=len(self.pending)
  self.adapter.stats['logBacklogBytes']=max(0,self.log.stat().st_size-self.end)
  if self.pending:
   try:
    response=self.client.call('ingest',{'events':self.pending}) or {}
    self.adapter.stats['rejectedEvents']+=len(response.get('rejected',[]));self.adapter.stats['delivered']+=len(self.pending)-len(response.get('rejected',[]));self.pending=[];self.adapter.stats['pending']=0;self.adapter.stats['backpressure']=0;self.checkpoint();return True
   except Exception:
    self.adapter.stats['sendErrors']+=1;self.adapter.stats['backpressure']=1;return False
  self.checkpoint();return False
 def close(self):
  if self.handle:self.handle.close()
def main():
 client=Client();adapter=Adapter(client.config);pump=LogPump(client,adapter,client.config);stop=threading.Event()
 def heartbeat_loop():
  while not stop.is_set():
   try:client.call('heartbeat',adapter.heartbeat())
   except Exception:adapter.stats['heartbeatErrors']+=1
   stop.wait(10)
 threading.Thread(target=heartbeat_loop,daemon=True).start()
 while True:
  try:progress=pump.step()
  except OSError:adapter.stats['logErrors']+=1;progress=False
  time.sleep(.01 if progress else .5)
if __name__=='__main__':main()
