"""Bounded persistent detection and approvals. No commands are executed here."""
import contextlib,copy,hashlib,hmac,ipaddress,json,re,sqlite3,time,uuid,fnmatch,shlex
from pathlib import Path
try:
 from runtime.redact import redact_text
except ImportError:
 from redact import redact_text

RULES=[
 {'id':'S01','version':'1.0','name':'敏感凭据路径访问','severity':'high','sources':['file'],'condition':'已登记工作负载成功以读取权限打开敏感路径，或尝试访问被拒绝','falsePositive':'部署与密钥轮换可能合法；按工作负载、路径、动作和期限加白','mode':'alert','limitation':'读取权限打开不证明读取了文件正文；不采集凭据内容'},
 {'id':'S02','version':'1.0','name':'工具后的非白名单外联','severity':'medium','sources':['tool','network'],'condition':'同一链路中不受信输入后的高风险工具调用，按目的实体关联到允许范围外的连接','falsePositive':'模型 API、DNS、依赖安装及代理需要写入 allowedNetworks','mode':'alert','limitation':'必须先有不受信片段，并且连接目的与工具参数实体一致；只有时间邻近不触发；不自动阻断'},
 {'id':'S03','version':'1.0','name':'可疑模型到命令执行链','severity':'medium','sources':['model','tool','process','file','network'],'condition':'不受信输入之后出现高风险工具调用；主机侧按同一 agent 的参数实体确认落地','falsePositive':'用户直接指令或模型自行提议的授权内操作不应命中；这不证明提示注入','mode':'alert','limitation':'不解析提示词语义；语义段先告警，主机段只在精确实体匹配后升级同一条告警；不自动阻断'},
 {'id':'S04','version':'1.0','name':'下载文件后执行','severity':'high','sources':['process','network','file'],'condition':'同一工作负载内下载命令指定的落地路径，被后续进程执行','falsePositive':'合法安装/更新也会命中，必须审阅来源与任务','mode':'alert','limitation':'shell 启动本身不触发；下载/执行按路径与工作负载形成 candidate'},
 {'id':'S05','version':'1.0','name':'授权范围外连接','severity':'high','sources':['network'],'condition':'配置非空网络授权范围的工作负载连接未获允许的目的 IP/端口','falsePositive':'需包含 DNS、模型服务、CDN 与代理实际路径','mode':'alert','limitation':'未配置时不启用；连接尝试不等于已外传数据'},
 {'id':'P01','version':'1.0','name':'已接入工具执行前审批','severity':'medium','sources':['tool'],'condition':'受保护执行器即将执行一个具体调用','falsePositive':'审批请求不是危险行为已发生；这是显式工具保护策略','mode':'require_approval','limitation':'仅保护已接入的 REA analyze 与固定范围实验执行器，不覆盖任意 Dify 工具'},
 {'id':'S08','version':'1.0','name':'敏感文件被修改','severity':'high','sources':['file'],'condition':'已登记工作负载写入敏感凭据或持久化路径','falsePositive':'密钥轮换、软件包安装和用户 shell 配置更新可能合法','mode':'alert','limitation':'只告警，不阻断、不回滚；敏感文件只保留哈希和大小，不保留正文；volume 与 bind mount 不在容器 upperdir 中'}]
for _rule in RULES:
 if _rule['id']=='P01':
  continue
 _rule['version']='1.2' if _rule['id'] in ('S02','S03','S08') else '1.1'
TERMINAL={'denied','expired','cancelled','succeeded','failed','interrupted'}
def compact(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'))
def digest(v):return hashlib.sha256(compact(v).encode()).hexdigest()
def clean(v):
 if isinstance(v,dict):return {str(k):('[REDACTED]' if re.search(r'(?i)^(authorization|api[_-]?key|password|token|secret|cookie)$',str(k)) else clean(x)) for k,x in v.items()}
 if isinstance(v,list):return [clean(x) for x in v[:100]]
 if isinstance(v,str):return redact_text(v)
 return v
class Conflict(ValueError):pass
class Store:
 def __init__(self,path,clock=time.time,config=None):
  self.config=config or {};self.last_ingest={};self.path=str(path);self.clock=clock;Path(path).parent.mkdir(parents=True,exist_ok=True)
  with self.db() as c:
   c.executescript('''PRAGMA journal_mode=WAL; PRAGMA auto_vacuum=INCREMENTAL;
CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, time REAL, source TEXT, workload TEXT, kind TEXT, payload TEXT);
CREATE INDEX IF NOT EXISTS ev_lookup ON events(workload,kind,time);
CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY, time REAL, rule TEXT, severity TEXT, status TEXT, fingerprint TEXT UNIQUE, payload TEXT);
CREATE INDEX IF NOT EXISTS alert_lookup ON alerts(time);
CREATE TABLE IF NOT EXISTS gates(id TEXT PRIMARY KEY,source TEXT,hash TEXT,request_key TEXT UNIQUE,status TEXT,deadline REAL,payload TEXT);
CREATE TABLE IF NOT EXISTS reviews(id TEXT PRIMARY KEY,time REAL,alert_id TEXT,payload TEXT);
CREATE TABLE IF NOT EXISTS sources(id TEXT PRIMARY KEY,seen REAL,payload TEXT);
CREATE TABLE IF NOT EXISTS gaps(source TEXT,start REAL,end REAL,PRIMARY KEY(source,start));
CREATE TABLE IF NOT EXISTS exceptions(id TEXT PRIMARY KEY,expires REAL,payload TEXT);
CREATE TABLE IF NOT EXISTS intel(id TEXT PRIMARY KEY,time REAL,payload TEXT);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE IF NOT EXISTS coverage_losses(source TEXT,time REAL,audit INTEGER,sensor INTEGER);
CREATE INDEX IF NOT EXISTS coverage_loss_time ON coverage_losses(source,time);
''')
   c.execute('PRAGMA max_page_count=65536')
 @contextlib.contextmanager
 def db(self,write=True):
  c=sqlite3.connect(self.path,timeout=15);c.row_factory=sqlite3.Row
  try:
   c.execute('PRAGMA busy_timeout=15000')
   if write:c.execute('PRAGMA max_page_count=65536');c.execute('BEGIN IMMEDIATE')
   else:c.execute('PRAGMA query_only=ON');c.execute('BEGIN')
   yield c;c.commit()
  except BaseException:c.rollback();raise
  finally:c.close()
 def heartbeat(self,source,body):
  now=self.clock();body=clean(body);body.update(source=source,receivedAt=now)
  body['serverRejected']=self.last_ingest.get(source,{}).get('rejectedTotal',0)
  with self.db() as c:
   prev=c.execute('SELECT seen,payload FROM sources WHERE id=?',(source,)).fetchone()
   old=json.loads(prev['payload']) if prev else {};oldloss,olda=loss_totals(old);newloss,newa=loss_totals(body)
   sensor_delta=max(0,newloss-oldloss) if prev and old.get('bootId')==body.get('bootId') else newloss
   audit_delta=max(0,(newa or 0)-(olda or 0)) if prev and old.get('bootId')==body.get('bootId') else (newa or 0)
   if sensor_delta or audit_delta:c.execute('INSERT INTO coverage_losses VALUES(?,?,?,?)',(source,now,audit_delta,sensor_delta))
   c.execute('DELETE FROM coverage_losses WHERE time<?',(now-86400,))
   if prev and now-prev['seen']>35:c.execute('INSERT OR REPLACE INTO gaps VALUES(?,?,?)',(source,prev['seen']+35,now))
   c.execute('INSERT OR REPLACE INTO sources VALUES(?,?,?)',(source,now,compact(body)))
 def coverage(self,c,source):
  row=c.execute('SELECT * FROM sources WHERE id=?',(source,)).fetchone();now=self.clock()
  if not row:return {'source':source,'state':'unknown','layers':{},'limitations':['未收到独立心跳']}
  body=json.loads(row['payload']);fresh=now-row['seen']<35;gaps=[dict(x) for x in c.execute('SELECT start,end FROM gaps WHERE source=? ORDER BY start DESC LIMIT 20',(source,))]
  if not fresh:gaps.insert(0,{'start':row['seen']+35,'end':None})
  counters=body.get('counters') or {};loss,audit=loss_totals(body)
  window=max(60,min(3600,int(self.config.get('lossWindowSeconds',900))))
  recent=c.execute('SELECT coalesce(sum(audit),0),coalesce(sum(sensor),0) FROM coverage_losses WHERE source=? AND time>?',(source,now-window)).fetchone()
  recent_audit,recent_sensor=recent[0],recent[1];degraded=bool(recent_audit or recent_sensor or counters.get('backpressure',0))
  if (body.get('serviceState') or {}).get('audit') in ('inactive','failed'):degraded=True
  layers=self._overlay_layers(c,source,body.get('layers'))
  return {**body,'layers':layers,'state':('degraded' if degraded else 'online') if fresh else 'offline','auditLost':audit,'sensorLoss':loss,'degraded':degraded,'lossWindowSeconds':window,'recentLoss':{'audit':recent_audit if audit is not None else None,'sensor':recent_sensor,'total':recent_audit+recent_sensor if audit is not None else None},'historicalLoss':{'audit':audit,'sensor':loss},'lossWarning':'近期检测窗口有丢失、拒绝或背压' if degraded else None,'ageSeconds':round(now-row['seen'],1),'gaps':gaps,'drop':(int(audit)+loss) if audit is not None else None,'limitations':['近期未增长不代表历史没有缺口；累计损失单独展示','工作目录来自 audit 或执行时 /proc；短命进程可能无法补采','S02/S03 主机段只在同一 agent 的参数实体对齐后升级；Dify bridge 不是触发源']}
 def _overlay_layers(self,c,source,layers):
  layers=dict(layers or {});now=self.clock()
  rows=c.execute("SELECT payload FROM alerts WHERE rule IN ('S02','S03') AND time>?",(now-86400,)).fetchall()
  for row in rows:
   alert=json.loads(row[0])
   seen=float(alert.get('hostConfirmedAt') or alert.get('lastSeen') or 0)
   if alert.get('source')==source and alert.get('phase')=='host_confirmed' and seen>=now-300:
    layers['tool']='host_linked';break
  return layers

 def source_fresh(self,c,source):
  r=c.execute('SELECT seen FROM sources WHERE id=?',(source,)).fetchone();return r and self.clock()-r['seen']<35
 def _suppressed(self,c,e,rule):
  for r in c.execute('SELECT payload FROM exceptions WHERE expires>?',(self.clock(),)):
   x=json.loads(r[0]);scope=x['scope']
   if x.get('rule')==rule and all(str(e.get(k,''))==str(v) for k,v in scope.items()):return True
  return False
 def _alert(self,c,rule,e,refs,title,relation='explicit',basis='工作负载身份与直接主机事件',gate_id=None,confidence=None):
  spec=next(r for r in RULES if r['id']==rule)
  if self._suppressed(c,e,rule):return None
  now=self.clock()
  if not gate_id:
   aggregate=digest([rule,e['source'],e['workload'],e.get('destination'),e.get('port'),e.get('path'),e.get('command') if rule in ('S03','S04') else None])
   prior=c.execute('SELECT id,payload FROM alerts WHERE rule=? AND time>? ORDER BY time DESC LIMIT 200',(rule,now-300)).fetchall()
   for old in prior:
    existing=json.loads(old['payload'])
    if existing.get('aggregateKey')==aggregate and e['id'] not in existing.get('sampleEventIds',[]):
     existing['count']=existing.get('count',1)+1;existing['lastSeen']=max(existing.get('lastSeen',e['time']),e['time']);existing['revision']+=1;existing['sampleEventIds']=(existing.get('sampleEventIds',[])+[e['id']])[-1000:]
     if len(existing['evidence'])<6:existing['evidence'].append(e)
     if e.get('sha256Before') or e.get('sha256After'):
      digest_info=dict(existing.get('fileDigest') or {})
      if e.get('sha256Before'):digest_info['before']=e.get('sha256Before')
      if e.get('sha256After'):digest_info['after']=e.get('sha256After')
      if e.get('size') is not None:digest_info['size']=e.get('size')
      existing['fileDigest']=digest_info
     c.execute('UPDATE alerts SET payload=? WHERE id=?',(compact(existing),old['id']));return old['id']
    if existing.get('aggregateKey')==aggregate and e['id'] in existing.get('sampleEventIds',[]):return old['id']
  else:aggregate=None
  key=digest([rule,e['source'],e['id'],gate_id]);aid='al_'+key[:24];coverage=self.coverage(c,e['source'])
  rel={'strength':relation,'basis':basis}
  if confidence or relation=='explicit':rel['confidence']=confidence or 'observed'
  value={'id':aid,'aggregateKey':aggregate,'count':1,'firstSeen':e['time'],'lastSeen':e['time'],'sampleEventIds':[e['id']],'createdAt':self.clock(),'rule':rule,'ruleVersion':spec['version'],'severity':spec['severity'],'title':title,'status':'pending' if gate_id else 'open','revision':1,'source':e['source'],'workload':e['workload'],'runId':e.get('runId'),'agentId':e.get('agentId'),'sessionId':e.get('sessionId'),'gateId':gate_id,'relation':rel,'evidence':refs,'coverageAtDetection':coverage,'limitations':[spec['limitation']],'ruleSnapshot':spec}
  if e.get('sha256Before') or e.get('sha256After'):value['fileDigest']={'before':e.get('sha256Before'),'after':e.get('sha256After'),'size':e.get('size')}
  c.execute('INSERT OR IGNORE INTO alerts VALUES(?,?,?,?,?,?,?)',(aid,value['createdAt'],rule,spec['severity'],value['status'],key,compact(value)));return aid
 def ingest(self,source,items):
  if not isinstance(items,list):raise ValueError('events 必须为数组')
  if len(items)>100:raise ValueError('最多 100 条事件')
  now=self.clock();added=0
  with self.db() as c:
   rejected=[]
   valid=[]
   for index,item in enumerate(items):
    try:
     if not isinstance(item,dict):raise ValueError('事件必须为对象')
     e=clean(item)
     if e.get('source') not in (None,source):raise ValueError('来源不匹配')
     if not e.get('id') or len(str(e['id']))>160 or e.get('kind') not in ('process','file','network','tool','model'):raise ValueError('事件字段无效')
     if not e.get('workload') or not e.get('identity',{}).get('basis'):raise ValueError('必须登记工作负载身份及依据')
     e['source']=source;e['receivedAt']=now;e['time']=float(e.get('time',now))
     if abs(e['time']-now)>72*3600:raise ValueError('超出 72 小时事件留存窗口')
     if e.get('kind') in ('model','tool'):
      try:from runtime.semantic_extract import bound_event
      except ImportError:from semantic_extract import bound_event
      e=bound_event(e)
     valid.append(e)
    except (ValueError,TypeError,AttributeError):rejected.append({'index':index,'reason':'事件字段、身份或时间无效'})
   for e in sorted(valid,key=lambda x:x['time']):
    if c.execute('INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?)',(e['id'],e['time'],source,e['workload'],e['kind'],compact(e))).rowcount:
     added+=1;self.detect(c,e)
   previous=self.last_ingest.get(source,{}).get('rejectedTotal',0)
   self.last_ingest[source]={'rejected':rejected,'rejectedTotal':previous+len(rejected),'acknowledged':len(items)}
   # Late audit records can arrive after their corresponding execution.
   for item in valid:
    if item.get('downloadPath'):
     for rr in c.execute('SELECT payload FROM events WHERE source=? AND workload=? AND kind=? AND time BETWEEN ? AND ? ORDER BY time LIMIT 100',(source,item['workload'],'process',float(item.get('time',now)),float(item.get('time',now))+120)).fetchall():self.detect(c,json.loads(rr[0]))
    self._recompute(c,item)
   self.prune(c)
  return added
 def detect(self,c,e):
  w=e['workload'];kind=e['kind'];now=e['time'];row=[e]
  recent=lambda kinds:[json.loads(x[0]) for x in c.execute('SELECT payload FROM events WHERE source=? AND workload=? AND time BETWEEN ? AND ? AND kind IN ('+','.join('?' for _ in kinds)+') ORDER BY time DESC LIMIT 100',(e['source'],w,now-120,now,*kinds))]
  path=e.get('path','');cmd=e.get('command','');policy=e.get('policy') or {};success=e.get('result')
  if kind=='file' and e.get('pid',0)>0 and e.get('access') in ('read_open','read') and sensitive_path(path,self.config.get('sensitivePaths')):
   self._alert(c,'S01',e,row,('敏感路径访问被拒绝：' if success=='denied' else '敏感路径读取权限访问：')+path)
  if kind=='network' and e.get('destination'):
   allowed=policy.get('allowedNetworks');enabled=isinstance(allowed,list) and len(allowed)>0
   if enabled and not network_allowed(e['destination'],e.get('port'),allowed):
    self._alert(c,'S05',e,row,'授权范围外连接尝试：'+e['destination']+':'+str(e.get('port','')))
  if kind=='file' and e.get('pid',0)>0 and str(e.get('access')) in ('write','metadata_or_write','write_open') and (sensitive_path(path,self.config.get('sensitivePaths')) or persistence_path(path,self.config.get('persistencePaths'))):
   self._alert(c,'S08',e,row,('敏感或持久化路径写入被拒绝：' if success=='denied' else '敏感或持久化路径被修改：')+path,'explicit','audit 写入事件带有进程与已登记工作负载；只告警，不回滚')
  if kind=='process' and e.get('result') in ('success','attempt'):
   # Joining requires a concrete downloaded output path, not just starting a shell.
   for d in recent(['process']):
    if d['id']==e['id']:continue
    output=d.get('downloadPath')
    if output and not e.get('downloadPath') and output in e.get('execPaths',[]) and d.get('destination') and d.get('result') in ('success','attempt') and (not e.get('runId') or e.get('runId')==d.get('runId')):
     self._alert(c,'S04',e,[d,e],'下载文件后执行：'+output,'candidate','相同工作负载、下载输出路径与执行参数匹配');break
   if risky_command(cmd):
    for m in recent(['model']):
     if e.get('runId') and e.get('runId')==m.get('runId') and m.get('text') is not None and 'untrustedSegments' not in m and cmd and canonical_command(cmd) in canonical_command(m.get('text','')):
      self._alert(c,'S03',e,[m,e],'可疑模型到命令执行链','candidate','任务身份、命令文本与时间窗；不证明提示注入');break
  try:from runtime.chain_detect import observe
  except ImportError:from chain_detect import observe
  observe(self,c,e)
 def _recompute(self,c,item):
  if item.get('kind') not in ('model','tool','process','network','file'):return
  seen=set()
  def run(other):
   if not other.get('id') or other.get('id') in seen or other.get('id')==item.get('id'):return
   seen.add(other.get('id'))
   if item.get('agentId') and other.get('agentId') and item['agentId']!=other['agentId']:return
   if not item.get('agentId') and not item.get('chainId') and other.get('workload')!=item.get('workload'):return
   self.detect(c,other)
  start,end=float(item['time'])-120,float(item['time'])+120
  for rr in c.execute('SELECT payload FROM events WHERE source=? AND time>=? AND time<=? ORDER BY time LIMIT 200',(item['source'],start,end)).fetchall():
   run(json.loads(rr[0]))
  chain=item.get('chainId')
  if not chain:return
  lo,hi=float(item['time'])-3600,float(item['time'])+120
  for rr in c.execute('SELECT payload FROM events WHERE source=? AND time>=? AND time<=? ORDER BY time LIMIT 200',(item['source'],lo,hi)).fetchall():
   other=json.loads(rr[0])
   if other.get('chainId')==chain and other.get('operation')=='TOOL_CALL':run(other)
 def open_chain_alert(self,c,rule,e,refs,title,phase,confidence,basis,links,chain_id=None,tool_call_id=None,agent_event=None):
  spec=next(r for r in RULES if r['id']==rule)
  anchor=agent_event or e
  chain_id=chain_id or anchor.get('chainId') or e.get('chainId')
  tool_call_id=anchor.get('toolCallId') if tool_call_id is None else tool_call_id
  if not chain_id or self._suppressed(c,e,rule):return None
  found=self._find_chain_alert(c,rule,e['source'],chain_id,tool_call_id)
  if found:return found
  key=digest(['chain',rule,e['source'],chain_id,tool_call_id or e.get('id')]);aid='al_'+key[:24];coverage=self.coverage(c,e['source'])
  value={'id':aid,'aggregateKey':key,'count':1,'firstSeen':min(x.get('time',e['time']) for x in refs),'lastSeen':e['time'],'sampleEventIds':[x.get('id') for x in refs if x.get('id')],'createdAt':self.clock(),'rule':rule,'ruleVersion':spec['version'],'severity':spec['severity'],'title':title,'status':'open','revision':1,'source':e['source'],'workload':e.get('workload'),'runId':chain_id,'chainId':chain_id,'toolCallId':tool_call_id,'agentId':anchor.get('agentId') or e.get('agentId'),'sessionId':e.get('sessionId') or anchor.get('sessionId'),'phase':phase,'gateId':None,'relation':{'strength':'candidate','confidence':confidence,'basis':basis,'links':links},'evidence':refs[:6],'coverageAtDetection':coverage,'limitations':[spec['limitation']],'ruleSnapshot':spec}
  c.execute('INSERT OR IGNORE INTO alerts VALUES(?,?,?,?,?,?,?)',(aid,value['createdAt'],rule,spec['severity'],'open',key,compact(value)));return aid
 def upgrade_chain_alert(self,c,aid,host,link,basis):
  row=c.execute('SELECT payload FROM alerts WHERE id=?',(aid,)).fetchone()
  if not row:return None
  alert=json.loads(row['payload']);ids=list(alert.get('sampleEventIds') or []);changed=False
  copy=dict(host);copy.update(chainId=alert.get('chainId'),toolCallId=alert.get('toolCallId'),linkConfidence='correlated',linkBasis=link.get('basis'))
  if host.get('id') not in ids:
   alert['sampleEventIds']=(ids+[host.get('id')])[-1000:];alert['count']=alert.get('count',1)+1;alert['lastSeen']=max(alert.get('lastSeen',0),host.get('time',0))
   if len(alert.get('evidence') or [])<6:alert.setdefault('evidence',[]).append(copy)
   alert.setdefault('relation',{}).setdefault('links',[]).append(link);changed=True
  if alert.get('phase')!='host_confirmed':
   alert['phase']='host_confirmed';alert['hostConfirmedAt']=host.get('time');alert['relation']['confidence']='correlated';alert['relation']['basis']=basis;changed=True
   if alert.get('sessionId') is None and host.get('sessionId'):alert['sessionId']=host.get('sessionId')
  if not changed:return aid
  alert['revision']=alert.get('revision',1)+1;c.execute('UPDATE alerts SET payload=? WHERE id=?',(compact(alert),aid));return aid
 def _find_chain_alert(self,c,rule,source,chain_id,tool_call_id):
  if not chain_id:return None
  for row in c.execute('SELECT id,payload FROM alerts WHERE rule=? AND time>? ORDER BY time DESC LIMIT 300',(rule,self.clock()-7*86400)).fetchall():
   payload=json.loads(row['payload'])
   if payload.get('source')!=source or payload.get('chainId')!=chain_id:continue
   if tool_call_id and payload.get('toolCallId') and payload.get('toolCallId')!=tool_call_id:continue
   return row['id']
  return None
 def prune(self,c):
  now=self.clock();limit=max(1000,min(2000000,int(self.config.get('maxEvents',20000))))
  c.execute('DELETE FROM events WHERE time<?',(now-72*3600,));c.execute('DELETE FROM events WHERE rowid IN (SELECT rowid FROM events ORDER BY time DESC LIMIT -1 OFFSET ?)',(limit,))
  per=self.config.get('maxEventsPerSource')
  if per:
   per=max(100,min(2000000,int(per)))
   for (source,) in c.execute('SELECT DISTINCT source FROM events').fetchall():
    c.execute('DELETE FROM events WHERE source=? AND rowid IN (SELECT rowid FROM events WHERE source=? ORDER BY time DESC LIMIT -1 OFFSET ?)',(source,source,per))
  c.execute('DELETE FROM reviews WHERE time<?',(now-30*86400,));c.execute('DELETE FROM alerts WHERE time<? AND status!=?',(now-30*86400,'pending'));c.execute('DELETE FROM alerts WHERE rowid IN (SELECT rowid FROM alerts WHERE status!=? ORDER BY time DESC LIMIT -1 OFFSET 2000)',('pending',))
  c.execute('DELETE FROM exceptions WHERE expires<?',(now,));c.execute('DELETE FROM gaps WHERE start<?',(now-30*86400,))
  # Decisions survive restart; executing grants are never replayed automatically.
  c.execute('DELETE FROM gates WHERE deadline<? AND status IN (?,?,?,?,?,?)',(now-30*86400,*sorted(TERMINAL)))
 def expire(self,c):
  for r in c.execute('SELECT * FROM gates WHERE status IN (?,?,?)',('pending','approved','executing')).fetchall():
   g=json.loads(r['payload']);status=None
   if g['status'] in ('pending','approved') and g['deadline']<self.clock():status='expired'
   elif g['status']=='executing' and self.clock()-g.get('claimedAt',0)>180:status='interrupted'
   if status:
    g['status']=status;self._save_gate(c,g)
    self._gate_alert_status(c,g,status)
 def _save_gate(self,c,g):c.execute('UPDATE gates SET status=?,payload=? WHERE id=?',(g['status'],compact(g),g['id']))
 def _gate_alert_status(self,c,g,status):
  r=c.execute('SELECT * FROM alerts WHERE id=?',(g['alertId'],)).fetchone()
  if r:
   a=json.loads(r['payload']);a['status']=status;a['revision']+=1;c.execute('UPDATE alerts SET status=?,payload=? WHERE id=?',(status,compact(a),a['id']))
 def gate_create(self,source,body):
  for k in ('requestKey','workload','tool','arguments','runId'):
   if k not in body:raise ValueError('缺少 '+k)
  binding={k:body[k] for k in ('tool','arguments','runId','workload')}
  if clean(binding)!=binding:raise ValueError('参数含需隐藏的凭据字段，禁止盲批；请用预配置凭据引用')
  hash_=digest(binding);now=self.clock()
  with self.db() as c:
   self.expire(c)
   if body['tool'] not in ('rea_analyze_frontend','runtime_lab_command'):raise ValueError('此工具未接入执行审批')
   r=c.execute('SELECT payload FROM gates WHERE request_key=?',(source+':'+str(body['requestKey']),)).fetchone()
   if r:
    g=json.loads(r[0])
    if g['hash']!=hash_:raise Conflict('同一请求参数已改变，必须创建新审批')
    return g
   if not self.source_fresh(c,source):raise Conflict('来源心跳过期，拒绝创建执行许可')
   if c.execute('SELECT count(*) FROM gates WHERE source=? AND status IN (?,?)',(source,'pending','approved')).fetchone()[0]>=30:raise Conflict('待审批队列已满')
   gid='gate_'+uuid.uuid4().hex;event={'id':gid+':intent','source':source,'workload':body['workload'],'kind':'tool','time':now,'runId':body['runId'],'operation':'EXECUTION_INTENT','tool':body['tool'],'arguments':clean(body['arguments']),'bindingHash':hash_,'identity':{'basis':'执行器在实际调用边界申请；不是已执行证据'}}
   aid=self._alert(c,'P01',event,[event],'工具执行前审批：'+str(body['tool']),'explicit','已接入执行器的具体调用绑定；并非下载或危险行为已发生',gid)
   g={'id':gid,'source':source,'createdAt':now,'deadline':now+min(120,max(10,int(body.get('timeout',90)))),'status':'pending','binding':clean(binding),'hash':hash_,'alertId':aid,'requestKey':body['requestKey']};c.execute('INSERT INTO gates VALUES(?,?,?,?,?,?,?)',(gid,source,hash_,source+':'+str(body['requestKey']),'pending',g['deadline'],compact(g)));return g
 def gate_get(self,source,gid):
  with self.db() as c:
   self.expire(c);r=c.execute('SELECT payload FROM gates WHERE id=? AND source=?',(gid,source)).fetchone()
   if not r:raise KeyError('审批不存在')
   return json.loads(r[0])
 def claim(self,source,gid,hash_):
  with self.db() as c:
   self.expire(c);r=c.execute('SELECT payload FROM gates WHERE id=? AND source=?',(gid,source)).fetchone()
   if not r:raise KeyError('审批不存在')
   g=json.loads(r[0])
   if not hmac.compare_digest(g['hash'],hash_):raise Conflict('调用参数不匹配')
   if g['status']!='approved':raise Conflict('不是可领取的审批；不能重复执行')
   if not self.source_fresh(c,source):raise Conflict('来源离线，拒绝执行')
   g.update(status='executing',claimedAt=self.clock());self._save_gate(c,g);self._gate_alert_status(c,g,'executing');return g
 def complete(self,source,gid,body):
  with self.db() as c:
   r=c.execute('SELECT payload FROM gates WHERE id=? AND source=?',(gid,source)).fetchone()
   if not r:raise KeyError('审批不存在')
   g=json.loads(r[0])
   if g['status']!='executing':raise Conflict('没有执行中的单次许可')
   g.update(status='succeeded' if body.get('exitCode')==0 else 'failed',execution=clean(body),completedAt=self.clock());self._save_gate(c,g);self._gate_alert_status(c,g,g['status']);return g
 def review(self,aid,body,actor):
  action=body.get('action');reason=body.get('reason','').strip()
  if action not in ('allow','deny','escalate','whitelist','dismiss','cancel') or not 3<=len(reason)<=1000:raise ValueError('请提供有效动作和至少三个字符的理由')
  with self.db() as c:
   self.expire(c)
   r=c.execute('SELECT payload FROM alerts WHERE id=?',(aid,)).fetchone()
   if not r:raise KeyError('告警不存在')
   a=json.loads(r[0]);revision=a['revision']
   if body.get('revision')!=revision:raise Conflict('证据或状态已更新，请刷新后重审')
   gate=None
   if a.get('gateId'):
    gate=json.loads(c.execute('SELECT payload FROM gates WHERE id=?',(a['gateId'],)).fetchone()[0])
   if action in ('allow','deny','cancel'):
    if not gate:raise Conflict('此告警为事后观测，无法放行或撤销已经发生的操作')
    if gate['status']!='pending':raise Conflict('审批已决定或执行中，不能重复处置')
    if action=='allow' and not self.source_fresh(c,gate['source']):raise Conflict('执行器离线，不能放行')
    gate['status']={'allow':'approved','deny':'denied','cancel':'cancelled'}[action];self._save_gate(c,gate);a['status']=gate['status']
   elif action=='dismiss':
    if gate:raise Conflict('审批请求请使用放行或阻断')
    a['status']='dismissed'
   elif action=='escalate':a['status']='pending' if gate and gate['status']=='pending' else 'escalated'
   elif action=='whitelist':
    if gate:raise Conflict('执行审批不支持绕过；请另行审阅告警白名单')
    if a['rule'] not in ('S01','S05'):raise Conflict('此规则尚不支持精确加白')
    e=a['evidence'][-1];scope={'source':e['source'],'workload':e['workload']}
    if a['rule']=='S01':scope.update(path=e['path'],access=e['access'])
    else:scope.update(destination=e['destination'],port=e.get('port'))
    x={'id':'ex_'+uuid.uuid4().hex,'scope':scope,'rule':a['rule'],'actor':actor,'reason':reason,'expires':self.clock()+3600};c.execute('INSERT INTO exceptions VALUES(?,?,?)',(x['id'],x['expires'],compact(x)));a['status']='whitelisted'
   a['revision']+=1;c.execute('UPDATE alerts SET status=?,payload=? WHERE id=?',(a['status'],compact(a),aid))
   v={'id':'rev_'+uuid.uuid4().hex,'time':self.clock(),'alertId':aid,'actor':actor,'action':action,'reason':reason,'snapshotRevision':revision,'evidenceHash':digest(a['evidence']),'result':a['status']};c.execute('INSERT INTO reviews VALUES(?,?,?,?)',(v['id'],v['time'],aid,compact(v)));return v
 def detail(self,aid):
  with self.db(write=False) as c:
   r=c.execute('SELECT payload FROM alerts WHERE id=?',(aid,)).fetchone()
   if not r:raise KeyError('告警不存在')
   a=json.loads(r[0]);a['coverageNow']=self.coverage(c,a['source']);a['reviews']=[json.loads(x[0]) for x in c.execute('SELECT payload FROM reviews WHERE alert_id=? ORDER BY time',(aid,))]
   if a.get('gateId'):a['gate']=json.loads(c.execute('SELECT payload FROM gates WHERE id=?',(a['gateId'],)).fetchone()[0])
   return a
 def listing(self,q):
  with self.db(write=False) as c:
   where=["status!='merged'"];params=[]
   for key in ('rule','severity','status'):
    v=q.get(key,[''])[0]
    if v:where.append(key+'=?');params.append(v)
   query=q.get('q',[''])[0]
   if query:where.append('payload LIKE ?');params.append('%'+query.replace('%','\\%').replace('_','\\_')+'%');where[-1]+=" ESCAPE '\\'"
   sql=' WHERE '+' AND '.join(where) if where else '';total=c.execute('SELECT count(*) FROM alerts'+sql,params).fetchone()[0];offset=max(0,int(q.get('offset',['0'])[0]));limit=min(100,max(1,int(q.get('limit',['30'])[0])))
   items=[json.loads(r[0]) for r in c.execute('SELECT payload FROM alerts'+sql+' ORDER BY time DESC LIMIT ? OFFSET ?',(*params,limit,offset))]
   for a in items:a.pop('evidence',None);a.pop('ruleSnapshot',None)
   stats={r['status']:r['n'] for r in c.execute("SELECT status,count(*) n FROM alerts WHERE status!='merged' GROUP BY status")};sources=[self.coverage(c,r[0]) for r in c.execute('SELECT id FROM sources')]
   kept=int(self.config.get('maxEvents',20000))
   return {'items':items,'total':total,'offset':offset,'limit':limit,'stats':stats,'sources':sources,'serverTime':self.clock(),'capabilities':{'kernelBlock':False,'gate':'REA analyze + fixed-scope lab executor only','retention':'raw 72h/%d; alerts 30d/2000; 256MiB SQLite pages'%kept,'webLens':'candidate import only; no automatic FOFA queries'}}
 def intelligence(self):
  with self.db(write=False) as c:return [json.loads(x[0]) for x in c.execute('SELECT payload FROM intel ORDER BY time DESC LIMIT 50')]
 def intel_accept(self,iid,body,actor):
  reason=str(body.get('reason','')).strip()
  if len(reason)<3:raise ValueError('需要至少三个字符的审核理由')
  with self.db() as c:
   row=c.execute('SELECT payload FROM intel WHERE id=?',(iid,)).fetchone()
   if not row:raise KeyError('候选不存在')
   value=json.loads(row[0]);selected=body.get('rules',value.get('rules',[]))
   if not selected or any(r not in [x['id'] for x in RULES if x['id']!='P01'] for r in selected):raise ValueError('请指定有效的行为规则')
   value.update(status='accepted_recommendation',reviewedBy=actor,reviewedAt=self.clock(),reviewReason=reason,rules=selected,limitation='人工采纳的规则建议；不自动更改采集范围或启用阻断')
   c.execute('UPDATE intel SET payload=? WHERE id=?',(compact(value),iid));return value
 def intel_import(self,body,actor):
  if not body.get('component') or not body.get('sourceUrl'):raise ValueError('需要组件与可追溯来源 URL')
  component=str(body['component']).lower();mapping=self.config.get('intelligenceMappings',{'dify':{'rules':['S01','S03','S04'],'basis':'工作流执行与凭据访问风险，人工核查后决定'},'open webui':{'rules':['S01','S04'],'basis':'工具执行工作负载的通用文件/执行防护'}});match=mapping.get(component,{'rules':[],'basis':'没有匹配的映射，需人工制定'})
  v=clean({k:body.get(k) for k in ['component','version','sourceUrl','observedAt','assetId','note']});v.update(id='intel_'+uuid.uuid4().hex,receivedAt=self.clock(),actor=actor,status='candidate',rules=match['rules'],mappingBasis=match['basis'],mappingVersion='1',limitation='仅线索，不证明漏洞、不自动启用阻断')
  with self.db() as c:c.execute('INSERT INTO intel VALUES(?,?,?)',(v['id'],self.clock(),compact(v)));c.execute('DELETE FROM intel WHERE rowid IN (SELECT rowid FROM intel ORDER BY time DESC LIMIT -1 OFFSET 50)')
  return v

def network_allowed(destination,port,allowed):
 try:ip=ipaddress.ip_address(destination)
 except ValueError:return False
 for item in allowed:
  cidr=item.get('cidr') if isinstance(item,dict) else item;ports=item.get('ports') if isinstance(item,dict) else None
  try:
   if ip in ipaddress.ip_network(cidr,strict=False) and (ports is None or port in ports):return True
  except (ValueError,TypeError):continue
 return False

SENSITIVE_PATHS={
 'env':['*/.env','*/.env.*'], 'ssh':['*/.ssh/*','*/id_rsa','*/id_ed25519','*/id_ecdsa'],
 'system':['/etc/shadow','/etc/gshadow'], 'kubernetes':['*/.kube/config','*/kubeconfig'],
 'container':['*/.docker/config.json'], 'git':['*/.git-credentials'], 'netrc':['*/.netrc'],
 'aws':['*/.aws/credentials','*/.aws/config'], 'gcloud':['*/.config/gcloud/application_default_credentials.json'],
 'azure':['*/.azure/accessTokens.json','*/.azure/msal_token_cache*'],
 'key':['*.pem','*.key'], 'secrets':['*/secrets.yaml','*/secrets.yml','*/secrets.json']}
PERSISTENCE_PATHS={
 'env':['*/.env','*/.env.*'],'ssh':['*/.ssh/authorized_keys','*/.ssh/authorized_keys2'],
 'shell':['*/.bashrc','*/.profile','*/.bash_profile','*/.zshrc'],
 'cron':['/etc/crontab','/etc/cron.d/*','/etc/cron.daily/*','/etc/cron.hourly/*','/var/spool/cron/*','/var/spool/cron/crontabs/*'],
 'systemd':['/etc/systemd/system/*','*/.config/systemd/user/*'],'preload':['/etc/ld.so.preload'],
 'git':['*/.git/hooks/*'],'workflow':['*/.github/workflows/*'],
 'account':['/etc/passwd','/etc/group','/etc/sudoers','/etc/sudoers.d/*']}
def sensitive_path(path,patterns=None):
 groups=patterns if isinstance(patterns,dict) else SENSITIVE_PATHS
 return any(fnmatch.fnmatchcase(path,p) for ps in groups.values() for p in ps)
def persistence_path(path,patterns=None):
 groups=patterns if isinstance(patterns,dict) else PERSISTENCE_PATHS
 return any(fnmatch.fnmatchcase(path or '',p) for ps in groups.values() for p in ps)
def canonical_command(s):
 try:return ' '.join(shlex.split(s))
 except ValueError:return ' '.join(s.split())
def risky_command(cmd):
 return bool(re.search(r'(?:curl|wget)\b.*\|\s*(?:/bin/)?(?:ba)?sh|\$\(\s*(?:curl|wget)\b|\bnc(?:at)?\b.*\s-e\s|rm\s+-rf|/dev/tcp/',cmd))

def loss_totals(body):
 counters=body.get('counters') or {}
 sensor=sum(int(counters.get(k,0) or 0) for k in ('spoolDropped','expiredDropped','oversizeDropped','parseErrors','staleSkipped','rejectedEvents','rotationLost'))
 return max(sensor,int(body.get('serverRejected',0))),body.get('auditLost',body.get('drop'))
