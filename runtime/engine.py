"""Bounded persistent detection and approvals. No commands are executed here."""
import contextlib,copy,hashlib,hmac,ipaddress,json,re,sqlite3,time,uuid
from pathlib import Path

RULES=[
 {'id':'S01','version':'1.0','name':'敏感凭据路径访问','severity':'high','sources':['file'],'condition':'已登记工作负载成功以读取权限打开敏感路径，或尝试访问被拒绝','falsePositive':'部署与密钥轮换可能合法；按工作负载、路径、动作和期限加白','mode':'alert','limitation':'读取权限打开不证明读取了文件正文；不采集凭据内容'},
 {'id':'S02','version':'1.0','name':'工具后的非白名单外联','severity':'medium','sources':['tool','network'],'condition':'同一任务/执行身份的工具调用后，出现允许范围外连接','falsePositive':'模型 API、DNS、依赖安装及代理需要独立配置','mode':'alert','limitation':'只有时间邻近时不触发；candidate 只告警，不自动阻断'},
 {'id':'S03','version':'1.0','name':'可疑模型到命令执行链','severity':'medium','sources':['model','process'],'condition':'明确任务内模型输出的命令与后续执行相符且含高风险模式','falsePositive':'用户可能明确授权；这不单独证明提示注入','mode':'alert','limitation':'命令文本匹配为 candidate；不自动阻断'},
 {'id':'S04','version':'1.0','name':'下载文件后执行','severity':'high','sources':['process','network','file'],'condition':'同一工作负载内下载命令指定的落地路径，被后续进程执行','falsePositive':'合法安装/更新也会命中，必须审阅来源与任务','mode':'alert','limitation':'shell 启动本身不触发；下载/执行按路径与工作负载形成 candidate'},
 {'id':'S05','version':'1.0','name':'授权范围外连接','severity':'high','sources':['network'],'condition':'配置非空网络授权范围的工作负载连接未获允许的目的 IP/端口','falsePositive':'需包含 DNS、模型服务、CDN 与代理实际路径','mode':'alert','limitation':'未配置时不启用；连接尝试不等于已外传数据'},
 {'id':'P01','version':'1.0','name':'已接入工具执行前审批','severity':'medium','sources':['tool'],'condition':'受保护执行器即将执行一个具体调用','falsePositive':'审批请求不是危险行为已发生；这是显式工具保护策略','mode':'require_approval','limitation':'仅保护已接入的 REA analyze 与固定范围实验执行器，不覆盖任意 Dify 工具'}]
TERMINAL={'denied','expired','cancelled','succeeded','failed','interrupted'}
def compact(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'))
def digest(v):return hashlib.sha256(compact(v).encode()).hexdigest()
def clean(v):
 if isinstance(v,dict):return {str(k):('[REDACTED]' if re.search(r'(?i)^(authorization|api[_-]?key|password|token|secret|cookie|env)$',str(k)) else clean(x)) for k,x in v.items()}
 if isinstance(v,list):return [clean(x) for x in v[:100]]
 if isinstance(v,str):return re.sub(r'(?i)(Bearer\s+|(?:password|api[_-]?key|token|secret)\s*[=:]\s*)[^\s"\']+',r'\1[REDACTED]',v[:16000])
 return v
class Conflict(ValueError):pass
class Store:
 def __init__(self,path,clock=time.time):
  self.path=str(path);self.clock=clock;Path(path).parent.mkdir(parents=True,exist_ok=True)
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
''')
   c.execute('PRAGMA max_page_count=65536')
 @contextlib.contextmanager
 def db(self):
  c=sqlite3.connect(self.path,timeout=15);c.row_factory=sqlite3.Row
  try:
   c.execute('PRAGMA busy_timeout=15000');c.execute('PRAGMA max_page_count=65536');c.execute('BEGIN IMMEDIATE');yield c;c.commit()
  except BaseException:c.rollback();raise
  finally:c.close()
 def heartbeat(self,source,body):
  now=self.clock();body=clean(body);body.update(source=source,receivedAt=now)
  with self.db() as c:
   prev=c.execute('SELECT seen FROM sources WHERE id=?',(source,)).fetchone()
   if prev and now-prev['seen']>35:c.execute('INSERT OR REPLACE INTO gaps VALUES(?,?,?)',(source,prev['seen']+35,now))
   c.execute('INSERT OR REPLACE INTO sources VALUES(?,?,?)',(source,now,compact(body)))
 def coverage(self,c,source):
  row=c.execute('SELECT * FROM sources WHERE id=?',(source,)).fetchone();now=self.clock()
  if not row:return {'source':source,'state':'unknown','layers':{},'limitations':['未收到独立心跳']}
  body=json.loads(row['payload']);fresh=now-row['seen']<35;gaps=[dict(x) for x in c.execute('SELECT start,end FROM gaps WHERE source=? ORDER BY start DESC LIMIT 20',(source,))]
  if not fresh:gaps.insert(0,{'start':row['seen']+35,'end':None})
  return {**body,'state':'online' if fresh else 'offline','ageSeconds':round(now-row['seen'],1),'gaps':gaps,'drop':body.get('drop'),'limitations':['未提供的 drop 计数为未知；心跳在线不证明每条事件已采到']}
 def source_fresh(self,c,source):
  r=c.execute('SELECT seen FROM sources WHERE id=?',(source,)).fetchone();return r and self.clock()-r['seen']<35
 def _suppressed(self,c,e,rule):
  for r in c.execute('SELECT payload FROM exceptions WHERE expires>?',(self.clock(),)):
   x=json.loads(r[0]);scope=x['scope']
   if x.get('rule')==rule and all(str(e.get(k,''))==str(v) for k,v in scope.items()):return True
  return False
 def _alert(self,c,rule,e,refs,title,relation='explicit',basis='工作负载身份与直接主机事件',gate_id=None):
  spec=next(r for r in RULES if r['id']==rule)
  if self._suppressed(c,e,rule):return None
  key=digest([rule,e['source'],e['id'],gate_id]);aid='al_'+key[:24];coverage=self.coverage(c,e['source'])
  value={'id':aid,'createdAt':self.clock(),'rule':rule,'ruleVersion':spec['version'],'severity':spec['severity'],'title':title,'status':'pending' if gate_id else 'open','revision':1,'source':e['source'],'workload':e['workload'],'runId':e.get('runId'),'gateId':gate_id,'relation':{'strength':relation,'basis':basis},'evidence':refs,'coverageAtDetection':coverage,'limitations':[spec['limitation']],'ruleSnapshot':spec}
  c.execute('INSERT OR IGNORE INTO alerts VALUES(?,?,?,?,?,?,?)',(aid,value['createdAt'],rule,spec['severity'],value['status'],key,compact(value)));return aid
 def ingest(self,source,items):
  if len(items)>100:raise ValueError('最多 100 条事件')
  now=self.clock();added=0
  with self.db() as c:
   for item in sorted(items,key=lambda x:float(x.get('time',now))):
    e=clean(item)
    if e.get('source') not in (None,source):raise ValueError('来源不匹配')
    if not e.get('id') or len(str(e['id']))>160 or e.get('kind') not in ('process','file','network','tool','model'):raise ValueError('事件字段无效')
    if not e.get('workload') or not e.get('identity',{}).get('basis'):raise ValueError('必须登记工作负载身份及依据')
    e['source']=source;e['receivedAt']=now;e['time']=float(e.get('time',now))
    if abs(e['time']-now)>300:raise ValueError('只接受最近 5 分钟事件；历史回填须独立标识')
    if c.execute('INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?)',(e['id'],e['time'],source,e['workload'],e['kind'],compact(e))).rowcount:
     added+=1;self.detect(c,e)
   # Late audit records can arrive after their corresponding execution.
   for item in items:
    if item.get('downloadPath'):
     for rr in c.execute('SELECT payload FROM events WHERE source=? AND workload=? AND kind=? AND time BETWEEN ? AND ? ORDER BY time LIMIT 100',(source,item['workload'],'process',float(item.get('time',now)),float(item.get('time',now))+120)).fetchall():self.detect(c,json.loads(rr[0]))
   self.prune(c)
  return added
 def detect(self,c,e):
  w=e['workload'];kind=e['kind'];now=e['time'];row=[e]
  recent=lambda kinds:[json.loads(x[0]) for x in c.execute('SELECT payload FROM events WHERE source=? AND workload=? AND time BETWEEN ? AND ? AND kind IN ('+','.join('?' for _ in kinds)+') ORDER BY time DESC LIMIT 100',(e['source'],w,now-120,now,*kinds))]
  path=e.get('path','');cmd=e.get('command','');policy=e.get('policy') or {};success=e.get('result')
  if kind=='file' and e.get('pid',0)>0 and e.get('access') in ('read_open','read') and re.search(r'(^|/)(\.env(?:\.[^/]*)?|\.ssh/[^/]+|credentials|[^/]+\.pem)$',path):
   self._alert(c,'S01',e,row,('敏感路径访问被拒绝：' if success=='denied' else '敏感路径读取权限访问：')+path)
  if kind=='network' and e.get('destination'):
   allowed=policy.get('allowedNetworks');enabled=isinstance(allowed,list) and len(allowed)>0
   if enabled and not network_allowed(e['destination'],e.get('port'),allowed):
    self._alert(c,'S05',e,row,'授权范围外连接尝试：'+e['destination']+':'+str(e.get('port','')))
    for t in recent(['tool']):
     if e.get('runId') and e.get('runId')==t.get('runId'):
      self._alert(c,'S02',e,[t,e],'工具后的非白名单外联','candidate','相同已登记任务身份与时间窗口；不代表工具唯一导致');break
  if kind=='process' and e.get('result')=='success':
   # Joining requires a concrete downloaded output path, not just starting a shell.
   for d in recent(['process']):
    if d['id']==e['id']:continue
    output=d.get('downloadPath')
    if output and not e.get('downloadPath') and output in e.get('execPaths',[]) and d.get('destination') and d.get('result')=='success' and (not e.get('runId') or e.get('runId')==d.get('runId')):
     self._alert(c,'S04',e,[d,e],'下载文件后执行：'+output,'candidate','相同工作负载、下载输出路径与执行参数匹配');break
   if re.search(r'curl\s.*\|\s*(?:ba)?sh|rm\s+-rf|/dev/tcp/',cmd):
    for m in recent(['model']):
     if e.get('runId') and e.get('runId')==m.get('runId') and cmd and cmd in m.get('text',''):
      self._alert(c,'S03',e,[m,e],'可疑模型到命令执行链','candidate','任务身份、命令文本与时间窗；不证明提示注入');break
 def prune(self,c):
  now=self.clock()
  c.execute('DELETE FROM events WHERE time<?',(now-72*3600,));c.execute('DELETE FROM events WHERE rowid IN (SELECT rowid FROM events ORDER BY time DESC LIMIT -1 OFFSET 20000)')
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
  binding={k:body[k] for k in ('tool','arguments','runId','workload')};hash_=digest(binding);now=self.clock()
  with self.db() as c:
   self.expire(c)
   if body['tool'] not in ('rea_analyze_frontend','runtime_lab_command'):raise ValueError('此工具未接入执行审批')
   r=c.execute('SELECT payload FROM gates WHERE request_key=?',(source+':'+str(body['requestKey']),)).fetchone()
   if r:
    g=json.loads(r[0])
    if g['hash']!=hash_:raise Conflict('同一请求参数已改变，必须创建新审批')
    return g
   if not self.source_fresh(c,source):raise Conflict('来源心跳过期，拒绝创建执行许可')
   if c.execute('SELECT count(*) FROM gates WHERE status IN (?,?)',('pending','approved')).fetchone()[0]>=30:raise Conflict('待审批队列已满')
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
   self.expire(c);r=c.execute('SELECT payload FROM alerts WHERE id=?',(aid,)).fetchone()
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
  with self.db() as c:
   self.expire(c);r=c.execute('SELECT payload FROM alerts WHERE id=?',(aid,)).fetchone()
   if not r:raise KeyError('告警不存在')
   a=json.loads(r[0]);a['coverageNow']=self.coverage(c,a['source']);a['reviews']=[json.loads(x[0]) for x in c.execute('SELECT payload FROM reviews WHERE alert_id=? ORDER BY time',(aid,))]
   if a.get('gateId'):a['gate']=json.loads(c.execute('SELECT payload FROM gates WHERE id=?',(a['gateId'],)).fetchone()[0])
   return a
 def listing(self,q):
  with self.db() as c:
   self.expire(c);where=[];params=[]
   for key in ('rule','severity','status'):
    v=q.get(key,[''])[0]
    if v:where.append(key+'=?');params.append(v)
   query=q.get('q',[''])[0]
   if query:where.append('payload LIKE ?');params.append('%'+query.replace('%','\\%').replace('_','\\_')+'%');where[-1]+=" ESCAPE '\\'"
   sql=' WHERE '+' AND '.join(where) if where else '';total=c.execute('SELECT count(*) FROM alerts'+sql,params).fetchone()[0];offset=max(0,int(q.get('offset',['0'])[0]));limit=min(100,max(1,int(q.get('limit',['30'])[0])))
   items=[json.loads(r[0]) for r in c.execute('SELECT payload FROM alerts'+sql+' ORDER BY time DESC LIMIT ? OFFSET ?',(*params,limit,offset))]
   for a in items:a.pop('evidence',None);a.pop('ruleSnapshot',None)
   stats={r['status']:r['n'] for r in c.execute('SELECT status,count(*) n FROM alerts GROUP BY status')};sources=[self.coverage(c,r[0]) for r in c.execute('SELECT id FROM sources')]
   return {'items':items,'total':total,'offset':offset,'limit':limit,'stats':stats,'sources':sources,'serverTime':self.clock(),'capabilities':{'kernelBlock':False,'gate':'REA analyze + fixed-scope lab executor only','retention':'raw 72h/20000; alerts 30d/2000; 256MiB SQLite pages','webLens':'candidate import only; no automatic FOFA queries'}}
 def intelligence(self):
  with self.db() as c:return [json.loads(x[0]) for x in c.execute('SELECT payload FROM intel ORDER BY time DESC LIMIT 50')]
 def intel_import(self,body,actor):
  if not body.get('component') or not body.get('sourceUrl'):raise ValueError('需要组件与可追溯来源 URL')
  v=clean({k:body.get(k) for k in ['component','version','sourceUrl','observedAt','assetId','note']});v.update(id='intel_'+uuid.uuid4().hex,receivedAt=self.clock(),actor=actor,status='candidate',rules=['S01','S03','S04'] if 'dify' in str(body['component']).lower() else ['S02','S05'],limitation='仅线索，不证明漏洞、不自动启用阻断')
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
