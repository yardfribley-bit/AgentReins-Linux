"""Bounded SQL/FTS evidence search with an explicitly limited field DSL."""
import json,hashlib,datetime,shlex,re
FIELDS={'agent':'app','agent.name':'app','task.id':'run_id','trace.id':'trace','tool.name':'tool','container.id':'container','process.pid':'pid','event.category':'category','event.operation':'operation','execution.exit_code':'exit_code','status':'status'}
def init(c):
 c.executescript('CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY,run_id TEXT,app TEXT,time TEXT,ts REAL,category TEXT,operation TEXT,tool TEXT,container TEXT,pid INTEGER,trace TEXT,exit_code INTEGER,status TEXT,text TEXT,payload TEXT);CREATE INDEX IF NOT EXISTS evidence_ts ON evidence(ts DESC);CREATE INDEX IF NOT EXISTS evidence_run ON evidence(run_id);CREATE INDEX IF NOT EXISTS evidence_cid ON evidence(container);CREATE VIRTUAL TABLE IF NOT EXISTS evidence_fts USING fts5(id UNINDEXED,text,tokenize="unicode61");')
def put(c,key,run,app,stamp,category,operation,tool='',container='',pid=None,trace='',exit_code=None,status='',payload=None):
 try:ts=datetime.datetime.fromisoformat(str(stamp).replace('Z','+00:00')).timestamp()
 except (ValueError,TypeError):ts=0
 body=json.dumps(payload or {},ensure_ascii=False);text=' '.join([run,app,category,operation,tool,container,str(pid or ''),trace,body[:50000]]);old=c.execute('SELECT payload FROM evidence WHERE id=?',(key,)).fetchone()
 if old and old[0]==body:return
 c.execute('INSERT OR REPLACE INTO evidence VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(key,run,app,stamp,ts,category,operation,tool,container,pid,trace,exit_code,status,text,body));c.execute('DELETE FROM evidence_fts WHERE id=?',(key,));c.execute('INSERT INTO evidence_fts VALUES(?,?)',(key,text))
def ingest(c,d):
 init(c)
 for j in d.get('journeys',[]):
  w=(j.get('request') or {}).get('workflowTrace') or {};run=w.get('runId',j['id'].split(':')[0]);app=w.get('appName','Dify');stamp=j.get('time','')
  put(c,'model:'+j['id'],run,app,stamp,'model','MODEL_EXCHANGE',status=j.get('status',''),payload={'id':j['id'],'userMessages':[m for m in (j.get('request') or {}).get('messages',[]) if m.get('role')=='user'],'response':j.get('response'),'error':j.get('error')})
  for t in j.get('tools',[]):
   try:result=json.JSONDecoder().raw_decode((t.get('result') or {}).get('content',''))[0]
   except (ValueError,TypeError):result={}
   if not isinstance(result,dict):result={}
   cid=result.get('container_id',t.get('runtimeContainerId',''));trace=result.get('trace_id',t.get('traceId',''));pid=result.get('host_pid',t.get('runtimeHostPid'))
   put(c,'tool:'+t['id'],run,app,t.get('time',stamp),'tool','TOOL_CALL',t['name'],cid,pid,trace,result.get('exit_code'),t.get('association',''),{'arguments':t.get('arguments'),'result':t.get('result'),'association':t.get('association')})
   for k in ['commands','network','kernel']:
    for e in t.get(k,[]):
     key=e.get('eventKey') or hashlib.sha256(json.dumps(e,sort_keys=True).encode()).hexdigest()
     put(c,'event:'+run+':'+key,run,app,e.get('time',stamp),'command' if k=='commands' else ('network' if k=='network' else 'kernel'),e.get('operation',''),t['name'],e.get('containerId',cid),e.get('pid'),trace,status=e.get('result',''),payload=e)
   for f in result.get('files',[]):put(c,'file:'+run+':'+f,run,app,stamp,'file','FILE_ARTIFACT',t['name'],cid,pid,trace,result.get('exit_code'),payload={'path':f,'source':'executor returned file path'})
 for a in d.get('actions',{}).values():
  run='action:'+a['id'];put(c,run,run,'Dify system action',a.get('start',a.get('time','')),'command','SYSTEM_ACTION',a.get('tool',''),a.get('containerId',''),a.get('pid'),payload={k:a.get(k) for k in ['id','title','description','command','tool','start','status','containerId','pid']})
def search(c,params):
 init(c);query=params.get('q',[''])[0];offset=max(0,int(params.get('offset',['0'])[0]));limit=min(100,max(1,int(params.get('limit',['25'])[0])));clauses=[];args=[];groups=[[]];group_args=[[]]
 if len(query)>2000:raise ValueError('查询过长')
 if any(x in query for x in ['(',')']):raise ValueError('暂不支持括号；支持字段、AND、OR、数值范围与字段通配符')
 for token in shlex.split(query):
  if token=='AND':continue
  if token=='OR':
   if not groups[-1]:raise ValueError('OR 前缺少条件')
   groups.append([]);group_args.append([]);continue
  if token=='NOT':raise ValueError('当前不支持 NOT')
  if ':' in token:
   field,value=token.split(':',1)
   if field not in FIELDS:raise ValueError('未知字段：'+field)
   column=FIELDS[field];match=re.fullmatch(r'(>=|<=|>|<|=)?(-?\d+)',value)
   if column in ('pid','exit_code'):
    if not match:raise ValueError(field+' 需要整数或数值范围，例如 >0')
    sql=column+(match[1] or '=')+'?';values=[int(match[2])]
   else:
    sql=column+' LIKE ? ESCAPE "\\"';values=[value.replace('\\','\\\\').replace('%','\\%').replace('_','\\_').replace('*','%')]
  else:sql='id IN (SELECT id FROM evidence_fts WHERE evidence_fts MATCH ?)';values=['"'+token.replace('"','""')+'"']
  if ':' in token and field in FIELDS and value=='*' and column not in ('pid','exit_code'):sql='('+column+' IS NOT NULL AND '+column+'!=?)';values=['']
  groups[-1].append(sql);group_args[-1]+=values
 if len(groups)>1 and not groups[-1]:raise ValueError('OR 后缺少条件')
 if groups[0]:clauses.append('('+' OR '.join('('+' AND '.join(g)+')' for g in groups)+')');args=[v for group in group_args for v in group]
 for key,op in [('from','>='),('to','<=')]:
  value=params.get(key,[''])[0]
  if value:
   try:stamp=datetime.datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()
   except ValueError:raise ValueError('时间格式无效')
   clauses.append('ts'+op+'?');args.append(stamp)
 category=params.get('category',[''])[0]
 if category:clauses.append('category=?');args.append(category)
 where=' WHERE '+' AND '.join(clauses) if clauses else ''
 total=c.execute('SELECT count(*) FROM evidence'+where,args).fetchone()[0];facets=dict(c.execute('SELECT category,count(*) FROM evidence'+where+' GROUP BY category',args).fetchall())
 columns=['id','runId','app','time','category','operation','tool','container','pid','traceId','exitCode','status','text','payload']
 rows=c.execute('SELECT id,run_id,app,time,category,operation,tool,container,pid,trace,exit_code,status,substr(text,1,450),payload FROM evidence'+where+' ORDER BY ts DESC,id LIMIT ? OFFSET ?',args+[limit,offset]).fetchall();hits=[]
 for row in rows:
  h=dict(zip(columns,row));h['payload']=json.loads(h['payload']);hits.append(h)
 coverage=c.execute('SELECT min(time),max(time),count(*) FROM evidence').fetchone()
 return {'total':total,'offset':offset,'limit':limit,'hits':hits,'facets':facets,'coverage':{'from':coverage[0],'to':coverage[1],'documents':coverage[2],'note':'仅检索公网已归档模型、工具和关联系统证据；不是39上全部原始日志。'},'supportedFields':list(FIELDS)}

def natural(params):
 out={k:list(v) for k,v in params.items()};text=params.get('q',[''])[0];parts=[];notes=[];now=datetime.datetime.now(datetime.timezone.utc)
 if not text.strip():return out,{'original':text,'query':'','category':out.get('category',[''])[0],'from':'','to':'','notes':[],'method':'未输入条件，展示全部已归档证据'}
 if re.search(r'最近一天|过去一天|24\s*小时',text):out['from']=[(now-datetime.timedelta(days=1)).isoformat()];out['to']=[now.isoformat()]
 elif re.search(r'最近一周|过去一周|7\s*天',text):out['from']=[(now-datetime.timedelta(days=7)).isoformat()];out['to']=[now.isoformat()]
 elif '昨天' in text:
  local=now.astimezone(datetime.timezone(datetime.timedelta(hours=8)));end=local.replace(hour=0,minute=0,second=0,microsecond=0);out['from']=[(end-datetime.timedelta(days=1)).isoformat()];out['to']=[end.isoformat()]
 else:
  m=re.search(r'最近\s*(\d+)\s*(分钟|小时|天)',text)
  if m:out['from']=[(now-datetime.timedelta(seconds=int(m[1])*{'分钟':60,'小时':3600,'天':86400}[m[2]])).isoformat()];out['to']=[now.isoformat()]
 category=''
 if re.search(r'网络|访问了|连接',text):category='network'
 elif re.search(r'命令|执行了什么|执行了哪些',text):category='command'
 elif re.search(r'内核|系统调用|隔离',text):category='kernel'
 elif re.search(r'文件|报告产物',text):category='file'
 elif '工具' in text:category='tool'
 elif re.search(r'(?i)redis|键值|缓存键',text):category='redis'
 if category:out['category']=[category]
 if re.search(r'失败|非零退出',text):parts.append('execution.exit_code:>0');out['category']=['tool'];notes.append('失败按执行器返回的非零退出码筛选；不包含所有模型或网络错误。')
 for pattern,field in [(r'(?:PID|pid|进程号)\s*[:：为是]?\s*(\d+)','process.pid'),(r'(?:容器)\s*[:：为是]?\s*([a-f0-9]{12,64})','container.id'),(r'(?:Trace|trace|追踪ID)\s*[:：为是]?\s*([a-zA-Z0-9_-]{8,128})','trace.id')]:
  m=re.search(pattern,text)
  if m:parts.append(field+':'+m[1])
 if '沙箱' in text:parts.append('container.id:*');notes.append('沙箱范围按已记录容器身份筛选，不代表所有容器都具备相同隔离强度。')
 if re.search(r'python|Python',text):parts.append('python')
 if re.search(r'nmap|Nmap',text):parts.append('nmap')
 for domain in re.findall(r'\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b',text):parts.append('"'+domain+'"')
 if not parts and not category and not out.get('from'):notes.append('未识别明确字段，按整句全文搜索；可以改用关键词或字段语法。');parts=['"'+text.replace('"','')+'"']
 out['q']=[' AND '.join(parts)]
 return out,{'original':text,'query':out['q'][0],'category':out.get('category',[''])[0],'from':out.get('from',[''])[0],'to':out.get('to',[''])[0],'notes':notes,'method':'规则解析常见表达，非通用语义模型；请核对转换条件'}

def ingest_platform(c,p):
 init(c);metrics=p.get('dependencyMetrics',{});stamp=datetime.datetime.fromtimestamp(p.get('sampledAt',0),datetime.timezone.utc).isoformat()
 for key in metrics.get('redis',{}).get('keyValues',{}).get('keys',[]):
  put(c,'redis:'+key['key'],'dependency:redis','Dify Redis',stamp,'redis','REDIS_KEY_PREVIEW',status=key.get('contentStatus',''),payload=key)
 for a in metrics.get('artifacts',[]):
  put(c,'artifact:'+a['executionId']+':'+a['name'],'executor:'+a['executionId'],'Dify sandbox',stamp,'file','FILE_CONTENT_PREVIEW',payload=a)
