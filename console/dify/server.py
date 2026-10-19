#!/usr/bin/env python3
import hmac,json,time,threading,urllib.parse,sqlite3,contextlib
import evidence_search
import assistant_jobs
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from pathlib import Path
ROOT=Path('/opt/agentreins-dify');DATA=Path('/var/lib/agentreins-dify/snapshot.json');DB=DATA.with_suffix('.sqlite');LIVE=DATA.with_name('live.json');TOKEN=(ROOT/'sync.token').read_text().strip();lock=threading.Lock()
@contextlib.contextmanager
def connection():
 c=sqlite3.connect(DB,timeout=30)
 try:
  c.execute('PRAGMA temp_store=MEMORY')
  c.execute('CREATE TABLE IF NOT EXISTS records(kind TEXT,id TEXT,time TEXT,payload TEXT,PRIMARY KEY(kind,id))')
  c.execute('CREATE INDEX IF NOT EXISTS records_kind_time ON records(kind,time DESC)')
  yield c
  c.commit()
 finally:c.close()
def archive(d):
 with connection() as c:
  evidence_search.ingest(c,d)
  for kind,rows in [('journey',d.get('journeys',[])),('action',list(d.get('actions',{}).values()))]:
   for row in rows:
    if row.get('id'):c.execute('INSERT OR REPLACE INTO records VALUES(?,?,?,?)',(kind,row['id'],row.get('time',row.get('start','')),json.dumps(row,ensure_ascii=False)))
def fetch(kind,id=None):
 with connection() as c:
  rows=c.execute('SELECT payload FROM records WHERE kind=?'+(' AND id=?' if id else '')+' ORDER BY time DESC',([kind,id] if id else [kind])).fetchall()
 return [json.loads(r[0]) for r in rows]
def related(j):
 tools=list(j.get('tools',[]));seen={t['id'] for t in tools}
 for rid in j.get('previousInteractions',[]):
  for prev in fetch('journey',rid):
   for t in prev.get('tools',[]):
    if t['id'] not in seen:tools.append(t);seen.add(t['id'])
 return tools
def brief(j):
 w=(j.get('request') or {}).get('workflowTrace') or {};tools=related(j)
 return {**{k:j.get(k) for k in ('id','time','client','model','status','isTest')},'appName':w.get('appName'),'runId':w.get('runId'),'tools':[t['name'] for t in tools],'counts':{k:sum(len(t.get(k,[])) for t in tools) for k in ('commands','network','kernel')}}
def backfill_search():
 try:
  for kind in ['journey','action']:
   offset=0
   while True:
    with connection() as c:batch=c.execute('SELECT payload FROM records WHERE kind=? ORDER BY time DESC LIMIT 20 OFFSET ?',(kind,offset)).fetchall()
    if not batch:break
    rows=[json.loads(r[0]) for r in batch]
    with connection() as c:evidence_search.ingest(c,{'journeys':rows} if kind=='journey' else {'actions':{r['id']:r for r in rows}})
    offset+=len(rows);time.sleep(.1)
 except Exception as e:print('Search backfill error',type(e).__name__,str(e)[:160],flush=True)
threading.Thread(target=backfill_search,daemon=True).start()
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def send(self,code,value,html=False):
  body=value if isinstance(value,bytes) else json.dumps(value,ensure_ascii=False).encode();self.send_response(code);self.send_header('Content-Type','text/html; charset=utf-8' if html else 'application/json; charset=utf-8');self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def do_GET(self):
  u=urllib.parse.urlsplit(self.path);q=urllib.parse.parse_qs(u.query);id=q.get('id',[''])[0]
  if u.path=='/dify/_assistant/jobs':
   if not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+TOKEN):return self.send(403,{})
   return self.send(200,{'job':assistant_jobs.claim()})
  if u.path.startswith('/dify/api/assistant/'):
   job=assistant_jobs.read(u.path.rsplit('/',1)[-1]);return self.send(200,job) if job else self.send(404,{'error':'请求不存在或已过期'})
  if u.path in ('/dify','/dify/'):return self.send(200,(ROOT/'index.html').read_bytes(),True)
  try:d=json.loads(DATA.read_text())
  except (OSError,ValueError):return self.send(503,{'error':'Waiting for Dify synchronization'})
  if u.path=='/dify/api/sync':
   try:live=json.loads(LIVE.read_text())
   except (OSError,ValueError):live={}
   with connection() as c:counts=dict(c.execute('SELECT kind,count(*) FROM records GROUP BY kind').fetchall())
   return self.send(200,{'updatedAt':d['updatedAt'],'sourceUpdatedAt':d.get('sourceUpdatedAt'),'archiveCounts':counts,'live':live.get('live',d.get('live',{})),'executors':live.get('executors',d.get('executors',{})),'runtimeSyncedAt':live.get('updatedAt'),'platform':live.get('platform',{}),'coverage':'已收到的模型交互和行动详情持续归档；源端列表窗口仍有限，未做全部原始事件历史回填。'})
  if u.path=='/dify/api/search':
   try:
    translated=None
    if q.get('natural',['0'])[0]=='1':q,translated=evidence_search.natural(q)
    with connection() as c:result=evidence_search.search(c,q)
    if translated:result['translation']=translated
    return self.send(200,result)
   except (ValueError,sqlite3.Error) as e:return self.send(400,{'error':str(e)[:250]})
  if u.path=='/dify/api/journeys':
   rows=fetch('journey',id or None)
   if id:
    for j in rows:j['relatedTools']=related(j)
   else:rows=[brief(j) for j in rows]
   return self.send(200,{'journeys':rows})
  if u.path=='/dify/api/cockpit':
   if id:
    rows=fetch('action',id);return self.send(200,rows[0]) if rows else self.send(404,{'error':'Not archived'})
   query=q.get('q',[''])[0].lower();rows=fetch('action');rows=[r for r in rows if query in json.dumps(r,ensure_ascii=False).lower()]
   return self.send(200,{**d.get('cockpit',{}),'actions':[{k:r.get(k) for k in ('id','time','start','pid','containerId','tool','initiator','title','description')} for r in rows]})
  self.send(404,{'error':'Not found'})
 def do_POST(self):
  if self.path=='/dify/api/assistant':
   try:
    n=int(self.headers.get('Content-Length','0'));assert 0<n<=8000
    body=json.loads(self.rfile.read(n));question=body.get('question','');params,_=evidence_search.natural({'q':[question],'limit':['5']})
    with connection() as c:hits=evidence_search.search(c,params)['hits']
    context=[{k:h.get(k) for k in ['runId','app','category','operation','tool','container','pid','traceId','status','text']} for h in hits]
    key=assistant_jobs.submit(question,context,self.headers.get('X-Forwarded-For',self.client_address[0]).split(',')[0]);return self.send(202,{'id':key})
   except (ValueError,AssertionError) as e:return self.send(400,{'error':str(e) or '输入无效'})
  if self.path=='/dify/_assistant/result':
   if not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+TOKEN):return self.send(403,{})
   n=int(self.headers.get('Content-Length','0'))
   if not 0<n<=20000:return self.send(413,{})
   body=json.loads(self.rfile.read(n));assistant_jobs.finish(body.get('id'),body.get('result',{}));return self.send(200,{'ok':True})
  if self.path not in ('/dify/_ingest','/dify/_live'):return self.send(404,{})
  if not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+TOKEN):return self.send(403,{})
  n=int(self.headers.get('Content-Length','0'))
  if not 0<n<15_000_000:return self.send(413,{})
  try:
   d=json.loads(self.rfile.read(n))
   if self.path=='/dify/_live':
    assert isinstance(d.get('live'),dict);d['updatedAt']=time.time()
    with connection() as c:evidence_search.ingest_platform(c,d.get('platform',{}))
    with lock:p=LIVE.with_suffix('.new');p.write_text(json.dumps(d,ensure_ascii=False));p.replace(LIVE)
    return self.send(200,{'ok':True})
   assert isinstance(d.get('journeys'),list);assert isinstance(d.get('cockpit'),dict);d['updatedAt']=time.time()
   with lock:archive(d);p=DATA.with_suffix('.new');p.write_text(json.dumps(d,ensure_ascii=False));p.replace(DATA)
   self.send(200,{'ok':True})
  except (ValueError,AssertionError):self.send(400,{})
ThreadingHTTPServer(('127.0.0.1',8898),Handler).serve_forever()
