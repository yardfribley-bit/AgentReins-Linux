import glob,gzip,json,os,sqlite3,threading,time,datetime
DB='/var/log/agentreins/history.sqlite3'
STATUS={'state':'starting','indexed':0}
def connect():
 c=sqlite3.connect(DB,timeout=30);c.execute('PRAGMA auto_vacuum=INCREMENTAL');c.execute('PRAGMA journal_mode=WAL');c.execute('PRAGMA max_page_count=524288');return c
def init():
 c=connect();c.executescript('CREATE TABLE IF NOT EXISTS events (key TEXT PRIMARY KEY,time TEXT,category TEXT,operation TEXT,pid INTEGER,ppid INTEGER,container TEXT,process TEXT,resource TEXT,result TEXT,source TEXT,evidence TEXT);CREATE INDEX IF NOT EXISTS etime ON events(time);CREATE INDEX IF NOT EXISTS ec ON events(container,time);CREATE TABLE IF NOT EXISTS cursor(path TEXT PRIMARY KEY,inode INTEGER,offset INTEGER);');c.close()
def ingest_file(path):
 c=connect();st=os.stat(path);old=c.execute('SELECT inode,offset FROM cursor WHERE path=?',(path,)).fetchone();compressed=path.endswith('.gz')
 if old and old[0]==st.st_ino and compressed:c.close();return
 start=old[1] if old and old[0]==st.st_ino and old[1]<=st.st_size and not compressed else 0
 f=gzip.open(path,'rt') if compressed else open(path)
 if start:f.seek(start)
 count=0
 while True:
  offset=f.tell();line=f.readline()
  if not line or not line.endswith('\n'):break
  try:r=json.loads(line)
  except ValueError:continue
  ev=r.get('evidence') or {};key=r.get('eventKey')
  if not key:continue
  try:
   if datetime.datetime.fromisoformat(r.get('time','')).timestamp()<time.time()-72*3600:continue
  except (ValueError,TypeError):continue
  c.execute('INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(key,r.get('time',''),r.get('category',''),r.get('operation',''),r.get('pid',0),r.get('ppid',ev.get('ppid',0)),r.get('containerId',''),r.get('process',''),r.get('resource',''),r.get('result',''),r.get('source',''),json.dumps(ev,ensure_ascii=False)))
  count+=1
  if count%2000==0:trim(c);c.commit();STATUS['indexed']+=2000
 c.execute('INSERT OR REPLACE INTO cursor VALUES(?,?,?)',(path,st.st_ino,0 if compressed else offset));c.commit();c.close();f.close();STATUS['indexed']+=count%2000

def trim(c):
 cutoff=datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(hours=72)
 c.execute('DELETE FROM events WHERE julianday(time)<julianday(?)',(cutoff.isoformat(),))
 c.execute('DELETE FROM events WHERE rowid IN (SELECT rowid FROM events ORDER BY time DESC LIMIT -1 OFFSET 100000)')
 used=(c.execute('PRAGMA page_count').fetchone()[0]-c.execute('PRAGMA freelist_count').fetchone()[0])*c.execute('PRAGMA page_size').fetchone()[0]
 if used>1024**3:c.execute('DELETE FROM events WHERE rowid IN (SELECT rowid FROM events ORDER BY time ASC LIMIT 10000)')
 c.commit();c.execute('PRAGMA incremental_vacuum(2000)')
 STATUS.update(retentionHours=72,maxEvents=100000,softBytes=1024**3,hardBytes=2*1024**3)

def loop():
 init()
 while True:
  STATUS['state']='indexing'
  for path in ['/var/log/agentreins/host.jsonl','/var/log/agentreins/audit.jsonl','/var/log/agentreins/semantic.jsonl']:
   try:ingest_file(path)
   except (OSError,sqlite3.Error) as e:STATUS['error']=type(e).__name__
  c=connect();trim(c);c.close()
  STATUS['state']='ready';time.sleep(10)
def start():threading.Thread(target=loop,daemon=True).start()
def query(params):
 init();where=[];args=[]
 for name,column in [('container','container'),('category','category')]:
  value=params.get(name,[''])[0]
  if value=='sandbox_activity' and name=='category':where.append("container!=''")
  elif value:where.append(column+'=?');args.append(value)
 text=params.get('q',[''])[0]
 if text:where.append('(resource LIKE ? OR process LIKE ?)');args.extend(['%'+text+'%']*2)
 for name,op in [('from','>='),('to','<=')]:
  value=params.get(name,[''])[0]
  if value:where.append('time '+op+' ?');args.append(value)
 clause=' WHERE '+' AND '.join(where) if where else ''
 c=connect();total=c.execute('SELECT count(*) FROM events'+clause,args).fetchone()[0]
 limit=min(500,max(1,int(params.get('limit',['200'])[0])));offset=max(0,int(params.get('offset',['0'])[0]))
 rows=c.execute('SELECT time,category,operation,pid,ppid,container,process,resource,result,source,evidence FROM events'+clause+' ORDER BY time DESC LIMIT ? OFFSET ?',args+[limit,offset]).fetchall()
 columns=['time','category','operation','pid','ppid','containerId','process','resource','result','source']
 containers=[{'id':r[0],'events':r[1]} for r in c.execute("SELECT container,count(*) FROM events WHERE container!='' GROUP BY container ORDER BY count(*) DESC")]
 output=[]
 for r in rows:
  row=dict(zip(columns,r[:10]));evidence=json.loads(r[10] or '{}')
  row['executionStatus']={k:evidence.get(k) for k in ('exit_code','exit_signal','syscall','exit','uid','cwd','dst','dport','classification') if k in evidence}
  if row['operation']=='EXIT':row['resource']='退出状态 '+json.dumps(row['executionStatus'],ensure_ascii=False)
  output.append(row)
 c.close();return {'events':output,'total':total,'containers':containers,'index':dict(STATUS),'offset':offset}

def association_events(semantic):
 from tool_chains import build,stamp
 import datetime
 init();c=connect();found={}
 def rows(sql,args):
  result=[]
  for r in c.execute(sql,args):
   ev=json.loads(r[11] or '{}');row=dict(zip(['eventKey','time','category','operation','pid','ppid','containerId','process','resource','result','source'],r[:11]));row['kernelEvidence']={k:ev[k] for k in ('syscall','arch','exit','exit_code','exit_signal','uid','cwd','arguments','namespaces','cgroup') if k in ev};result.append(row)
  return result
 select='SELECT key,time,category,operation,pid,ppid,container,process,resource,result,source,evidence FROM events'
 for tool in build([],semantic)[:40]:
  try:
   payload=json.JSONDecoder().raw_decode((tool.get('result') or {}).get('content',''))[0]
   cid=payload.get('container_id','')
  except (ValueError,TypeError,AttributeError):cid=''
  if cid:
   dt=datetime.datetime.fromisoformat(tool['time']);low=(dt-datetime.timedelta(seconds=5)).isoformat();high=(dt+datetime.timedelta(seconds=300)).isoformat()
   for row in rows(select+' WHERE container=? AND time>=? AND time<=? LIMIT 2000',[cid[:12],low,high]):found[row['eventKey']]=row
  commands=[v for v in tool['commandIntent'] if len(v.strip())>=4]
  if not commands:continue
  dt=datetime.datetime.fromisoformat(tool['time']);low=(dt-datetime.timedelta(seconds=2)).isoformat();high=(dt+datetime.timedelta(seconds=300)).isoformat()
  matched=rows(select+" WHERE time>=? AND time<=? AND operation IN ('EXEC','AUDIT_EXEC') AND ("+' OR '.join('instr(resource,?)>0' for _ in commands)+') LIMIT 50',[low,high]+commands)
  pids={r['pid'] for r in matched if r['pid']}
  for _ in range(6):
   if not pids:break
   new=rows(select+' WHERE time>=? AND time<=? AND ppid IN ('+','.join('?' for _ in pids)+') LIMIT 500',[low,high]+list(pids));updated=pids|{r['pid'] for r in new if r['pid']};matched+=new
   if updated==pids:break
   pids=updated
  if pids:matched+=rows(select+' WHERE time>=? AND time<=? AND pid IN ('+','.join('?' for _ in pids)+') LIMIT 1000',[low,high]+list(pids))
  for row in matched:found[row['eventKey']]=row
 c.close();return list(found.values())

def process_timeline(params):
 import datetime
 pid=int(params.get('pid',['0'])[0]);container=params.get('container',[''])[0];anchor=params.get('time',[''])[0]
 if pid<=0 or not anchor:raise ValueError('pid and time required')
 dt=datetime.datetime.fromisoformat(anchor);low=(dt-datetime.timedelta(seconds=3)).isoformat();high=(dt+datetime.timedelta(minutes=30)).isoformat()
 c=connect()
 start_sql="SELECT time FROM events WHERE pid=? AND operation IN ('EXEC','AUDIT_EXEC') AND time<=?";start_args=[pid,anchor]
 if container:start_sql+=' AND container=?';start_args.append(container)
 prior=c.execute(start_sql+' ORDER BY time DESC LIMIT 1',start_args).fetchone()
 if prior:
  candidate=datetime.datetime.fromisoformat(prior[0])
  if 0<=(dt-candidate).total_seconds()<=1800:dt=candidate;low=(dt-datetime.timedelta(seconds=3)).isoformat();high=(dt+datetime.timedelta(minutes=30)).isoformat()
 clauses='pid=? AND time>=? AND time<=?';args=[pid,low,high]
 if container:clauses+=' AND container=?';args.append(container)
 columns=['time','category','operation','pid','ppid','containerId','process','resource','result','source']
 rows=c.execute('SELECT time,category,operation,pid,ppid,container,process,resource,result,source,evidence FROM events WHERE '+clauses+' ORDER BY time ASC LIMIT 500',args).fetchall()
 rows+=c.execute('SELECT time,category,operation,pid,ppid,container,process,resource,result,source,evidence FROM events WHERE '+clauses+" AND operation='EXIT' ORDER BY time ASC LIMIT 20",args).fetchall()
 rows=sorted(set(rows),key=lambda r:r[0])
 # Restrict this view to the selected PID; descendants and task ownership are not assumed.
 result=[]
 for r in rows:
  row=dict(zip(columns,r[:10]));ev=json.loads(r[10] or '{}');row['state']={k:ev[k] for k in ('syscall','arch','exit','exit_code','exit_signal','uid','cwd','dst','dport','classification') if k in ev};result.append(row)
 c.close();return {'pid':pid,'containerId':container,'events':result,'association':'PID_CONTAINER_TIME_WINDOW','note':'按 PID、容器和选定时间附近检索，最多30分钟、500条。PID 复用或缺失容器归属时可能不完整；不是整个任务的全部行为。'}

def semantic_events():
 c=connect();rows=c.execute("SELECT key,time,category,operation,pid,ppid,container,process,resource,result,source,evidence FROM events WHERE category='semantic' AND operation IN ('MODEL_REQUEST','MODEL_RESPONSE','MODEL_ERROR','MODEL_REASONING','TOOL_CALL','TOOL_RESULT') ORDER BY time DESC LIMIT 2000").fetchall();c.close();out=[]
 for r in reversed(rows):
  row=dict(zip(['eventKey','time','category','operation','pid','ppid','containerId','process','resource','result','source'],r[:11]));ev=json.loads(r[11] or '{}');row.update(requestId=ev.get('requestId',''),identity='model-client:'+str(ev.get('peer','unknown')));out.append(row)
 return out
