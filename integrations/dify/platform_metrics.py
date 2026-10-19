import datetime,json,sqlite3,time
from pathlib import Path
def metrics(run):
 result={}
 probe="import redis,json; from configs import dify_config as c; r=redis.Redis(host=c.REDIS_HOST,port=c.REDIS_PORT,username=c.REDIS_USERNAME,password=c.REDIS_PASSWORD,db=c.REDIS_DB,socket_connect_timeout=2,socket_timeout=2); i=r.info(); print(json.dumps({k:i.get(k) for k in ['connected_clients','used_memory','maxmemory','instantaneous_ops_per_sec','rejected_connections','evicted_keys','keyspace_hits','keyspace_misses']},ensure_ascii=False))"
 try:result['redis']={'sampledAt':time.time(),'status':'ok',**json.loads(run(['docker','exec','dify-api-1','/app/api/.venv/bin/python','-c',probe]))}
 except Exception as e:result['redis']={'status':'error','error':str(e)[:160]}
 try:
  inventory="""import redis,json,re,hashlib
from configs import dify_config as c
r=redis.Redis(host=c.REDIS_HOST,port=c.REDIS_PORT,username=c.REDIS_USERNAME,password=c.REDIS_PASSWORD,db=c.REDIS_DB,socket_timeout=2)
out=[];cursor,keys=r.scan(0,count=100)
for k in keys[:50]:
 name=k.decode(errors='replace');prefix=name.split(':')[0];sensitive=bool(re.search(r'(?i)token|credential|password|secret|session|auth|api.?key',name));allowed=bool(re.match(r'(?i)^(workflow|task|agent|queue|celery|agentreins)(:|$)',name)) and not sensitive
 item={'key':prefix+':'+hashlib.sha256(k).hexdigest()[:8],'type':r.type(k).decode(),'ttlSeconds':r.ttl(k),'contentStatus':'hidden_sensitive' if sensitive else ('eligible' if allowed else 'namespace_not_allowed')}
 if allowed:
  typ=item['type'];value=None
  if typ=='string':value=r.getrange(k,0,2047).decode(errors='replace')
  elif typ=='hash':value={a.decode(errors='replace'):('[REDACTED]' if re.search(r'(?i)token|credential|password|secret|auth|api.?key',a.decode(errors='replace')) else b[:512].decode(errors='replace')) for a,b in list(r.hscan(k,0,count=10)[1].items())[:10]}
  elif typ=='list':value=[v[:512].decode(errors='replace') for v in r.lrange(k,0,9)]
  def redact(v):
   if isinstance(v,dict):return {a:('[REDACTED]' if re.search(r'(?i)token|credential|password|secret|auth|api.?key',a) else redact(b)) for a,b in v.items()}
   if isinstance(v,list):return [redact(x) for x in v]
   if isinstance(v,str):
    try:return redact(json.loads(v))
    except (ValueError,TypeError):return re.sub(r'(?i)(Bearer\\s+)\\S+',r'\\1[REDACTED]',v)
   return v
  item['preview']=redact(value);item['contentStatus']='bounded_preview' if value is not None else 'unsupported_type'
 out.append(item)
print(json.dumps({'keys':out,'scanComplete':cursor==0,'nextCursor':cursor,'sampleLimit':50,'policy':'Sensitive namespaces hidden; bounded allowlisted previews only'},ensure_ascii=False))"""
  result['redis']['keyValues']=json.loads(run(['docker','exec','dify-api-1','/app/api/.venv/bin/python','-c',inventory]))
 except Exception as e:result.setdefault('redis',{})['keyValuesError']=str(e)[:160]
 result['sourceFiles']=[]
 source=Path('/opt/agentreins/github-research/research.py')
 if source.is_file() and not source.is_symlink():
  result['sourceFiles'].append({'name':'research.py','size':source.stat().st_size,'preview':source.read_bytes()[:16384].decode(errors='replace'),'truncated':source.stat().st_size>16384,'source':'Current deployed executor script; not historical snapshot'})
 result['artifacts']=[]
 root=Path('/opt/agentreins/github-research/runs')
 if root.exists():
  for directory in sorted(root.iterdir(),key=lambda p:p.stat().st_mtime,reverse=True)[:8]:
   if directory.is_symlink():continue
   for name in ['report.json','report.md']:
    p=directory/name
    if p.is_file() and not p.is_symlink():
     with p.open('rb') as f:body=f.read(16384).decode(errors='replace')
     result['artifacts'].append({'executionId':directory.name,'name':name,'size':p.stat().st_size,'preview':body,'truncated':p.stat().st_size>16384,'source':'Fixed research executor report files'})

 rea_root=Path('/home/smith/agentreins-rea/runs')
 if rea_root.exists():
  for directory in sorted(rea_root.iterdir(),key=lambda p:p.stat().st_mtime,reverse=True)[:8]:
   if not directory.is_dir() or directory.is_symlink():continue
   for name in ['report.json','report.md','rea-evidence.json']:
    p=directory/name
    if p.is_file() and not p.is_symlink():
     with p.open('rb') as f:body=f.read(16384).decode(errors='replace')
     result['artifacts'].append({'executionId':directory.name,'name':name,'size':p.stat().st_size,'preview':body,'truncated':p.stat().st_size>16384,'source':'REA fixed public frontend analysis; local preflight or Dify tool run as recorded'})

 try:result['postgres']={'sampledAt':time.time(),'readiness':run(['docker','exec','dify-pgvector-1','pg_isready']).strip()}
 except Exception as e:result['postgres']={'error':str(e)[:160]}
 since=(datetime.datetime.now().astimezone()-datetime.timedelta(hours=1)).isoformat();latest=None;counts={'requests':0,'responses':0,'errors':0,'totalTokens':0};latencies=[];models=set()
 try:
  with sqlite3.connect('file:/var/log/agentreins/history.sqlite3?mode=ro',uri=True,timeout=3) as c:
   rows=c.execute("SELECT time,operation,resource,evidence FROM events WHERE category='semantic' AND time>=? AND operation IN ('MODEL_REQUEST','MODEL_RESPONSE','MODEL_ERROR','MODEL_INTERRUPTED') ORDER BY time DESC LIMIT 1000",(since,)).fetchall()
   latest=c.execute("SELECT time FROM events WHERE category='semantic' AND operation='MODEL_RESPONSE' ORDER BY time DESC LIMIT 1").fetchone()
  seen=set()
  for stamp,operation,raw,evidence in rows:
   try:data=json.loads(raw);identity=(json.loads(evidence or '{}').get('requestId') or '')+':'+operation
   except (ValueError,TypeError):continue
   if identity in seen:continue
   seen.add(identity)
   if operation=='MODEL_REQUEST':counts['requests']+=1
   elif operation=='MODEL_RESPONSE':
    counts['responses']+=1;usage=data.get('usage') or {};counts['totalTokens']+=int(usage.get('total_tokens') or 0)
    if isinstance(usage.get('latency'),(int,float)):latencies.append(usage['latency'])
   else:counts['errors']+=1
   if data.get('model'):models.add(data['model'])
  result['model']={'status':'connected','sampledAt':time.time(),'windowSeconds':3600,'counts':counts,'models':sorted(models),'meanLatencySeconds':round(sum(latencies)/len(latencies),3) if latencies else None,'latencySamples':len(latencies),'latestResponseAt':latest[0] if latest else None,'limit':1000,'truncated':len(rows)>=1000,'source':'AgentReins own semantic index; Dify normalized API observations, not provider HTTP request counts'}
 except Exception as e:result['model']={'status':'error','error':str(e)[:160]}
 return result
