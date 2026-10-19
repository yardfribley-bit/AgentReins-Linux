#!/usr/bin/env python3
"""Read Dify execution APIs; never accesses its database or provider secrets."""
import datetime,hashlib,http.cookiejar,json,os,re,time,urllib.request,urllib.error,fcntl
from pathlib import Path
BASE=os.environ.get('AGENTREINS_DIFY_URL','http://127.0.0.1:8080').rstrip('/')
COOKIE=Path('/etc/agentreins/dify.cookies')
STATE=Path('/var/log/agentreins/dify-bridge-state.json')
OUT=Path('/var/log/agentreins/host.jsonl')
INTERVAL=int(os.environ.get('AGENTREINS_DIFY_POLL_SECONDS','10'))
CUTOFF=int(os.environ.get('AGENTREINS_DIFY_SINCE','0'))
jar=http.cookiejar.LWPCookieJar(str(COOKIE));jar.load(ignore_discard=True,ignore_expires=True)
op=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(jar))
try:seen=set(json.loads(STATE.read_text()).get('seen',[]))
except (OSError,ValueError):seen=set()

def clean(value):
 if isinstance(value,dict):return {k:('[REDACTED]' if re.search(r'(?i)^(authorization|password|token|api[_-]?key|cookie|secret)$',k) else clean(v)) for k,v in value.items()}
 if isinstance(value,list):return [clean(v) for v in value]
 if isinstance(value,str):return re.sub(r'(?i)(Bearer\s+)\S+',r'\1[REDACTED]',value)
 return value

def call(path,data=None,retry=True):
 csrf=next((c.value for c in jar if c.name=='csrf_token'),'')
 req=urllib.request.Request(BASE+path,data=json.dumps(data).encode() if data is not None else None,headers={'Content-Type':'application/json','X-CSRF-Token':csrf,'Origin':BASE})
 try:
  with op.open(req,timeout=20) as response:return json.load(response)
 except urllib.error.HTTPError as e:
  if e.code in (401,403) and retry:
   # Other collectors may have refreshed this shared session since startup.
   with COOKIE.with_suffix('.refresh.lock').open('a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX)
    jar.load(ignore_discard=True,ignore_expires=True)
    try:return call(path,data,False)
    except urllib.error.HTTPError as current:
     if current.code not in (401,403):raise
    call('/console/api/refresh-token',{},False);jar.save(ignore_discard=True,ignore_expires=True);return call(path,data,False)
  raise

def iso(value):
 if isinstance(value,(float,int)):return datetime.datetime.fromtimestamp(value,datetime.timezone.utc).astimezone().isoformat()
 return datetime.datetime.now().astimezone().isoformat()

def emit(operation,rid,payload,stamp,app_id,run_id,node_id,result='CAPTURED'):
 key=hashlib.sha256(('dify:'+rid+':'+operation).encode()).hexdigest()
 if key in seen:return
 event={'eventKey':key,'time':iso(stamp),'component':'DifyAPIObserver','category':'semantic','operation':operation,'process':'dify-workflow','pid':0,'ppid':0,'containerId':'','resource':json.dumps(clean(payload),ensure_ascii=False),'result':result,'source':'Dify authenticated execution API (normalized, not raw model HTTP)','evidence':{'requestId':rid,'peer':'dify-api','workflowRunId':run_id,'appId':app_id,'nodeId':node_id,'attribution':'DIRECT_API_EVENT'}}
 with OUT.open('a') as f:f.write(json.dumps(event,ensure_ascii=False)+'\n')
 seen.add(key)

def brief(node):
 outputs=node.get('outputs') or {}
 return {'nodeId':node.get('node_id'),'type':node.get('node_type'),'title':node.get('title'),'status':node.get('status'),'start':iso(node.get('created_at')),'end':iso(node.get('finished_at')) if node.get('finished_at') else None,'elapsed':node.get('elapsed_time'),'inputs':clean(node.get('inputs') or {}),'outputs':{k:clean(v[:16384] if isinstance(v,str) else v) for k,v in outputs.items() if k!='headers'},'error':str(node.get('error') or '')[:700]}

"""Agent-chat adapter: normalize persisted Dify message context, not raw HTTP."""
def poll_agent(app):
 aid=app['id']; observed=0
 conversations=call('/console/api/apps/'+aid+'/chat-conversations?page=1&limit=20').get('data',[])
 for conv in conversations:
  if (conv.get('updated_at') or conv.get('created_at') or 0)<CUTOFF:continue
  cid=conv['id']; model=(conv.get('model_config') or {}).get('model',{}).get('name','unknown')
  messages=call('/console/api/apps/'+aid+'/chat-messages?conversation_id='+cid+'&limit=20').get('data',[])
  for msg in messages:
   mid=msg['id']; key='agent-message:'+mid
   if key in seen or (msg.get('created_at') or 0)<CUTOFF:continue
   if not msg.get('answer') or msg.get('status') not in ('normal','success'):continue
   logs=call('/console/api/apps/'+aid+'/agent/logs?conversation_id='+cid+'&message_id='+mid)
   if logs.get('meta',{}).get('status') not in ('success','succeeded'):continue
   stamp=msg['created_at']; elapsed=logs.get('meta',{}).get('elapsed_time') or 0
   source='Dify agent message API: persisted context and output, not raw model HTTP; intermediate request envelopes are reconstructed from ordered message context'
   trace={'appId':aid,'appName':app.get('name'),'runId':mid,'conversationId':cid,'status':'succeeded','source':'Dify Agent execution API','nodes':[]}
   for index,iteration in enumerate(logs.get('iterations',[])):
    trace['nodes'].append({'nodeId':'iteration-'+str(index+1),'type':'agent','title':'Agent 第 '+str(index+1)+' 轮','status':'succeeded','start':iteration.get('created_at'),'elapsed':None,'outputs':{'tools':[{'name':t.get('tool_name'),'status':t.get('status'),'duration':t.get('time_cost'),'input':t.get('tool_input'),'output':t.get('tool_output')} for t in iteration.get('tool_calls',[])]}})
   context=[]; pending=[]; phase=0
   for entry in msg.get('message') or []:
    m={'role':entry.get('role','user'),'content':entry.get('text','')}
    if entry.get('tool_calls'):
     m['tool_calls']=entry['tool_calls']; phase+=1; rid=mid+':agent-'+str(phase)
     req={'model':model,'messages':list(context),'workflowTrace':trace,'observationSource':source}
     emit('MODEL_REQUEST',rid,req,stamp,aid,mid,'agent-'+str(phase))
     emit('MODEL_RESPONSE',rid,{'model':model,'choices':[{'message':m}],'observationSource':source},stamp,aid,mid,'agent-'+str(phase),'200')
     for tc in entry['tool_calls']:
      # One event per actual call ID; avoid duplicate event keys for parallel calls.
      trid=rid if len(entry['tool_calls'])==1 else rid+':'+tc['id']
      if trid!=rid:emit('MODEL_REQUEST',trid,req,stamp,aid,mid,'agent-'+str(phase))
      emit('TOOL_CALL',trid,tc,stamp,aid,mid,tc['id']);pending.append((tc['id'],trid))
    if m['role']=='tool' and pending:
     # Dify omits tool_call_id in this API. Only uniquely match a single pending call.
     if len(pending)==1:
      tid,trid=pending.pop(0);m['tool_call_id']=tid
      emit('TOOL_RESULT',trid,{'role':'tool','tool_call_id':tid,'content':m['content'],'associationSource':'Unique pending tool in Dify ordered message context'},stamp,aid,mid,tid)
    context.append(m)
   rid=mid+':final'
   emit('MODEL_REQUEST',rid,{'model':model,'messages':context,'workflowTrace':trace,'observationSource':source},stamp+elapsed,aid,mid,'final')
   emit('MODEL_RESPONSE',rid,{'model':model,'choices':[{'message':{'role':'assistant','content':msg['answer']}}],'usage':(msg.get('metadata') or {}).get('usage'),'observationSource':source},stamp+elapsed,aid,mid,'final','200')
   seen.add(key);observed+=1
 return observed


def poll():
 apps=call('/console/api/apps?page=1&limit=20').get('data',[])
 observed=0
 for app in apps:
  if app.get('mode')=='agent-chat':
   observed+=poll_agent(app);continue
  if app.get('mode') not in ('workflow','advanced-chat'):continue
  aid=app['id']
  runs=call('/console/api/apps/'+aid+'/workflow-runs?page=1&limit=10').get('data',[])
  for run in runs:
   if (run.get('created_at') or 0)<CUTOFF:continue
   if run.get('status') not in ('succeeded','failed','stopped','partial-succeeded'):continue
   run_id=run['id'];run_key='run:'+run_id
   if run_key in seen:continue
   nodes=call('/console/api/apps/'+aid+'/workflow-runs/'+run_id+'/node-executions').get('data',[])
   trace={'appId':aid,'appName':app.get('name'),'runId':run_id,'status':run.get('status'),'source':'Dify workflow execution API','nodes':[brief(n) for n in nodes]}
   for node in nodes:
    nid=node.get('node_id');rid=run_id+':'+str(nid);pd=node.get('process_data') or {};stamp=node.get('created_at')
    emit('WORKFLOW_NODE_FINISHED',rid,{'workflowTrace':trace,'node':brief(node)},node.get('finished_at') or stamp,aid,run_id,nid,node.get('status','unknown'))
    if node.get('node_type')!='llm' or not pd.get('prompts'):continue
    messages=[]
    for p in pd['prompts']:
     messages.append({'role':p.get('role','user'),'content':p.get('text',p.get('content',''))})
    request={'model':pd.get('model_name','unknown'),'messages':messages,'workflowTrace':trace,'observationSource':'Dify execution API: actual node prompts, not raw HTTP request','requestCoverage':'Model-node context and node results; provider HTTP headers are not collected'}
    emit('MODEL_REQUEST',rid,request,stamp,aid,run_id,nid)
    outputs=node.get('outputs') or {}
    if node.get('status')=='succeeded':
     response={'model':pd.get('model_name','unknown'),'choices':[{'message':{'role':'assistant','content':outputs.get('text','')}}],'usage':pd.get('usage'),'observationSource':'Dify execution API: actual node output, normalized response','rawNodeOutput':outputs}
     emit('MODEL_RESPONSE',rid,response,node.get('finished_at') or stamp,aid,run_id,nid,'200')
     reasoning=outputs.get('reasoning_content')
     if reasoning:emit('MODEL_REASONING',rid,{'reasoning':reasoning},node.get('finished_at') or stamp,aid,run_id,nid)
    else:emit('MODEL_ERROR',rid,{'type':'DifyModelNodeError','message':str(node.get('error') or '')[:1200],'workflowRunId':run_id},node.get('finished_at') or stamp,aid,run_id,nid,'FAILED')
   seen.add(run_key);observed+=1
 with STATE.open('w') as f:json.dump({'state':'ready','lastPoll':datetime.datetime.now().astimezone().isoformat(),'seen':sorted(seen),'runsThisPoll':observed},f)
 return observed

if __name__=='__main__':
 while True:
  try:print('Dify execution API poll, new runs:',poll(),flush=True)
  except Exception as e:print('Dify bridge error:',type(e).__name__,str(e)[:150],flush=True)
  time.sleep(INTERVAL)
