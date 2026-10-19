#!/usr/bin/env python3
"""Observe current Dify API state; never claims provider-token streaming."""
import runpy,json,time,hashlib,datetime,os
from pathlib import Path
m=runpy.run_path('/opt/agentreins/dify_api_bridge.py');call=m['call'];clean=m['clean'];OUT=Path('/var/log/agentreins/dify-live.json');LOG=Path('/var/log/agentreins/host.jsonl');cache={};history={}
def event(key,state):
 digest=hashlib.sha256(json.dumps(state,sort_keys=True,default=str).encode()).hexdigest()
 if cache.get(key)==digest:return
 cache[key]=digest
 row={'time':datetime.datetime.now().astimezone().isoformat(),'category':'semantic','operation':'DIFY_EXECUTION_STATE','component':'DifyLiveObserver','process':'dify-api','resource':json.dumps(clean(state),ensure_ascii=False),'result':state['status'],'eventKey':hashlib.sha256((key+digest).encode()).hexdigest(),'evidence':{'appId':state['appId'],'workflowRunId':state['runId'],'attribution':'DIRECT_API_STATE'}}
 with LOG.open('a') as f:f.write(json.dumps(row,ensure_ascii=False)+'\n')
 history[key]=state
while True:
 started=time.time();errors=[];current=[]
 try:
  apps=[];page=1
  while True:
   d=call('/console/api/apps?page='+str(page)+'&limit=100');apps+=d.get('data',[])
   if not d.get('has_more'):break
   page+=1
  for app in apps:
   aid=app['id']
   try:
    if app['mode'] in ('workflow','advanced-chat'):
     runs=call('/console/api/apps/'+aid+'/workflow-runs?page=1&limit=20').get('data',[])
     for run in runs:
      if time.time()-(run.get('created_at') or 0)>3600:continue
      rid=run['id'];nodes=call('/console/api/apps/'+aid+'/workflow-runs/'+rid+'/node-executions').get('data',[])
      state={'appId':aid,'appName':app['name'],'runId':rid,'kind':'workflow','status':run['status'],'nodes':[{'id':n.get('node_id'),'type':n.get('node_type'),'title':n.get('title'),'status':n.get('status'),'start':n.get('created_at'),'end':n.get('finished_at'),'elapsed':n.get('elapsed_time'),'error':n.get('error')} for n in nodes]};event(rid,state);current.append(state)
    elif app['mode']=='agent-chat':
     conversations=call('/console/api/apps/'+aid+'/chat-conversations?page=1&limit=20').get('data',[])
     for conv in conversations:
      if time.time()-(conv.get('updated_at') or 0)>3600:continue
      for msg in call('/console/api/apps/'+aid+'/chat-messages?conversation_id='+conv['id']+'&limit=10').get('data',[]):
       if time.time()-(msg.get('created_at') or 0)>3600:continue
       state={'appId':aid,'appName':app['name'],'runId':msg['id'],'conversationId':conv['id'],'kind':'agent','status':'failed' if msg.get('error') else ('finished' if msg.get('answer') else 'running'),'query':msg.get('query'),'error':msg.get('error'),'tools':[{'id':t.get('id'),'position':t.get('position'),'name':t.get('tool'),'input':t.get('tool_input'),'hasResult':bool(t.get('observation'))} for t in msg.get('agent_thoughts',[]) if t.get('tool')]};event(msg['id'],state);current.append(state)
   except Exception as e:errors.append({'appId':aid,'type':type(e).__name__,'message':str(e)[:150]})
 except Exception as e:errors.append({'type':type(e).__name__,'message':str(e)[:150]})
 state={'lastPoll':time.time(),'pollElapsed':round(time.time()-started,3),'pollInterval':3,'source':'Dify execution API polling; not token streaming','runs':clean(current),'errors':errors}
 temp=OUT.with_suffix('.new');temp.write_text(json.dumps(state,ensure_ascii=False));temp.replace(OUT)
 time.sleep(max(0.1,3-(time.time()-started)))
