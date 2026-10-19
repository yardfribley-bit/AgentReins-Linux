#!/usr/bin/env python3
"""Publish read-only Dify observation snapshots; never transfers Dify sessions."""
import json,time,urllib.request,urllib.parse,re
from pathlib import Path
local=urllib.request.build_opener(urllib.request.ProxyHandler({}))
remote=urllib.request.build_opener(urllib.request.ProxyHandler({'http':'http://127.0.0.1:10809','https':'http://127.0.0.1:10809'}))
token=Path('/etc/agentreins/dify-public-sync.token').read_text().strip()
def get(path):
 with local.open('http://127.0.0.1:8899'+path,timeout=20) as r:return json.load(r)
def clean(v):
 if isinstance(v,dict):return {k:('[REDACTED]' if re.search(r'(?i)(password|authorization|api.?key|cookie|secret|access.?token|refresh.?token)',k) else clean(x)) for k,x in v.items()}
 if isinstance(v,list):return [clean(x) for x in v]
 if isinstance(v,str):return re.sub(r'(?i)Bearer\s+\S+','Bearer [REDACTED]',v)
 return v
while True:
 try:
  journeys=[]
  for j in get('/api/journeys').get('journeys',[])[:40]:
   details=get('/api/journeys?id='+urllib.parse.quote(j['id'])).get('journeys',[])
   for detail in details:
    trace=(detail.get('request') or {}).get('workflowTrace') or {}
    if trace.get('appId'):journeys.append(detail)
  cockpit=get('/api/cockpit?q=');cockpit['actions']=cockpit.get('actions',[])[:40];actions={}
  for action in cockpit['actions']:
   try:actions[action['id']]=get('/api/cockpit?id='+urllib.parse.quote(action['id']))
   except Exception:continue
  live={}
  executors={}
  try:live=json.loads(Path('/var/log/agentreins/dify-live.json').read_text())
  except (OSError,ValueError):pass
  try:executors=json.loads(Path('/var/log/agentreins/executor-live.json').read_text())
  except (OSError,ValueError):pass
  payload=clean({'sourceUpdatedAt':time.time(),'journeys':journeys,'cockpit':cockpit,'actions':actions,'live':live,'executors':executors})
  req=urllib.request.Request('https://www.agentreins.info/dify/_ingest',json.dumps(payload,ensure_ascii=False).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+token})
  with remote.open(req,timeout=30) as r:print('Published Dify snapshot',r.status,'journeys',len(journeys),'actions',len(actions),flush=True)
 except Exception as e:print('Dify publish error',type(e).__name__,str(e)[:120],flush=True)
 time.sleep(10)
