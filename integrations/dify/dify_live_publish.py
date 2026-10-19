#!/usr/bin/env python3
import json,time,urllib.request
from pathlib import Path
op=urllib.request.build_opener(urllib.request.ProxyHandler({'http':'http://127.0.0.1:10809','https':'http://127.0.0.1:10809'}))
token=Path('/etc/agentreins/dify-public-sync.token').read_text().strip()
while True:
 try:
  live=json.loads(Path('/var/log/agentreins/dify-live.json').read_text())
  try:executors=json.loads(Path('/var/log/agentreins/executor-live.json').read_text())
  except (OSError,ValueError):executors={}
  try:platform=json.loads(Path('/var/log/agentreins/dify-platform.json').read_text())
  except (OSError,ValueError):platform={}
  body=json.dumps({'live':live,'executors':executors,'platform':platform},ensure_ascii=False).encode()
  req=urllib.request.Request('https://www.agentreins.info/dify/_live',body,headers={'Content-Type':'application/json','Authorization':'Bearer '+token})
  with op.open(req,timeout=8) as r:r.read()
 except Exception as e:print(type(e).__name__,str(e)[:150],flush=True)
 time.sleep(2)
