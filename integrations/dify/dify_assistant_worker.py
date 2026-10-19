import json,time,urllib.request,runpy
from pathlib import Path
TOKEN=Path('/etc/agentreins/dify-public-sync.token').read_text().strip();CONFIG=json.loads(Path('/etc/agentreins/search-assistant.json').read_text())
op=urllib.request.build_opener(urllib.request.ProxyHandler({'https':'http://127.0.0.1:10809'}))
def remote(path,data=None):
 req=urllib.request.Request('https://www.agentreins.info'+path,data=json.dumps(data).encode() if data is not None else None,headers={'Content-Type':'application/json','Authorization':'Bearer '+TOKEN})
 with op.open(req,timeout=15) as r:return json.load(r)
while True:
 job=None
 try:
  job=remote('/dify/_assistant/jobs').get('job')
  if job:
   m=runpy.run_path('/opt/agentreins/dify_api_bridge.py');call=m['call'];aid=CONFIG['appId'];info=call('/console/api/apps/'+aid)
   query=json.dumps({'question':job['question'],'evidence':job.get('context',[])},ensure_ascii=False)
   result=call('/console/api/apps/'+aid+'/chat-messages',{'inputs':{},'query':query,'model_config':info['model_config'],'response_mode':'blocking','files':[]})
   answer=result.get('answer','').strip();answer=answer.removeprefix('```json').removeprefix('```').removesuffix('```').strip();parsed=json.loads(answer)
   assert isinstance(parsed.get('query'),str) and isinstance(parsed.get('explanation'),str)
   remote('/dify/_assistant/result',{'id':job['id'],'result':{'query':parsed['query'][:2000],'explanation':parsed['explanation'][:4000],'limitations':parsed.get('limitations',[]),'model':info['model_config']['model']['name'],'source':'Dify read-only model assistant; validate query before applying'}})
 except Exception as e:
  print(type(e).__name__,str(e)[:160],flush=True)
  if job:
   try:remote('/dify/_assistant/result',{'id':job['id'],'result':{'error':type(e).__name__+': '+str(e)[:200]}})
   except Exception:pass
 time.sleep(3)
