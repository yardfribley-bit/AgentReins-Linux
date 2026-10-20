"""Execution-boundary client. Fail closed; never retries command execution."""
import hashlib,json,time,urllib.request,urllib.error,uuid
from pathlib import Path
class GateDenied(RuntimeError):pass
class Client:
 def __init__(self,config='/etc/agentreins-runtime/sensor.json'):
  self.config=json.loads(Path(config).read_text());self.base=self.config['url'].rstrip('/');self.token=self.config['token'];self.http=urllib.request.build_opener(urllib.request.ProxyHandler(self.config.get('proxies',{})))
 def call(self,path,body=None):
  request=urllib.request.Request(self.base+'/api/'+path,json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json','Authorization':'Bearer '+self.token})
  try:
   with self.http.open(request,timeout=12) as response:return json.load(response)
  except urllib.error.HTTPError as e:
   try:msg=json.load(e).get('error','审批服务拒绝请求')
   except Exception:msg='审批服务拒绝请求'
   raise GateDenied(msg) from None
 def authorize(self,tool,arguments,run_id,workload='dify-rea',timeout=90,on_pending=None):
  binding={'tool':tool,'arguments':arguments,'runId':run_id,'workload':workload};hash_=hashlib.sha256(json.dumps(binding,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest();g=self.call('gates',{'requestKey':uuid.uuid4().hex,**binding,'timeout':timeout})
  if on_pending:on_pending(g)
  start=time.monotonic()
  while time.monotonic()-start<timeout+5:
   if g['status']=='approved':
    self.call('gates/'+g['id']+'/claim',{'hash':hash_});return g
   if g['status']!='pending':raise GateDenied('工具未执行：'+g['status']+' · '+g['id'])
   time.sleep(1);g=self.call('gates/'+g['id'])
  raise GateDenied('工具未执行：审批等待超时')
 def complete(self,gate,exit_code,**evidence):return self.call('gates/'+gate['id']+'/complete',{'exitCode':exit_code,**evidence})
