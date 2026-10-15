#!/usr/bin/env python3
"""OpenAI-compatible observation gateway. No credential persistence."""
import time,datetime,hashlib,json,os,re,threading,urllib.request,urllib.error,uuid
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
UPSTREAM=os.environ.get('AGENTREINS_UPSTREAM','https://api.openai.com/v1').rstrip('/')
OUT='/var/log/agentreins/host.jsonl'
LOCK=threading.Lock()
def clean(value):
 if isinstance(value,dict):return {k:('[REDACTED]' if re.search(r'(?i)^(authorization|api[_-]?key|password|token|secret|cookie)$',k) else clean(v)) for k,v in value.items()}
 if isinstance(value,list):return [clean(v) for v in value]
 if isinstance(value,str):
  value=re.sub(r'(?i)((?:password|token|secret|api[_-]?key)\s*[=:]\s*)[^\s"\']+',r'\1[REDACTED]',value)
  value=re.sub(r'(?i)(Bearer\s+)\S+',r'\1[REDACTED]',value)
  value=re.sub(r'(https?://[^\s/:]+:)[^@/\s]+@',r'\1[REDACTED]@',value)
 return value
def emit(op,request_id,data,peer,result='CAPTURED'):
 event={'time':datetime.datetime.now().astimezone().isoformat(),'component':'SemanticGateway','category':'semantic','operation':op,'process':'model-gateway','pid':os.getpid(),'ppid':os.getppid(),'containerId':'','container':'','resource':json.dumps(clean(data),ensure_ascii=False),'result':result,'source':'OpenAI-compatible application boundary','evidence':{'requestId':request_id,'peer':peer,'upstream':UPSTREAM,'attribution':'CLIENT_CONNECTION'},'data':json.dumps({'requestId':request_id,'peer':peer})}
 event['eventKey']=hashlib.sha256((request_id+op+event['time']+event['resource']).encode()).hexdigest()
 with LOCK:
  for path in (OUT,'/var/log/agentreins/semantic.jsonl'):
   with open(path,'a') as f:f.write(json.dumps(event,ensure_ascii=False)+'\n')
class Handler(BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def do_GET(self):self.forward()
 def do_POST(self):self.forward()
 def forward(self):
  rid=uuid.uuid4().hex;peer=self.client_address[0];body=b'';phase='request';started=time.monotonic()
  try:
   size=int(self.headers.get('Content-Length','0'))
   if size>32*1024*1024:self.send_error(413);return
   if size:body=self.rfile.read(size)
   payload={}
   if body:
    try:payload=json.loads(body)
    except ValueError:pass
   path=self.path
   if not path.startswith('/v1/') or '..' in path:self.send_error(404);return
   if payload:
    emit('MODEL_REQUEST',rid,{'path':path,**payload},peer)
    for message in payload.get('messages',[]):
     if message.get('role')=='tool':emit('TOOL_RESULT',rid,message,peer)
   headers={k:v for k,v in self.headers.items() if k.lower() not in ('host','connection','content-length','accept-encoding','transfer-encoding')}
   request=urllib.request.Request(UPSTREAM+path[3:],data=body if self.command=='POST' else None,headers=headers,method=self.command)
   phase='upstream_connect'
   try:response=urllib.request.urlopen(request,timeout=660)
   except urllib.error.HTTPError as e:response=e
   if 'text/event-stream' not in response.headers.get('Content-Type',''):
    phase='upstream_read'
    raw_body=response.read();status=response.status;ctype=response.headers.get('Content-Type','application/json');response.close()
    phase='downstream_write'
    self.send_response(status);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(raw_body)));self.send_header('Connection','close');self.end_headers();self.close_connection=True
    self.wfile.write(raw_body);self.wfile.flush()
    if self.command=='POST':
     try:decoded=json.loads(raw_body)
     except ValueError:decoded={'non_json_response':True,'bytes':len(raw_body)}
     emit('MODEL_RESPONSE',rid,decoded,peer,str(status))
     for choice in decoded.get('choices',[]):
      message=choice.get('message') or {}
      for tool in message.get('tool_calls',[]):emit('TOOL_CALL',rid,tool,peer)
      reasoning=message.get('reasoning_content') or message.get('reasoning')
      if reasoning:emit('MODEL_REASONING',rid,{'reasoning':reasoning},peer)
    return
   self.send_response(response.status)
   self.send_header('Content-Type',response.headers.get('Content-Type','application/json'))
   self.send_header('Connection','close');self.end_headers();self.close_connection=True
   sse='text/event-stream' in response.headers.get('Content-Type','')
   full=bytearray();choices={};usage=None
   while True:
    chunk=response.readline() if sse else response.read(65536)
    if not chunk:break
    self.wfile.write(chunk);self.wfile.flush()
    if not sse:full.extend(chunk);continue
    if chunk.startswith(b'data:'):
     try:part=json.loads(chunk[5:].strip())
     except ValueError:continue
     if part.get('usage'):usage=part['usage']
     for choice in part.get('choices',[]):
      state=choices.setdefault(choice.get('index',0),{'content':'','reasoning_content':'','tool_calls':{}})
      delta=choice.get('delta') or choice.get('message') or {}
      for field in ('content','reasoning_content','reasoning'):
       if isinstance(delta.get(field),str):state[field]=state.get(field,'')+delta[field]
      for tool in delta.get('tool_calls',[]):
       target=state['tool_calls'].setdefault(tool.get('index',0),{'id':'','type':'function','function':{'name':'','arguments':''}})
       if tool.get('id'):target['id']=tool['id']
       for key in ('name','arguments'):target['function'][key]+=tool.get('function',{}).get(key,'')
   response.close()
   if sse:
    decoded={'choices':[{'index':index,'message':{**value,'tool_calls':list(value['tool_calls'].values())}} for index,value in choices.items()],'usage':usage,'stream':True}
   else:
    try:decoded=json.loads(full)
    except ValueError:decoded={'non_json_response':True,'bytes':len(full)}
   if self.command=='POST':
    emit('MODEL_RESPONSE',rid,decoded,peer,str(response.status))
    for choice in decoded.get('choices',[]):
     message=choice.get('message') or {}
     for tool in message.get('tool_calls',[]):emit('TOOL_CALL',rid,tool,peer)
     reasoning=message.get('reasoning_content') or message.get('reasoning')
     if reasoning:emit('MODEL_REASONING',rid,{'reasoning':reasoning},peer)
  except (BrokenPipeError,ConnectionResetError) as e:
   emit('MODEL_INTERRUPTED',rid,{'reason':'connection interrupted','phase':phase,'elapsed':round(time.monotonic()-started,2),'type':type(e).__name__},peer,'PARTIAL')
   self.close_connection=True
   if phase.startswith('upstream'):
    try:self.send_error(502,'Upstream connection interrupted')
    except OSError:pass
  except Exception as e:
   emit('MODEL_ERROR',rid,{'type':type(e).__name__,'phase':phase,'elapsed':round(time.monotonic()-started,2)},peer,'FAILED')
   try:self.send_error(502,'Model gateway upstream failure')
   except OSError:pass
 def log_message(self,*args):pass
if __name__=='__main__':ThreadingHTTPServer((os.environ.get('AGENTREINS_BIND','127.0.0.1'),int(os.environ.get('AGENTREINS_GATEWAY_PORT','18900'))),Handler).serve_forever()
