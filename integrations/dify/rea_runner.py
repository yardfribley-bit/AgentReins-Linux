"""Fixed-scope REA adapter for Dify; target is a public frontend snapshot only."""
import datetime,hashlib,json,re,subprocess,threading,time,uuid,sys
sys.path.insert(0,"/opt/agentreins-runtime")
from gate_client import Client,GateDenied
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
ROOT=Path('/home/smith/agentreins-rea');TARGET=ROOT/'target';RUNS=ROOT/'runs';RUNS.mkdir(exist_ok=True)
NODE=ROOT/'node-v24.11.0-linux-x64';PACKAGE=ROOT/'package';CLI='/package/node_modules/rea-agents/scripts/rea.mjs';lock=threading.Lock()
def live(rid,status,**values):
 state={'runId':rid,'status':status,'updatedAt':time.time(),**values};p=Path('/var/log/agentreins/executor-live.json')
 try:items=json.loads(p.read_text())
 except (OSError,ValueError):items={}
 items[rid]=state;tmp=p.with_suffix('.new');tmp.write_text(json.dumps(dict(list(items.items())[-100:])));tmp.replace(p)
 event={'time':datetime.datetime.now().astimezone().isoformat(),'category':'semantic','operation':'EXECUTION_'+status.upper(),'component':'REAExecutor','process':'rea-runner','resource':json.dumps(state),'result':status,'evidence':{'executionId':rid,'traceId':values.get('traceId'),'attribution':'EXECUTOR_RUNTIME_ID'}}
 with Path('/var/log/agentreins/host.jsonl').open('a') as f:f.write(json.dumps(event)+'\n')
def analyze():
 rid=str(uuid.uuid4());trace=uuid.uuid4().hex;out=RUNS/rid;out.mkdir();name='dify-rea-'+rid[:8];started=time.time();cid='';pid=0
 args=['/runtime/bin/node','--max-old-space-size=1024',CLI,'analyze-javascript-application','/target','--source-path','frontend.js','--max-heap-mb','256','--analysis-timeout-ms','60000','--format','json']
 cmd=['docker','create','--name',name,'--network','none','--read-only','--cap-drop=ALL','--security-opt','no-new-privileges','--pids-limit','64','--memory','1536m','--cpus','1','--user','65534:65534','--tmpfs','/tmp:rw,nosuid,size=256m','-e','HOME=/tmp','-e','PATH=/runtime/bin:/usr/bin:/bin','--label','agentreins.workload=dify-rea','--label','agentreins.execution_id='+rid,'--label','agentreins.trace_id='+trace,'-v',str(NODE)+':/runtime:ro','-v',str(PACKAGE)+':/package:ro','-v',str(TARGET)+':/target:ro','--entrypoint',args[0],'vxcontrol/kali-linux:latest',*args[1:]]
 live(rid,'awaiting_approval',traceId=trace,container=name)
 gate=None
 try:
  client=Client();target_hash=hashlib.sha256((TARGET/'index.html').read_bytes()).hexdigest()
  gate=client.authorize('rea_analyze_frontend',{'argv':cmd,'target_sha256':target_hash},rid,workload='dify-rea',timeout=90,on_pending=lambda g:live(rid,'awaiting_approval',traceId=trace,gateId=g['id'],alertId=g['alertId'],deadline=g['deadline']))
  if hashlib.sha256((TARGET/'index.html').read_bytes()).hexdigest()!=target_hash:raise GateDenied('目标快照已改变，必须重新审批')
  live(rid,'starting',traceId=trace,container=name,gateId=gate['id'])
  cid=subprocess.check_output(cmd,text=True,timeout=30).strip();process=subprocess.Popen(['docker','start','-a',cid],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);time.sleep(.3);ins=json.loads(subprocess.check_output(['docker','inspect',cid],text=True))[0];pid=ins['State']['Pid'];command=' '.join(args);live(rid,'running',traceId=trace,container=name,containerId=cid,pid=pid,command=command)
  stdout,stderr=process.communicate(timeout=100);exitcode=json.loads(subprocess.check_output(['docker','inspect',cid],text=True))[0]['State']['ExitCode'];(out/'rea-evidence.json').write_text(stdout);(out/'stderr.txt').write_text(stderr)
  try:evidence=json.loads(stdout)
  except ValueError:evidence={'parseError':True,'rawPreview':stdout[:2000]}
  result={'run_id':rid,'trace_id':trace,'container_id':cid,'container':name,'host_pid':pid,'command':command,'exit_code':exitcode,'elapsed_seconds':round(time.time()-started,3),'executor':'REA static JavaScript analysis in network-disabled Docker container','rea_version':'6.5.0','target_sha256':hashlib.sha256((TARGET/'index.html').read_bytes()).hexdigest(),'files':[str(out/'rea-evidence.json')],'evidence_top_keys':list(evidence) if isinstance(evidence,dict) else [],'rea_evidence_preview':json.dumps(evidence,ensure_ascii=False)[:14000],'stderr':stderr[-1500:],'isolation':{k:ins['HostConfig'].get(k) for k in ['ReadonlyRootfs','Privileged','CapDrop','SecurityOpt','Memory','NanoCpus','PidsLimit','NetworkMode']},'limitations':['Static analysis of a frozen public frontend copy; no browser/network execution','Extracted inline script keeps its original text; frontend.js line references differ from index.html','REA raw evidence saved without truncation; response preview is bounded']}
 except Exception as e:result={'run_id':rid,'trace_id':trace,'container_id':cid,'host_pid':pid,'exit_code':125,'error':type(e).__name__+': '+str(e)[:300]}
 finally:
  if cid:subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=30)
 if gate:
  try:client.complete(gate,result['exit_code'],executionId=rid,containerId=cid,pid=pid,traceId=trace)
  except Exception:result['approval_reporting']='execution completed; result synchronization unavailable'
 (out/'report.json').write_text(json.dumps(result,ensure_ascii=False,indent=2));live(rid,'finished' if result['exit_code']==0 else 'failed',traceId=trace,container=name,containerId=cid,pid=pid,exitCode=result['exit_code'],files=result.get('files',[]),command=result.get('command'))
 return result
SYMBOLS=['search','searchView','searchGuide','get','askAssistant','render','taskFiles','selectTask','bindFlight']
def source(symbol):
 if symbol not in SYMBOLS:raise ValueError('Unknown symbol; allowed: '+', '.join(SYMBOLS))
 text=(TARGET/'frontend.js').read_text();m=re.search(r'\b(?:async )?function '+re.escape(symbol)+r'\(',text)
 if not m:raise ValueError('Symbol not found')
 end=re.search(r'\b(?:async )?function \w+\(',text[m.end():]);stop=m.end()+end.start() if end else len(text);raw=text[m.start():stop];line=text[:m.start()].count('\n')+1
 return {'source':'Adapter exact source excerpt, not an REA inference','file':'frontend.js','symbol':symbol,'start_line':line,'end_line':line+raw.count('\n'),'start_offset':m.start(),'source_sha256':hashlib.sha256(text.encode()).hexdigest(),'code':raw[:16000],'truncated':len(raw)>16000}
class H(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_POST(self):
  try:
   n=int(self.headers.get('Content-Length','0'))
   if not 0<=n<=70000:raise ValueError('Invalid request length')
   data=json.loads(self.rfile.read(n) or b'{}')
   if self.path=='/analyze':
    if not lock.acquire(False):raise ValueError('Analysis busy')
    try:result=analyze()
    finally:lock.release()
   elif self.path=='/source':result=source(data.get('symbol',''))
   elif self.path=='/report':
    rid=data.get('run_id','');assert re.fullmatch(r'[a-f0-9-]{36}',rid) and (RUNS/rid/'report.json').is_file();body=data.get('markdown','');assert isinstance(body,str) and 20<len(body)<60000;p=RUNS/rid/'report.md';assert not p.exists();p.write_text(body);result={'run_id':rid,'file':str(p),'size':p.stat().st_size,'source':'Dify Agent authored report based on tool evidence'}
   else:raise ValueError('Unknown operation')
   body=json.dumps(result,ensure_ascii=False).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  except Exception as e:
   body=json.dumps({'error':str(e)[:300]}).encode();self.send_response(400);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
ThreadingHTTPServer(('172.18.0.1',18911),H).serve_forever()
