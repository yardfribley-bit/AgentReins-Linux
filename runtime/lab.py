#!/usr/bin/env python3
"""Non-destructive acceptance lab on this host. No arbitrary command or target input."""
import argparse,contextlib,http.server,json,os,subprocess,threading,time,uuid
from pathlib import Path
from gate_client import Client,GateDenied
BASE=Path('/var/lib/agentreins-runtime/lab')
def register(run_id):
 ticks=Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]
 Path('/var/lib/agentreins-runtime/lab-identity.json').write_text(json.dumps({'pid':os.getpid(),'startTicks':ticks,'runId':run_id}))
def detection():
 rid='lab-'+uuid.uuid4().hex;register(rid);time.sleep(1)
 class Handler(http.server.BaseHTTPRequestHandler):
  def log_message(self,*a):pass
  def do_GET(self):
   data=b'#!/bin/sh\nprintf "downloaded benign lab payload ran\\n" > /var/lib/agentreins-runtime/lab/download-executed.txt\n';self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
 server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start();out=BASE/'downloaded.sh'
 results=[]
 for argv in [['/bin/cat',str(BASE/'.env')],['/usr/bin/curl','-fsS','http://127.0.0.1:'+str(server.server_port)+'/benign.sh','-o',str(out)],['/bin/sh',str(out)],['/bin/sh','-c','true']]:
  p=subprocess.run(argv,capture_output=True,text=True,timeout=10);results.append({'argv':argv,'exitCode':p.returncode});time.sleep(2)
 server.shutdown();time.sleep(60);print(json.dumps({'runId':rid,'commands':results,'markerExists':(BASE/'download-executed.txt').exists(),'note':'受控实验：读取假凭据、访问本机 HTTP、执行无害脚本；不是客户业务攻击'},ensure_ascii=False))
def gate_case(case):
 rid='lab-gate-'+uuid.uuid4().hex;register(rid);marker=BASE/(rid+'.txt');client=Client();argv=['/usr/bin/touch',str(marker)]
 def pending(g):
  (BASE/(case+'-pending.json')).write_text(json.dumps({'gateId':g['id'],'alertId':g['alertId'],'runId':rid,'marker':str(marker)}))
 try:
  g=client.authorize('runtime_lab_command',{'argv':argv},rid,workload='runtime-lab',timeout=60,on_pending=pending)
  p=subprocess.run(argv,timeout=5);client.complete(g,p.returncode,runId=rid,marker=str(marker),markerExists=marker.exists());result={'runId':rid,'status':'executed','markerExists':marker.exists()}
 except GateDenied as e:result={'runId':rid,'status':'not_executed','markerExists':marker.exists(),'reason':str(e)}
 (BASE/(case+'-result.json')).write_text(json.dumps(result));print(json.dumps(result,ensure_ascii=False));time.sleep(3)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('case',choices=['detect','allow','deny','expire']);a=p.parse_args()
 BASE.mkdir(parents=True,exist_ok=True)
 if a.case=='detect':detection()
 else:gate_case(a.case)
