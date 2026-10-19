#!/usr/bin/env python3
import json,time,subprocess,os,shutil
from pathlib import Path
from platform_metrics import metrics
OUT=Path('/var/log/agentreins/dify-platform.json');previous=None;trend=[]
def run(args):
 r=subprocess.run(args,capture_output=True,text=True,timeout=12)
 if r.returncode:raise RuntimeError(r.stderr.strip()[:120])
 return r.stdout
mapping={'dify-web-1':'Web','dify-nginx-1':'Nginx','dify-api-1':'API','dify-worker-1':'Worker','dify-worker_beat-1':'Worker beat','dify-agent_backend-1':'Agent backend','dify-plugin_daemon-1':'Plugin daemon','dify-sandbox-1':'Sandbox','dify-local_sandbox-1':'Local sandbox','dify-redis-1':'Redis','dify-pgvector-1':'PostgreSQL','dify-ssrf_proxy-1':'SSRF proxy','dify-agent_ssrf_proxy-1':'Agent proxy'}
while True:
 errors=[];services=[];cpu=None
 try:
  ids=run(['docker','ps','-aq','--filter','label=com.docker.compose.project=dify']).split()
  for c in json.loads(run(['docker','inspect']+ids)) if ids else []:
   name=c['Name'].lstrip('/')
   if name not in mapping:continue
   state=c['State'];services.append({'name':mapping[name],'containerName':name,'containerId':c['Id'],'state':state['Status'],'health':state.get('Health',{}).get('Status'),'pid':state.get('Pid'),'oomKilled':state.get('OOMKilled'),'exitCode':state.get('ExitCode'),'restartCount':c.get('RestartCount'),'startedAt':state.get('StartedAt'),'image':c['Config']['Image'],'isolation':{k:c['HostConfig'].get(k) for k in ['ReadonlyRootfs','Privileged','CapDrop','SecurityOpt','Memory','NanoCpus','PidsLimit','NetworkMode']}})
 except Exception as e:errors.append({'source':'docker','error':str(e)[:120]})
 try:
  parts=list(map(int,Path('/proc/stat').read_text().splitlines()[0].split()[1:]));sample=(sum(parts[:8]),parts[3]+parts[4])
  if previous and sample[0]>previous[0]:cpu=round(100*(1-(sample[1]-previous[1])/(sample[0]-previous[0])),1)
  previous=sample;mem={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines()};disk=shutil.disk_usage('/');resources={'cpuPercent':cpu,'load':os.getloadavg(),'memoryTotal':mem['MemTotal'],'memoryAvailable':mem['MemAvailable'],'diskTotal':disk.total,'diskFree':disk.free,'diskUsed':disk.used}
 except Exception as e:resources={};errors.append({'source':'resources','error':str(e)[:120]})
 try:audit=dict(line.split(None,1) for line in run(['/sbin/auditctl','-s']).splitlines() if ' ' in line)
 except Exception as e:audit={'error':str(e)[:120]}
 try:audit['logUpdatedAt']=Path('/var/log/audit/audit.log').stat().st_mtime
 except OSError:pass
 collectors={}
 for name in ['agentreins-host-stream','agentreins-audit-bridge','agentreins-dify-api-bridge','agentreins-dify-live','agentreins-dify-public-sync']:
  try:collectors[name]=subprocess.run(['systemctl','is-active',name],capture_output=True,text=True,timeout=3).stdout.strip()
  except Exception:collectors[name]='unknown'
 try:live=json.loads(Path('/var/log/agentreins/dify-live.json').read_text())
 except (OSError,ValueError):live={}
 running=sum(x.get('status') in ('running','pending') for x in live.get('runs',[]));failed=sum(x.get('status') in ('failed','stopped') for x in live.get('runs',[]));trend.append({'time':time.time(),'running':running,'failed':failed});trend=trend[-60:]
 state={'dependencyMetrics':metrics(run),'sampledAt':time.time(),'services':services,'resources':resources,'audit':audit,'collectors':collectors,'errors':errors,'taskCounts':{'running':running,'failed':failed,'queued':None,'scope':'Dify API recent one-hour observation window'},'trend':trend,'knownGaps':[{'from':'2026-10-16T17:21:44+08:00','to':'2026-10-16T19:16:40+08:00','source':'Linux audit','reason':'磁盘不足暂停落盘，已恢复，期间证据不可补造'}]}
 tmp=OUT.with_suffix('.new');tmp.write_text(json.dumps(state,ensure_ascii=False));tmp.replace(OUT);time.sleep(10)
