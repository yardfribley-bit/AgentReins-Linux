"""Adaptive persistence: preserve execution evidence; aggregate idle background noise."""
import json,os,time,threading,collections,re
class Policy:
 def __init__(self,clock=time.time):
  self.clock=clock;self.active_until=0;self.last_check=0;self.fingerprints={};self.counts=collections.Counter();self.lock=threading.Lock();self.last_flush=clock()
 def keep(self,event):
  with self.lock:
   now=self.clock();op=event.get('operation','');e=event.get('evidence') or {};cid=event.get('containerId','');text=str(event.get('resource',''))+' '+str(e.get('cmdline',''))
   if now-self.last_check>5:
    self.last_check=now
    try:
     if now-os.stat('/var/log/agentreins/semantic.jsonl').st_mtime<120:self.active_until=max(self.active_until,now+120)
    except OSError:pass
   probe=bool(re.search(r'pg_isready|healthcheck|/health(?:z|\b)|redis-cli.*\bping\b',text,re.I))
   # A concrete non-probe execution wakes detailed persistence, including its first event.
   if cid and op in ('EXEC','AUDIT_EXEC') and not probe:self.active_until=max(self.active_until,now+120)
   try:
    live=json.load(open('/var/log/agentreins/dify-live.json'))
    if live.get('errors') or now-live.get('lastPoll',0)>90:
     self.active_until=max(self.active_until,now+120)
    elif any(r.get('status') in ('running','queued') for r in live.get('runs',[])):
     self.active_until=max(self.active_until,now+120)
   except (OSError,ValueError):pass
   active=now<self.active_until
   # Always preserve process, network, audit boundary, failure and lifecycle evidence.
   internal_background=(op in ('AUDIT_CONNECT','AUDIT_SENDTO') and e.get('classification')=='PRIVATE_OR_LOCAL' and ('agentreins' in e.get('cgroup','') or event.get('process','').endswith(('/postgres','/redis-server'))))
   aggregate=(not active and internal_background and event.get('result') in ('SUCCESS','CONNECT_PENDING')) or (probe and event.get("result") not in ("FAILED","FAILED_OR_PENDING","ERROR")) or (not active and op in ('FILE_ACCESS','FILE_OPEN','FILE_MODIFY','FILE_EVENT') and not event.get('pid'))
   if aggregate:
    key=(op,cid,event.get('process',''),event.get('resource',''),event.get('result',''))
    if now-self.fingerprints.get(key,-1e20)<60:
     self.counts[op]+=1;keep=False
    else:self.fingerprints[key]=now;keep=True
   else:keep=True
   if len(self.fingerprints)>4096:self.fingerprints={k:v for k,v in self.fingerprints.items() if now-v<60}
   if now-self.last_flush>=60:
    self.last_flush=now
    status={'sampledAt':now,'mode':'active' if active else 'idle','activeUntil':self.active_until,'suppressedSinceStart':dict(self.counts),'policy':'idle background events: first sample per signature per 60s; execution/network/boundary/failure retained','rawAudit':'unchanged'}
    try:
     path='/var/log/agentreins/activity-policy-'+str(os.getpid())+'.json';tmp=path+'.tmp'
     with open(tmp,'w') as f:json.dump(status,f)
     os.replace(tmp,path)
    except OSError:pass
   return keep
policy=Policy()
