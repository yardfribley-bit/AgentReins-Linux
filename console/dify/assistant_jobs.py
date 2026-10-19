import time,uuid,threading
jobs={};lock=threading.Lock();last={};recent=[]
def submit(question,context,ip):
 now=time.time()
 with lock:
  for key in list(jobs):
   if now-jobs[key]['createdAt']>600:jobs.pop(key,None)
  recent[:]=[t for t in recent if now-t<60]
  if now-last.get(ip,0)<20 or len(recent)>=10:raise ValueError('请求较频繁，请稍后再试')
  if not isinstance(question,str) or not 1<=len(question)<=1000:raise ValueError('请输入1–1000字的问题')
  key=str(uuid.uuid4());jobs[key]={'id':key,'status':'queued','createdAt':now,'question':question,'context':context};last[ip]=now;recent.append(now);return key
def claim():
 with lock:
  for j in jobs.values():
   if j['status']=='queued':j['status']='running';return dict(j)
 return None
def finish(key,result):
 with lock:
  if key in jobs:jobs[key].update(status='finished',result=result)
def read(key):
 with lock:
  j=jobs.get(key)
  if not j:return None
  return {k:j[k] for k in ('id','status','createdAt','result') if k in j}
