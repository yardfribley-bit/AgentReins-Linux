import datetime,json,shlex

def stamp(value):
 try:return datetime.datetime.fromisoformat(value).timestamp()
 except (ValueError,TypeError):return 0

def build(events,semantic):
 calls={};results={}
 for row in semantic:
  try:payload=json.loads(row['resource'])
  except (ValueError,TypeError):continue
  if row['operation']=='TOOL_CALL':
   key=payload.get('id')
   if key:
    calls[key]={'id':key,'name':payload.get('function',{}).get('name','unknown'),'arguments':payload.get('function',{}).get('arguments',''),'requestId':row.get('requestId'),'time':row['time'],'peer':row.get('identity'),'result':None}
  if row['operation']=='TOOL_RESULT' and payload.get('tool_call_id'):results[payload['tool_call_id']]=payload
 chains=[]
 for key,call in list(calls.items())[-40:]:
  call['result']=results.get(key)
  try:args=json.loads(call['arguments'])
  except (ValueError,TypeError):args={}
  commands=[]
  def find(value):
   if isinstance(value,dict):
    for k,v in value.items():
     if k.lower() in ('command','cmd','shell_command','script','code','input') and isinstance(v,str):commands.append(v)
     elif isinstance(v,(dict,list)):find(v)
   elif isinstance(value,list):
    for v in value:find(v)
  find(args)
  start=stamp(call['time']);window=[r for r in events if start-2<=stamp(r['time'])<=start+300 and r['category']!='semantic']
  matched=[]
  for row in window:
   if row['operation'] not in ('EXEC','AUDIT_EXEC'):continue
   resource=row.get('resource','')
   if any(len(cmd.strip())>=4 and cmd.strip() in resource for cmd in commands):matched.append(row)
  pids={r['pid'] for r in matched if r.get('pid')}
  descendants=set(pids)
  for _ in range(8):
   before=len(descendants)
   descendants.update(r['pid'] for r in window if r.get('ppid') in descendants and r.get('pid'))
   if len(descendants)==before:break
  linked=[r for r in window if r.get('pid') in descendants]
  def unique(rows):
   result=[];seen=set()
   for r in rows:
    key=(r.get('eventKey') or str(r))
    if key not in seen:result.append(r);seen.add(key)
   return result[-100:]
  call.update(commandIntent=commands,commands=unique([r for r in linked if r['operation'] in ('EXEC','AUDIT_EXEC')]),network=unique([r for r in linked if r['category']=='network']),kernel=unique([r for r in linked if r['category'] in ('kernel','sandbox') and r['operation'] not in ('EXEC','AUDIT_EXEC')]),association='COMMAND_AND_TIME_CANDIDATE' if matched else 'NO_EXECUTION_LINK',associationNote='命令文本与时间窗口匹配，再关联进程后代；没有执行器传播的工具 ID，不能确认唯一归属。' if matched else '尚无可验证的命令关联。模型生成调用不等于工具已执行。',candidateCount=len(window))
  chains.append(call)
 return chains[::-1]

def journeys(events,semantic):
 tools={t['id']:t for t in build(events,semantic)}
 groups={}
 for row in semantic:
  rid=row.get('requestId')
  if not rid:continue
  group=groups.setdefault(rid,{'id':rid,'time':row['time'],'client':row.get('identity'),'request':None,'response':None,'reasoning':[],'tools':[],'previousTools':[],'error':None})
  try:data=json.loads(row['resource'])
  except (ValueError,TypeError):continue
  op=row['operation']
  if op=='MODEL_REQUEST':
   group['request']=data
   group['previousTools']=[m.get('tool_call_id') for m in data.get('messages',[]) if m.get('role')=='tool']
  elif op=='MODEL_RESPONSE':group['response']=data
  elif op=='MODEL_REASONING':group['reasoning'].append(data)
  elif op=='TOOL_CALL' and data.get('id') in tools:group['tools'].append(tools[data['id']])
  elif op in ('MODEL_ERROR','MODEL_INTERRUPTED'):group['error']=data
 result=[]
 for group in groups.values():
  if not group['request']:continue
  text=json.dumps(group['request'],ensure_ascii=False).lower()
  group['isTest']=any(s in text for s in ('acceptance test','observability connectivity check','monitoring acceptance','monitoring verification'))
  group['model']=group['request'].get('model','unknown')
  group['status']='模型已返回' if group['response'] else ('交互中断' if group['error'] else '等待模型响应')
  group['previousInteractions']=list({t['requestId'] for key,t in tools.items() if key in group['previousTools']})
  result.append(group)
 return sorted(result,key=lambda r:r['time'],reverse=True)[:40]
