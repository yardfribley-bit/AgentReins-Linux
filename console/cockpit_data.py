import datetime,json,os,re,subprocess,shlex
import history_store as h

def summary(params):
 h.init();c=h.connect();q=params.get('q',[''])[0].strip();ids=workload_ids();args=list(ids);where="container IN ("+','.join('?' for _ in ids)+") AND operation IN ('EXEC','AUDIT_EXEC')"
 where+=" AND process NOT IN ('/bin/sh','/bin/bash','/bin/dash','/usr/bin/sleep','/usr/bin/cat','/usr/bin/head','/usr/bin/tail','/usr/bin/which','/usr/bin/date','/usr/bin/echo','/usr/bin/find','/usr/bin/ls','/usr/bin/id','/usr/bin/timeout','runc','/usr/bin/runc') AND process NOT LIKE '%runc%'"
 if q:where+=' AND resource LIKE ?';args.append('%'+q+'%')
 rows=c.execute('SELECT time,pid,container,process,resource FROM events WHERE '+where+' ORDER BY time DESC LIMIT 100',args).fetchall();items=[];seen=set()
 for ts,pid,cid,process,command in rows:
  key=(pid,ts[:19])
  if key in seen:continue
  seen.add(key)
  if not command:continue
  if os.path.basename(process) in ('sh','bash','dash','sleep','cat','head','tail','which','date','echo','find','ls'):continue
  title,description=explain(command)
  items.append({'id':f'{pid}|{ts}','time':ts,'pid':pid,'containerId':cid,'tool':os.path.basename(process),'initiator':'平台手动检查' if is_manual(command) else '发起来源未确认','title':title,'description':description})
 recent=c.execute("SELECT time,operation,resource FROM events WHERE operation IN ('MODEL_REQUEST','MODEL_RESPONSE','MODEL_ERROR','MODEL_INTERRUPTED') ORDER BY time DESC LIMIT 1").fetchone();c.close()
 model={'state':'未采到模型请求'}
 if recent:
  model={'time':recent[0],'operation':recent[1],'state':{'MODEL_REQUEST':'等待模型响应','MODEL_RESPONSE':'模型已返回，继续执行链','MODEL_ERROR':'模型请求失败','MODEL_INTERRUPTED':'模型连接中断'}.get(recent[1],recent[1])}
  if recent[1] in ('MODEL_ERROR','MODEL_INTERRUPTED'):
   try:model['error']=json.loads(recent[2])
   except ValueError:pass
 return {'modelStatus':model,'actions':items[:60],'scope':'PentAGI 已知 Kali 工作容器','index':dict(h.STATUS)}

def explain(command):
 tool=command.split()[0].split('/')[-1] if command.split() else '命令'
 if 'nmap' not in tool:
  names={'curl':'检查网页与 HTTP 响应','dig':'查询 DNS 解析','openssl':'检查 TLS 与证书','whatweb':'识别 Web 技术栈','nikto':'检查 Web 常见配置问题','nuclei':'执行模板检查','gobuster':'枚举 Web 路径','ffuf':'执行 Web 输入探测','ping':'检查网络可达性'}
  return names.get(tool,'执行 '+tool),'根据采集的命令记录展示；执行结论以退出事件与工具返回为准。'
 if ' -p- ' in command:return '枚举全部 TCP 端口','尝试发现目标开放的 TCP 服务；是否完成全范围扫描，以报告和超时记录为准。'
 if ' -sn ' in command:return '确认目标是否在线','执行主机发现；该参数关闭端口扫描。'
 if ' -sC ' in command:return '进一步检查服务','运行默认脚本，并对指定端口识别服务版本。'
 if ' -sV ' in command:return '识别开放端口与服务','探测端口，并尝试识别服务及版本。'
 return '执行网络探测','根据命令参数执行 Nmap 检查。'

def detail(params):
 value=params.get('id',[''])[0];pid,ts=value.split('|',1)
 conn=h.connect();found=conn.execute('SELECT container,process,resource FROM events WHERE pid=? AND time=? LIMIT 1',(int(pid),ts)).fetchone();conn.close();cid=found[0] if found else '';
 if cid not in workload_ids():raise ValueError('unknown workload')
 rows=h.process_timeline({'pid':[pid],'time':[ts],'container':[cid]})['events']
 commands=[r for r in rows if r['operation'] in ('EXEC','AUDIT_EXEC') and r['resource']]
 native=[r for r in commands if '/usr/lib/nmap/nmap' in r['resource']]
 command=found[2] if found and found[2] and not found[2].startswith('(cmdline') else (native or commands or [{'resource':''}])[0]['resource'];title,description=explain(command)
 exits=[r for r in rows if r['operation']=='EXIT'];start=ts;end=exits[-1]['time'] if exits else None
 duration=None
 live=False
 if not exits:
  try:
   live=cid in open(f'/proc/{pid}/cgroup').read() and bool(open(f'/proc/{pid}/cmdline','rb').read())
  except OSError:pass
 if end:
  try:duration=round((datetime.datetime.fromisoformat(end)-datetime.datetime.fromisoformat(start)).total_seconds(),2)
  except ValueError:pass
 target=re.search(r'(?<![\w.-])([\w.-]+\.[A-Za-z]{2,})(?![\w.-])',command)
 ports=re.search(r'(?:^|\s)-p\s+(\S+)',command)
 output=re.search(r'(?:^|\s)-o([NA])\s+(\S+)',command)
 exchange=model_for_command(command,start) if not is_manual(command) else None
 return {'modelExchange':exchange,'id':value,'title':title,'description':description,'tool':os.path.basename(found[1]) if found else '命令','command':command,'target':target[1] if target else '未提取','ports':ports[1] if ports else ('常用 1000 端口' if '--top-ports 1000' in command else '命令未显式指定'),'container':'PentAGI / Kali 工作容器','containerId':cid,'pid':int(pid),'start':start,'end':end,'duration':duration,'status':'进程已退出' if exits else ('执行中' if live else '未采到退出事件'),'exit':exits[-1].get('state',{}) if exits else None,'outputPath':output[2] if output else None,'initiator':'平台手动检查' if is_manual(command) else '发起来源未确认','scanReport':scan_report(output[2],output[1]) if output else None,'events':rows,'network':[r for r in rows if r['category']=='network'],'modelEvidence':False,'explanationSource':'根据已记录命令参数解释，不是模型当时的想法','coverageNote':'此视图按进程展示，尚未建立确定的模型调用归属。未采到可归属的网络事件，不代表没有网络访问。'}


def scan_report(path,kind):
 from pathlib import Path
 import xml.etree.ElementTree as ET
 configured=os.environ.get('AGENTREINS_REPORT_ROOT','')
 if not configured:return None
 root=Path(configured).resolve()
 if not path.startswith('/work/'):return None
 relative=path[6:]+('.xml' if kind=='A' else '')
 candidate=(root/relative).resolve()
 if not candidate.is_relative_to(root) or candidate.suffix!='.xml':return None
 try:
  if candidate.stat().st_size>4*1024*1024:return {'status':'too_large'}
  report=ET.parse(candidate).getroot();finish=report.find('runstats/finished')
  ports=[]
  for port in report.findall('host/ports/port'):
   state=port.find('state');service=port.find('service')
   ports.append({'port':port.get('portid'),'protocol':port.get('protocol'),'state':state.get('state') if state is not None else 'unknown','service':dict(service.attrib) if service is not None else {}})
  return {'status':'timed_out' if any(host.get('timedout')=='true' for host in report.findall('host')) else ('completed' if finish is not None else 'in_progress'),'elapsed':finish.get('elapsed') if finish is not None else None,'exit':finish.get('exit') if finish is not None else None,'ports':ports,'source':'Nmap XML report artifact'}
 except ET.ParseError:return {'status':'in_progress','source':'Nmap XML report artifact'}
 except OSError:return None


def workload_ids():
 ids={v.strip() for v in os.environ.get('AGENTREINS_WORKLOAD_IDS','').split(',') if v.strip()}
 try:
  output=subprocess.run(['docker','ps','-a','--format','{{.ID}}|{{.Names}}'],capture_output=True,text=True,timeout=4).stdout
  for line in output.splitlines():
   cid,_,name=line.partition('|')
   patterns=os.environ.get('AGENTREINS_WORKLOAD_PATTERNS','pentagi*terminal*,pentagi*kali*,*pentagi*terminal*,*pentagi*kali*').split(',')
   if any(__import__('fnmatch').fnmatch(name.lower(),p.strip().lower()) for p in patterns if p.strip()):ids.add(cid)
 except (OSError,subprocess.TimeoutExpired):pass
 return sorted(ids) or ['__no_configured_workload__']


def model_for_command(command,start):
 """Candidate association only: exact normalized command in tool input and bounded time."""
 tokens=[]
 try:
  tokens=shlex.split(command);normalized=' '.join(tokens)
 except ValueError:normalized=command
 if len(normalized)<12:return None
 dt=datetime.datetime.fromisoformat(start);low=(dt-datetime.timedelta(seconds=300)).isoformat()
 c=h.connect()
 try:
  calls=c.execute("SELECT time,resource,evidence FROM events WHERE operation='TOOL_CALL' AND time>=? AND time<=? ORDER BY time DESC LIMIT 150",(low,(dt+datetime.timedelta(seconds=2)).isoformat())).fetchall()
  for when,resource,evidence in calls:
   try:
    tool=json.loads(resource);args=json.loads(tool.get('function',{}).get('arguments','{}'));cmd=args.get('input') or args.get('command') or args.get('cmd') or ''
    if not isinstance(cmd,str):continue
    try:intent=' '.join(shlex.split(cmd))
    except ValueError:intent=cmd
    # Executable paths can differ between shell intent and exec observation.
    short=' '.join([os.path.basename(tokens[0])]+tokens[1:]) if tokens else normalized
    if normalized not in intent and short not in intent:continue
    rid=json.loads(evidence).get('requestId')
    if not rid:continue
    rows=c.execute("SELECT operation,resource FROM events WHERE time>=? AND time<=? AND category='semantic' AND evidence LIKE ? ORDER BY time",(low,(dt+datetime.timedelta(seconds=660)).isoformat(),'%'+rid+'%')).fetchall()
    exchange={'id':rid,'time':when,'request':None,'response':None,'reasoning':[],'tools':[],'error':None,'association':'命令文本与前 5 分钟工具调用匹配，仅为候选关联'}
    for op,payload in rows:
     try:data=json.loads(payload)
     except ValueError:continue
     if op=='MODEL_REQUEST':exchange['request']=data
     elif op=='MODEL_RESPONSE':exchange['response']=data
     elif op=='MODEL_REASONING':exchange['reasoning'].append(data)
     elif op in ('MODEL_INTERRUPTED','MODEL_ERROR'):exchange['error']=data
     elif op=='TOOL_CALL':exchange['tools'].append({'name':data.get('function',{}).get('name','unknown'),'arguments':data.get('function',{}).get('arguments','')})
    return exchange
   except (ValueError,TypeError,KeyError):continue
 finally:c.close()
 return None


def is_manual(command):
 marker=os.environ.get("AGENTREINS_MANUAL_COMMAND_MARKER", "")
 return bool(marker and marker in command)
