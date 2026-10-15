#!/usr/bin/env python3
import collections,datetime,json,os,re,subprocess,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from tool_chains import build,journeys
import history_store
import cockpit_data
from urllib.parse import urlsplit,parse_qs
EVENTS=collections.deque(maxlen=6000)
SEMANTICS=collections.deque(maxlen=2000)
SEEN=collections.OrderedDict()
LOCK=threading.Lock()
STATUS={}
OFFSETS={}
PATHS=['/var/log/agentreins/host.jsonl','/var/log/agentreins/semantic.jsonl']
def run(args):
 try:return subprocess.run(args,capture_output=True,text=True,timeout=4).stdout
 except Exception:return ''
def protect(s):
 s=re.sub(r'(?i)((?:password|passwd|token|secret|api[_-]?key|cookie)\s*[=:]\s*)[^\s"\']+',r'\1[REDACTED]',str(s))
 s=re.sub(r'(?i)(--(?:password|token|secret|api[_-]?key)\s+)\S+',r'\1[REDACTED]',s)
 return re.sub(r'(?i)(Authorization:\s*(?:Bearer|Basic)\s+)\S+',r'\1[REDACTED]',s)
def ingest():
 for path in PATHS:
  try:
   st=os.stat(path); previous=OFFSETS.get(path); offset=previous[1] if previous and previous[0]==st.st_ino and previous[1]<=st.st_size else max(0,st.st_size-2*1024*1024)
   with open(path,'rb') as f:
    f.seek(offset)
    if not previous and offset:f.readline()
    while True:
     start=f.tell(); line=f.readline()
     if not line or not line.endswith(b'\n'):
      OFFSETS[path]=(st.st_ino,start);break
     try:r=json.loads(line)
     except ValueError:continue
     key=r.get('eventKey')
     if key and key in SEEN:continue
     if key:SEEN[key]=None
     if len(SEEN)>12000:SEEN.popitem(last=False)
     evidence=r.get('evidence') or {}
     cid=r.get('containerId') or evidence.get('containerId') or ''
     # Explicit identity only; do not infer agent ownership from a generic component label.
     identity=('model-client:'+str(evidence.get('peer','unknown'))) if r.get('category')=='semantic' else ('container:'+cid if cid else 'host:'+str(r.get('process') or 'unknown'))
     row={k:r.get(k,'') for k in ('time','category','operation','pid','ppid','containerId','container','result','source','eventKey')}
     row.update(requestId=evidence.get('requestId',''),identity=identity,process=protect(r.get('process','')),resource=protect(r.get('resource','')),attribution=evidence.get('attribution','DIRECT' if cid else 'HOST_OR_UNKNOWN'))
     row['kernelEvidence']={k:evidence.get(k) for k in ('syscall','arch','exit','uid','auid','cwd','arguments','namespaces','cgroup') if k in evidence}
     EVENTS.append(row)
     if row['category']=='semantic':SEMANTICS.append(row)
  except OSError:pass
def collect():
 tick=0
 while True:
  with LOCK:ingest()
  if tick%5==0:
   containers=[]
   for line in run(['docker','ps','--format','{{json .}}']).splitlines():
    try:containers.append(json.loads(line))
    except ValueError:pass
   processes=[]
   for line in run(['ps','-eo','pid,ppid,user,comm','--no-headers']).splitlines():
    p=line.split(None,3)
    if len(p)==4:processes.append(dict(zip(('pid','ppid','user','name'),p)))
   services={}
   for name in ('auditd','agentreins-host-stream','agentreins-audit-bridge','agentreins-semantic-gateway'):
    services[name]=run(['systemctl','is-active',name]).strip()
   audit=run(['auditctl','-s'])
   with LOCK:STATUS.update(containers=containers,processes=processes,services=services,audit=audit,updated=datetime.datetime.now().astimezone().isoformat())
  tick+=1;time.sleep(2)
PAGE=r'''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentReins · 智能体活动</title><style>
*{box-sizing:border-box}body{margin:0;background:#0b1120;color:#e2e8f0;font:14px system-ui}main{max-width:1500px;margin:auto;padding:28px}h1{font-size:28px;margin:0}small,.muted{color:#94a3b8}.top{display:flex;justify-content:space-between;align-items:center}.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:24px 0}.card,section{background:#131e32;border:1px solid #25334c;border-radius:12px;padding:16px}.card strong{display:block;font-size:26px;margin-top:8px}.controls{display:flex;gap:10px;margin:16px 0;flex-wrap:wrap}input,select,button{background:#182840;color:#e2e8f0;border:1px solid #334966;border-radius:7px;padding:10px}input{flex:1}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid #26344a;vertical-align:top}th{color:#94a3b8}td:nth-child(5){word-break:break-word;max-width:600px;white-space:pre-wrap}code{color:#7dd3fc}.scroll{overflow:auto;height:620px;overflow-anchor:none}table{table-layout:fixed}th:nth-child(1){width:15%}th:nth-child(2){width:16%}th:nth-child(3){width:18%}th:nth-child(4){width:19%}th:nth-child(5){width:32%}.coverage{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px}h3{margin:0 0 8px}.good{color:#5eead4}.warn{color:#fbbf24}#entities{display:flex;flex-wrap:wrap;gap:8px}.pill{background:#182840;padding:8px;border-radius:8px}@media(max-width:800px){.cards,.coverage{grid-template-columns:1fr 1fr}main{padding:14px}}.journey{margin:14px 0;border:1px solid #314765;border-radius:14px;padding:18px;background:#101c30}.steps{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:16px}.step{padding:14px;background:#17273e;border-radius:10px;min-height:130px;overflow-wrap:anywhere}.step h3{font-size:15px}.step pre{white-space:pre-wrap;max-height:360px;overflow:auto;font:12px ui-monospace}.badge{display:inline-block;padding:4px 8px;border-radius:6px;background:#24364f;margin-right:8px}.step details{margin-top:12px}summary{cursor:pointer;color:#7dd3fc}.jheader{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.step table{table-layout:auto;font-size:12px}.step td{max-width:unset;padding:6px}.steps .wide{grid-column:span 2}@media(max-width:850px){.steps{grid-template-columns:1fr}.steps .wide{grid-column:span 1}}</style><main>
<div class="top"><div><h1>AgentReins <span class="muted">/ 智能体活动</span></h1><p class="muted">看清智能体从模型交互到实际执行的过程</p></div><span id="health">连接中</span></div>
<nav class="controls"><a href="/pentagi" style="color:#7dd3fc;margin-right:24px">PentAGI 驾驶舱 ↗</a><a href="#execution-process" style="color:#7dd3fc">智能体活动</a><a href="#history-review" style="color:#7dd3fc;margin-left:24px">历史执行</a><a href="#raw-evidence" style="color:#7dd3fc;margin-left:24px">系统证据</a></nav><section id="execution-process" style="margin:20px 0"><h3>智能体活动</h3><p class="muted">选择一次活动，查看模型请求、反馈、工具、执行位置、结果及关联行为。当前按模型交互组织活动；没有任务 ID 的记录暂不能确认完整任务边界。</p><div class="controls"><select id="jfilter"><option value="real">真实活动</option><option value="tools">真实活动 · 有工具调用</option><option value="all">包含验收测试</option></select><button id="jrefresh">更新活动</button><span class="muted" id="jstatus"></span></div><div id="journeyChoices"></div><div id="journeys"></div></section><section id="history-review" style="margin-top:16px"><h3>历史执行</h3><p class="muted">沙箱内活动包含容器里的命令和退出等事件；沙箱边界只表示隔离与权限变化。按执行位置、时间和目标回看真实命令与结果。默认显示已知 PentAGI 工作容器；其他智能体可选择相应容器，主机进程仍需识别归属。</p><div class="controls"><input id="hq" placeholder="搜索 nmap、命令或目标地址"><select id="hc"><option value="">全部容器与主机</option></select><select id="hcat"><option value="">全部事件</option><option value="kernel">命令 / 内核 / 文件</option><option value="network">网络</option><option value="semantic">模型 / 工具</option><option value="sandbox_activity">沙箱内活动 · 含命令</option><option value="sandbox">沙箱边界 · 权限 / namespace</option></select><input id="hf" type="datetime-local" title="开始时间"><input id="ht" type="datetime-local" title="结束时间"><button id="hsearch">查询历史</button><button id="hnmap">搜索沙箱内 Nmap</button><button id="hsandbox">查看沙箱内全部活动</button></div><p id="hstatus" class="muted"></p><div class="scroll" style="height:440px"><table><thead><tr><th>时间</th><th>操作 / 结果</th><th>进程 / PID</th><th>容器</th><th>命令 / 资源</th></tr></thead><tbody id="hrows"></tbody></table></div><section id="processDetail" style="display:none;margin:12px 0"></section><button id="hprev">上一页</button><button id="hnext">下一页</button></section><details id="legacyTools" style="margin-top:16px"><summary>工具调用详情 · 含历史验收记录</summary><p class="muted">调用与回传结果按工具 ID 关联；命令与系统行为按文本、时间和进程树关联，候选归属不等于确认。</p><div id="toolList"></div><div id="toolDetail"></div></details><details style="margin-top:20px"><summary>采集状态与观测范围</summary><div class="cards" id="cards"></div><div class="coverage"><section><h3>系统行为 · 已接入</h3><span class="good">Linux audit / netlink / Docker / inotify</span><p class="muted">主机统一采集，不依赖 Agent 数据库。覆盖选定系统调用、命令和已配置的数据卷。</p></section><section><h3>模型与工具语义 · 已接入兼容网关</h3><span class="warn">模型请求 / 响应 / 工具调用 / 工具结果</span><p class="muted">接入网关的 Agent 可见模型交互、工具调用和返回的推理字段。工具结果在后续请求送回模型时可见；未接入网关的 Agent 不覆盖语义。</p></section><section><h3>证据与归属</h3><p class="muted">保留直接证据、父进程关联和未知标记。列表为工作负载身份，不自动宣称每个进程都是 Agent。系统调用成功不代表任务成功。</p></section></div>
<section><h3>运行中的容器与观测身份</h3><div id="entities"></div><p class="muted" id="services"></p></section>
</details><div id="raw-evidence" class="controls"><input id="q" placeholder="搜索命令、进程、容器、IP 或 PID"><select id="cat"><option value="">全部行为</option><option value="kernel">内核 / 命令 / 文件</option><option value="semantic">模型 / 工具语义</option><option value="network">网络</option><option value="sandbox">沙箱边界 / 权限</option><option value="control-plane">容器生命周期</option></select><select id="identity"><option value="">全部身份</option></select><button id="pause">暂停画面</button></div>
<section><div class="top"><h3>系统证据</h3><small>每 2 秒更新 · 最近 6000 条缓冲 · 画面最多 300 条</small></div><div class="scroll"><table><thead><tr><th>时间</th><th>行为 / 结果</th><th>进程 / PID</th><th>归属</th><th>命令 / 资源</th></tr></thead><tbody id="rows"></tbody></table></div></section><p class="muted">AgentReins · 匿名只读观测 · 历史范围受日志保留策略限制</p></main><script>
let data=null,paused=false,toolData=[],selectedTool=null;const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function draw(){if(!data)return;let e=data.events;let counts=data.counts;document.getElementById('cards').innerHTML=[['缓存证据',data.buffered||e.length],['命令执行',counts.commands],['网络事件',counts.network],['沙箱事件',counts.sandbox],['运行容器',data.containers.length]].map(x=>'<div class="card">'+x[0]+'<strong>'+x[1]+'</strong></div>').join('');document.getElementById('entities').innerHTML=data.containers.map(c=>'<span class="pill">'+esc(c.Names)+' <code>'+esc(c.ID)+'</code></span>').join('')||'<span class="muted">未发现 Docker 容器</span>';document.getElementById('services').textContent=Object.entries(data.services).map(x=>x.join(': ')).join(' · ')+' · '+data.audit.replace(/\n/g,' ');let sel=document.getElementById('identity'),old=sel.value;let options='<option value="">全部身份</option>'+data.identities.map(i=>'<option>'+esc(i)+'</option>').join('');if(sel.dataset.options!==options){sel.innerHTML=options;sel.dataset.options=options;sel.value=old;}let q=document.getElementById('q').value.toLowerCase(),cat=document.getElementById('cat').value;e=e.filter(r=>(!cat||r.category===cat)&&(!old||r.identity===old)&&(!q||JSON.stringify(r).toLowerCase().includes(q)));let viewport=document.querySelector('.scroll'),scrollTop=viewport.scrollTop;document.getElementById('rows').innerHTML=e.slice(-300).reverse().map(r=>'<tr><td>'+esc(r.time)+'</td><td><code>'+esc(r.operation)+'</code><br><small>'+esc(r.result)+'</small></td><td>'+esc(r.process)+'<br><small>PID '+esc(r.pid)+' / PPID '+esc(r.ppid)+'</small></td><td>'+esc(r.identity)+'<br><small>'+esc(r.attribution)+' '+esc(r.requestId||'')+'</small></td><td>'+esc(r.resource)+'</td></tr>').join('');viewport.scrollTop=scrollTop;}
async function tick(){try{let r=await fetch('/api/state?'+new URLSearchParams({q:document.getElementById('q').value,category:document.getElementById('cat').value,identity:document.getElementById('identity').value}),{cache:'no-store'});if(!r.ok)throw Error(r.status);if(!paused){let viewport=document.querySelector('.scroll');if(viewport.scrollTop<10){data=await r.json();draw()}else{document.getElementById('health').textContent='正在查看历史 · 返回顶部恢复更新';return}}document.getElementById('health').textContent=paused?'画面已暂停':'● 实时连接 · '+new Date().toLocaleTimeString()}catch(e){document.getElementById('health').textContent='连接中断 · 自动重试'}}
for(let id of ['q','cat','identity'])document.getElementById(id).addEventListener('input',tick);document.getElementById('pause').onclick=()=>{paused=!paused;document.getElementById('pause').textContent=paused?'恢复画面':'暂停画面'};tick();setInterval(tick,2000);

function renderTools(){let list=document.getElementById('toolList');list.innerHTML=toolData.map((t,i)=>'<button data-tool="'+i+'" style="margin:4px">'+esc(t.name)+' · '+esc(t.time.slice(11,19))+' · '+(t.result?'已有回传':'等待回传')+'</button>').join('')||'<p class="muted">尚无工具调用。接入网关后的调用会显示在这里。</p>';list.querySelectorAll('button').forEach(b=>b.onclick=async()=>{selectedTool=toolData[Number(b.dataset.tool)].id;let r=await fetch('/api/tools?id='+encodeURIComponent(selectedTool));let full=(await r.json()).tools[0];if(full){toolData=toolData.map(t=>t.id===selectedTool?full:t);renderToolDetail()}});renderToolDetail()}
function renderToolDetail(){let t=toolData.find(x=>x.id===selectedTool);if(!t){document.getElementById('toolDetail').innerHTML='';return}let table=(title,rows)=>'<h3>'+title+'</h3>'+(rows.length?'<div class="scroll" style="height:240px"><table>'+rows.map(r=>'<tr><td>'+esc(r.time)+'<br>PID '+esc(r.pid)+'</td><td>'+esc(r.operation)+'<br>'+esc(r.result)+'</td><td>'+esc(r.resource)+'<pre style="white-space:pre-wrap">'+esc(JSON.stringify(r.kernelEvidence||{},null,2))+'</pre></td></tr>').join('')+'</table></div>':'<p class="muted">未找到关联证据。不能据此断定没有发生。</p>');document.getElementById('toolDetail').innerHTML='<h3>'+esc(t.name)+'</h3><p>工具 ID <code>'+esc(t.id)+'</code> · 请求 '+esc(t.requestId)+'</p><p class="warn">'+esc(t.associationNote)+'</p><h3>调用参数 / 意图</h3><pre style="white-space:pre-wrap">'+esc(t.arguments)+'</pre><h3>工具回传结果</h3><pre style="white-space:pre-wrap">'+esc(t.result?JSON.stringify(t.result,null,2):'尚无结果回传')+'</pre>'+table('执行命令 · 候选关联',t.commands)+table('网络行为 · 候选进程关联',t.network)+table('内核 / 沙箱事件与返回状态',t.kernel)}
async function updateTools(){try{let r=await fetch('/api/tools',{cache:'no-store'});if(r.ok){toolData=(await r.json()).tools;renderTools()}}catch(e){}}
document.getElementById('legacyTools').ontoggle=()=>{if(document.getElementById('legacyTools').open)updateTools()};

let historyOffset=0;async function historySearch(){let p=new URLSearchParams({q:document.getElementById('hq').value,container:document.getElementById('hc').value,category:document.getElementById('hcat').value,offset:historyOffset,limit:200});for(let [id,key] of [['hf','from'],['ht','to']]){let v=document.getElementById(id).value;if(v)p.set(key,v+':00')}document.getElementById('hstatus').textContent='查询中…';try{let r=await fetch('/api/history?'+p);if(!r.ok)throw Error(r.status);let s=await r.json();document.getElementById('hstatus').textContent='匹配 '+s.total+' 条 · 第 '+(historyOffset+1)+' 起 · 索引 '+s.index.state;document.getElementById('hrows').innerHTML=s.events.map((r,i)=>'<tr><td>'+esc(r.time)+'</td><td>'+esc(r.operation)+'<br>'+esc(r.result)+'</td><td>'+esc(r.process)+'<br>PID '+esc(r.pid)+' / PPID '+esc(r.ppid)+'</td><td>'+esc(r.containerId||'主机 / 未知')+'</td><td>'+esc(r.resource)+'<br><button class="process-open" data-index="'+i+'">查看执行时间线</button></td></tr>').join('');document.querySelectorAll('.process-open').forEach(b=>b.onclick=()=>processDetail(s.events[Number(b.dataset.index)]));let select=document.getElementById('hc'),old=select.value;select.innerHTML='<option value="">全部容器与主机</option>'+s.containers.map(c=>'<option value="'+esc(c.id)+'">'+esc(c.id)+' · '+c.events+' 条</option>').join('');select.value=old}catch(e){document.getElementById('hstatus').textContent='历史查询失败，请重试'}}document.getElementById('hsearch').onclick=()=>{historyOffset=0;historySearch()};document.getElementById('hnmap').onclick=()=>{document.getElementById('hq').value='nmap';document.getElementById('hc').value='';document.getElementById('hcat').value='sandbox_activity';document.getElementById('hf').value='';document.getElementById('ht').value='';historyOffset=0;historySearch()};document.getElementById('hprev').onclick=()=>{historyOffset=Math.max(0,historyOffset-200);historySearch()};document.getElementById('hnext').onclick=()=>{historyOffset+=200;historySearch()};document.getElementById('hsandbox').onclick=()=>{document.getElementById('hq').value='';document.getElementById('hcat').value='sandbox_activity';historyOffset=0;historySearch()};let initial=new URLSearchParams(location.search);if(initial.get('q'))document.getElementById('hq').value=initial.get('q');if(initial.get('view')==='sandbox')document.getElementById('hcat').value='sandbox_activity';historySearch();

let journeyData=[];
function stage(number,title,content){return '<div class="step"><h3><span class="badge">'+number+'</span>'+title+'</h3>'+content+'</div>'}
function raw(title,data){return '<details><summary>'+title+'</summary><pre>'+esc(typeof data==='string'?data:JSON.stringify(data,null,2))+'</pre></details>'}
function evidenceTable(rows){if(!rows.length)return '<p class="muted">缺少关联证据</p>';return '<table>'+rows.map(r=>'<tr><td>'+esc(r.operation)+'<br>'+esc(r.result)+'</td><td>PID '+esc(r.pid)+'<br>'+esc(r.resource)+raw('系统证据',r.kernelEvidence||{})+'</td></tr>').join('')+'</table>'}
function renderJourneyDetail(){let filter=document.getElementById('jfilter').value;let rows=journeyData.filter(j=>filter==='real'?!j.isTest:filter==='tools'?!j.isTest&&j.tools.length:true);document.getElementById('journeys').innerHTML=rows.map(j=>{let commands=j.tools.flatMap(t=>t.commands),network=j.tools.flatMap(t=>t.network),kernel=j.tools.flatMap(t=>t.kernel);let tools=j.tools;let messages=(j.request.messages||[]);let last=messages.filter(m=>m.role==='user').slice(-1)[0];let response=j.response?.choices?.map(c=>c.message?.content||'').join('\n')||'';return '<article class="journey"><div class="jheader"><strong>模型交互 · '+esc(j.model)+'</strong><span class="badge">'+esc(j.status)+'</span>'+(j.isTest?'<span class="badge warn">验收测试</span>':'')+'<small>'+esc(j.time)+'</small></div><small>交互 ID '+esc(j.id)+(j.previousInteractions.length?' · 上一步 '+esc(j.previousInteractions.join(', ')):'')+'</small><div class="steps">'+stage(1,'智能体 / 连接来源','<code>'+esc(j.client)+'</code><p class="muted">连接身份；尚无稳定任务 ID</p>')+stage(2,'向模型请求','<p>'+esc(last?JSON.stringify(last.content).slice(0,240):'非用户消息 / 后续工具回传')+'</p>'+raw('完整模型请求',j.request))+stage(3,'模型反馈','<p>'+esc(response.slice(0,240)||'工具调用或推理字段；展开查看')+'</p>'+raw('完整模型响应',j.response)+raw('返回的推理字段',j.reasoning))+stage(4,'调用了哪个工具',tools.map(t=>'<p><strong>'+esc(t.name)+'</strong><br><small>'+esc(t.id)+'</small></p>'+raw('参数',t.arguments)).join('')||'<p class="muted">本次未记录工具调用</p>')+stage(5,'执行命令',evidenceTable(commands)+ (tools.length?'<p class="warn">命令文本 + 时间 + 进程树：候选关联</p>':''))+stage(6,'在哪执行',commands.length?commands.map(r=>'<p>'+esc(r.containerId?'容器 '+r.containerId:'宿主机或归属未知')+'<br>PID '+esc(r.pid)+' / PPID '+esc(r.ppid)+'<br>'+esc(r.kernelEvidence?.cwd||'工作目录未知')+'</p>').join(''):'<p class="muted">没有执行位置证据</p>')+stage(7,'执行结果',tools.map(t=>'<p>'+esc(t.name)+'：'+(t.result?'结果已回传':'尚无回传')+'</p>'+raw('工具结果',t.result)).join('')+evidenceTable(kernel.filter(r=>r.operation==='EXIT')))+stage(8,'网络 / 内核行为',raw('网络事件',network)+raw('内核与沙箱事件',kernel)+'<p class="muted">记录的系统调用状态；不是完整实时内核快照</p>')+'</div></article>'}).join('')||'<p class="muted">当前没有采到真实模型交互。PentAGI 服务运行不代表正在执行任务；历史命令可在下方回看。只有经过观测网关的模型请求才会出现在这里。</p>'}
async function loadJourneys(){document.getElementById('jstatus').textContent='读取中';try{let r=await fetch('/api/journeys',{cache:'no-store'});if(!r.ok)throw Error(r.status);journeySummaries=(await r.json()).journeys;renderJourneys();document.getElementById('jstatus').textContent=journeySummaries.length+' 次交互 · 手动刷新以保持阅读位置'}catch(e){document.getElementById('jstatus').textContent='读取失败，请重试'}}document.getElementById('jfilter').onchange=renderJourneys;document.getElementById('jrefresh').onclick=loadJourneys;loadJourneys();

let journeySummaries=[];
function renderJourneys(){let filter=document.getElementById('jfilter').value;let rows=journeySummaries.filter(j=>filter==='real'?!j.isTest:filter==='tools'?!j.isTest&&j.tools.length:true);document.getElementById('journeyChoices').innerHTML=rows.map(j=>'<div class="journey"><strong>'+esc(j.model)+'</strong> · '+esc(j.status)+' · '+esc(j.time)+'<p>'+esc(j.client)+' · 工具：'+esc(j.tools.map(t=>t.name).join(', ')||'未记录')+(j.isTest?' · 验收测试':'')+'</p><button class="journey-open" data-id="'+esc(j.id)+'">查看执行过程</button></div>').join('')||'<p class="muted">未采到真实模型交互。可在历史执行中查询沙箱内 Nmap 等实际命令。</p>';document.querySelectorAll('.journey-open').forEach(b=>b.onclick=async()=>{let r=await fetch('/api/journeys?id='+encodeURIComponent(b.dataset.id));journeyData=(await r.json()).journeys;renderJourneyDetail()})}
async function processDetail(row){let box=document.getElementById('processDetail');box.style.display='block';box.textContent='正在读取执行时间线';try{let p=new URLSearchParams({pid:row.pid,container:row.containerId,time:row.time});let r=await fetch('/api/process?'+p);if(!r.ok)throw Error(r.status);let s=await r.json();box.innerHTML='<h3>执行时间线 · PID '+esc(s.pid)+'</h3><p>'+esc(s.containerId?'沙箱 / 容器 '+s.containerId:'宿主机或归属未知')+'</p><p class="muted">'+esc(s.note)+'</p>'+s.events.map(e=>'<section style="margin:8px 0"><strong>'+esc(e.time)+' · '+esc(e.operation)+'</strong><p>'+esc(e.process)+' · '+esc(e.result)+'</p><pre style="white-space:pre-wrap">'+esc(e.resource)+'</pre>'+raw('内核 / 返回状态',e.state)+'</section>').join('');box.scrollIntoView({block:'start',behavior:'smooth'})}catch(e){box.textContent='时间线查询失败，请重试'}}
</script></html>'''
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  path=self.path.split('?')[0]
  if path=='/pentagi':
   from pathlib import Path
   body=Path(__file__).with_name('pentagi_cockpit.html').read_bytes();ctype='text/html; charset=utf-8'
  elif path=='/api/cockpit':
   params=parse_qs(urlsplit(self.path).query)
   try:state=cockpit_data.detail(params) if params.get('id') else cockpit_data.summary(params)
   except (ValueError,IndexError):self.send_error(400);return
   if 'events' in state:
    state['command']=protect(state['command'])
    for row in state['events']:row['resource']=protect(row['resource']);row['process']=protect(row['process'])
   body=json.dumps(state,ensure_ascii=False).encode();ctype='application/json; charset=utf-8'
  elif path=='/api/process':
   try:state=history_store.process_timeline(parse_qs(urlsplit(self.path).query))
   except ValueError:self.send_error(400);return
   for row in state['events']:row['resource']=protect(row['resource']);row['process']=protect(row['process'])
   body=json.dumps(state,ensure_ascii=False).encode();ctype='application/json; charset=utf-8'
  elif path=='/api/journeys':
   with LOCK:ev=list(EVENTS);sem=list(SEMANTICS)
   requested=parse_qs(urlsplit(self.path).query).get('id',[''])[0]
   historical=history_store.association_events(sem) if requested else []
   for row in historical:row['resource']=protect(row['resource']);row['process']=protect(row['process'])
   items=journeys(ev+historical,sem);requested=parse_qs(urlsplit(self.path).query).get('id',[''])[0]
   if requested:items=[j for j in items if j['id']==requested]
   else:items=[{k:j[k] for k in ('id','time','client','model','status','isTest')}|{'tools':[{'name':t['name']} for t in j['tools']]} for j in items]
   state={'journeys':items}
   body=json.dumps(state,ensure_ascii=False).encode();ctype='application/json; charset=utf-8'
  elif path=='/api/history':
   try:state=history_store.query(parse_qs(urlsplit(self.path).query))
   except ValueError:self.send_error(400);return
   for row in state['events']:
    row['resource']=protect(row['resource']);row['process']=protect(row['process'])
   body=json.dumps(state,ensure_ascii=False).encode();ctype='application/json; charset=utf-8'
  elif path=='/api/tools':
   with LOCK:items=build(list(EVENTS),list(SEMANTICS))
   wanted=parse_qs(urlsplit(self.path).query).get('id',[''])[0]
   state={'tools':[t for t in items if t['id']==wanted] if wanted else [{'id':t['id'],'name':t['name'],'time':t['time'],'result':bool(t['result'])} for t in items]}
   body=json.dumps(state,ensure_ascii=False).encode();ctype='application/json; charset=utf-8'
  elif path=='/api/state':
   with LOCK:
    all_rows=list(EVENTS);params=parse_qs(urlsplit(self.path).query);rows=all_rows
    q=params.get('q',[''])[0].lower();category=params.get('category',[''])[0];identity=params.get('identity',[''])[0]
    rows=[r for r in rows if (not q or q in (r['process']+' '+r['resource']+' '+str(r['pid'])).lower()) and (not category or r['category']==category) and (not identity or r['identity']==identity)]
    total=len(rows);rows=[{k:(str(v)[:600] if k=='resource' else v) for k,v in r.items() if k!='kernelEvidence'} for r in rows[-100:]];state=dict(STATUS);state.pop('processes',None);state.update(total=total,buffered=len(all_rows),events=rows,identities=sorted({r['identity'] for r in all_rows}),counts={'commands':sum(r['operation'] in ('AUDIT_EXEC','EXEC') for r in all_rows),'network':sum(r['category']=='network' for r in all_rows),'sandbox':sum(r['category']=='sandbox' for r in all_rows)})
   body=json.dumps(state,ensure_ascii=False).encode();ctype='application/json; charset=utf-8'
  elif path in ('/','/index.html','/console'):body=PAGE.encode();ctype='text/html; charset=utf-8'
  else:self.send_error(404);return
  self.send_response(200);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store, no-cache, must-revalidate, max-age=0');self.send_header('X-AgentReins-UI','activity-sandbox-history');self.send_header('X-Content-Type-Options','nosniff');self.end_headers()
  try:self.wfile.write(body)
  except (BrokenPipeError,ConnectionResetError):pass
 def log_message(self,*args):pass
if __name__=='__main__':
 history_store.start()
 threading.Thread(target=collect,daemon=True).start()
 ThreadingHTTPServer((os.environ.get('AGENTREINS_CONSOLE_BIND','127.0.0.1'),int(os.environ.get('AGENTREINS_CONSOLE_PORT','8899'))),Handler).serve_forever()
