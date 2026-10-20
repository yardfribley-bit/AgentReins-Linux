import json,tempfile,threading,time,unittest,urllib.request,urllib.error
from pathlib import Path
from http.server import ThreadingHTTPServer
from runtime.server import App
class PublicBoundaryTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.app=App(Path('runtime'),{'database':str(Path(self.tmp.name)/'db'),'operators':{'alice':'alice-key','bob':'bob-key'},'sources':{'source':'source-key'},'version':'test-review'});self.server=ThreadingHTTPServer(('127.0.0.1',0),self.app.handler());threading.Thread(target=self.server.serve_forever,daemon=True).start();self.base='http://127.0.0.1:'+str(self.server.server_port)+'/runtime/api/';self.app.store.heartbeat('source',{'host':'private-host','fileWatchScope':['/private/.ssh'],'drop':0});self.app.store.ingest('source',[{'id':'event','time':time.time(),'workload':'private-agent','pid':1,'kind':'file','identity':{'basis':'registered'},'path':'/private/.env','access':'read_open','result':'success'}]);self.aid=self.app.store.listing({})['items'][0]['id']
 def tearDown(self):self.app.stop.set();self.server.shutdown();self.server.server_close();self.tmp.cleanup()
 def req(self,path,body=None,token=None):
  r=urllib.request.Request(self.base+path,data=json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json',**({'Authorization':'Bearer '+token} if token else {})})
  try:
   with urllib.request.urlopen(r) as x:return x.status,json.load(x)
  except urllib.error.HTTPError as e:
   with e:return e.code,json.load(e)
 def test_anonymous_projection_and_search_oracle(self):
  status,p=self.req('alerts?q=private-host');self.assertEqual(status,200);self.assertTrue(p['publicSummary']);self.assertEqual(p['total'],1);self.assertNotIn('private',json.dumps(p));self.assertNotIn('evidence',json.dumps(p));self.assertEqual(self.req('alerts/'+self.aid)[0],403)
 def test_operator_identity_and_read(self):
  self.assertEqual(self.req('me',token='bob-key')[1]['name'],'bob');a=self.req('alerts/'+self.aid,token='alice-key')[1];self.assertIn('evidence',a);self.assertEqual(self.req('alerts/'+self.aid+'/review',{'action':'escalate','reason':'actual human review','revision':a['revision']},'bob-key')[1]['actor'],'bob')
 def test_rate_limit(self):
  codes=[self.req('me',token='bad-'+str(i))[0] for i in range(20)];self.assertIn(429,codes);self.assertEqual(self.req('me',token='alice-key')[0],200)
 def test_hidden_secret_rejected_visible_env_preserved(self):
  base={'requestKey':'x','tool':'runtime_lab_command','arguments':{'env':{'LD_PRELOAD':'/tmp/test.so'}},'runId':'r','workload':'w'}
  status,g=self.req('gates',base,'source-key');self.assertEqual(status,201);self.assertEqual(self.req('alerts/'+g['alertId'],token='alice-key')[1]['gate']['binding']['arguments'],base['arguments']);base.update(requestKey='y',arguments={'token':'actual-secret'});self.assertEqual(self.req('gates',base,'source-key')[0],400)
 def test_mapping_acceptance_is_explicit_recommendation(self):
  _,v=self.req('intelligence',{'component':'Unknown App','sourceUrl':'https://example.test','assetId':'asset-1'},'alice-key');self.assertEqual(v['rules'],[]);_,a=self.req('intelligence/'+v['id']+'/accept',{'reason':'manually mapped process risk','rules':['S04']},'bob-key');self.assertEqual(a['status'],'accepted_recommendation');self.assertEqual(a['reviewedBy'],'bob');self.assertEqual(self.req('rules')[1]['intelligence'],[])
if __name__=='__main__':unittest.main()
