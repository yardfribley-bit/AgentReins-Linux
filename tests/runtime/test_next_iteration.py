import tempfile,unittest
from pathlib import Path
from runtime.engine import Store
from runtime.command_parse import parse
class NextIterationTests(unittest.TestCase):
 def test_output_priority(self):
  for command,expected in [('curl -o /tmp/a https://example.test/a > /dev/null','/tmp/a'),('curl -O https://example.test/a > /dev/null','/tmp/a'),('wget -O /tmp/a https://example.test/a > /dev/null','/tmp/a'),('wget https://example.test/a > /dev/null','/tmp/a'),('curl https://example.test/a > /tmp/a','/tmp/a'),('curl -o- https://example.test/a > /tmp/a',None)]:
   self.assertEqual(parse(command,'/tmp').get('downloadPath'),expected,command)
 def test_loss_window_recovers_retains_history_and_restart(self):
  with tempfile.TemporaryDirectory() as t:
   now=[100000.];db=Path(t)/'db';s=Store(db,lambda:now[0]);s.heartbeat('h',{'auditLost':0,'counters':{'spoolDropped':0}})
   now[0]+=10;s.heartbeat('h',{'auditLost':1,'counters':{'spoolDropped':2}})
   with s.db(write=False) as c:self.assertEqual(s.coverage(c,'h')['state'],'degraded')
   now[0]+=901;s=Store(db,lambda:now[0]);s.heartbeat('h',{'auditLost':1,'counters':{'spoolDropped':2}})
   with s.db(write=False) as c:
    p=s.coverage(c,'h');self.assertEqual(p['state'],'online');self.assertEqual(p['drop'],3);self.assertEqual(p['recentLoss']['total'],0)
   now[0]+=1;s.heartbeat('h',{'auditLost':1,'counters':{'spoolDropped':2,'backpressure':1}})
   with s.db(write=False) as c:self.assertEqual(s.coverage(c,'h')['state'],'degraded')
 def test_relative_no_cwd_not_guessed(self):
  self.assertNotIn('downloadPath',parse('curl -o a https://example.test/a'))
  self.assertEqual(parse('curl -o a https://example.test/a','/work')['downloadPath'],'/work/a')
if __name__=='__main__':unittest.main()
