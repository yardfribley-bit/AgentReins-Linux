import datetime, importlib.util, pathlib, tempfile, unittest
spec=importlib.util.spec_from_file_location('history',pathlib.Path(__file__).resolve().parents[1]/'console/history_store.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
class RetentionTest(unittest.TestCase):
 def test_old_and_excess_rows(self):
  with tempfile.TemporaryDirectory() as d:
   h.DB=d+'/history.sqlite';h.init();c=h.connect();now=datetime.datetime.now(datetime.timezone.utc)
   c.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',[(str(i),(now-datetime.timedelta(days=4) if i==0 else now).isoformat(),'kernel','EXEC',1,0,'c','true','','SUCCESS','test','{}') for i in range(100010)])
   c.commit();h.trim(c)
   self.assertEqual(c.execute('SELECT count(*) FROM events').fetchone()[0],100000)
   self.assertIsNone(c.execute("SELECT 1 FROM events WHERE key='0'").fetchone())
   self.assertEqual(c.execute('PRAGMA max_page_count').fetchone()[0],524288);c.close()
if __name__=='__main__':unittest.main()
