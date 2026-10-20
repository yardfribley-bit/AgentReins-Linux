"""One-time non-destructive grouping of legacy open S05 alerts. Keeps old IDs readable."""
import json,sys
from pathlib import Path
try:from .engine import Store,compact,digest
except ImportError:from engine import Store,compact,digest

def migrate(store):
 merged=0
 with store.db() as c:
  if c.execute("SELECT 1 FROM meta WHERE key='review-v11-grouped'").fetchone():return 0
  groups={}
  for r in c.execute("SELECT payload FROM alerts WHERE rule='S05' AND status='open' ORDER BY time").fetchall():
   a=json.loads(r[0])
   if a.get('aggregateKey'):continue
   e=a['evidence'][-1];key=(a['source'],a['workload'],e.get('destination'),e.get('port'),int(a['createdAt']//300));groups.setdefault(key,[]).append(a)
  for group in groups.values():
   if len(group)<2:continue
   a=group[0];e=a['evidence'][-1];a.update(count=len(group),firstSeen=min(x['createdAt'] for x in group),lastSeen=max(x['createdAt'] for x in group),mergedAlertIds=[x['id'] for x in group[1:]],aggregateKey=digest(['S05',e['source'],e['workload'],e.get('destination'),e.get('port'),e.get('path'),None]),sampleEventIds=[x['evidence'][-1]['id'] for x in group],evidence=[x['evidence'][-1] for x in group[:6]]);a['revision']+=1
   c.execute('UPDATE alerts SET payload=? WHERE id=?',(compact(a),a['id']))
   for previous in group[1:]:
    previous.update(status='merged',mergedInto=a['id']);c.execute("UPDATE alerts SET status='merged',payload=? WHERE id=?",(compact(previous),previous['id']));merged+=1
  c.execute("INSERT INTO meta VALUES('review-v11-grouped','done')")
 return merged
if __name__=='__main__':
 cfg=json.loads(Path(sys.argv[1] if len(sys.argv)>1 else '/etc/agentreins-runtime/config.json').read_text());print('Legacy alerts grouped; old IDs preserved:',migrate(Store(cfg['database'])))
